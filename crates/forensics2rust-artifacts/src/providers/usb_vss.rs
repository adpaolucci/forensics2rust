#![forbid(unsafe_code)]

//! Providers 10, 11, 12, and 13 (USB & VSS artifacts):
//! - USB Devices View (`artifacts.usb_devices`)
//! - USB Log View (`artifacts.usb_log`)
//! - Shadow Copy Catalog (`artifacts.vss`)
//! - Previous File Versions (`artifacts.previous`)

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use forensics2rust_core::{DiagnosticWarning, ForensicError, ForensicSource, WarningSeverity};
use guap_table::{
    CellValue, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};

use crate::live;
use crate::parsers::reg_reader::{RegTree, load_offline_hives, resolve_system_control_set, scan_live_trees};
use crate::parsers::registry_artifacts::{UsbDeviceRecord, decode_mounted_devices_tree, decode_usb_trees};
use crate::parsers::setupapi_log::{SetupApiUsbEvent, extract_vid_pid_serial, parse_setupapi_dev_log};
use crate::providers::{apply_rows, col, non_empty_text, opt_text, opt_timestamp};
use crate::vss::{
    PreviousFileRecord, PreviousFilesOptions, ShadowCopyRecord, enumerate_shadow_root_files,
    load_offline_previous_files, load_offline_shadow_copies,
};

// ---------------------------------------------------------------------------
// 10. artifacts.usb_devices — USB Devices View
// ---------------------------------------------------------------------------

pub struct UsbDevicesProvider {
    source: ForensicSource,
}

impl UsbDevicesProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (records, warnings) = load_usb_devices(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = records
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                let detail = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.device_name.clone()),
                        CellValue::Text(r.description.clone()),
                        CellValue::Text(r.device_type.clone()),
                        r.connected.map(CellValue::Bool).unwrap_or(CellValue::Null),
                        r.safe_to_unplug.map(CellValue::Bool).unwrap_or(CellValue::Null),
                        opt_text(r.vendor_id.as_deref()),
                        opt_text(r.product_id.as_deref()),
                        opt_text(r.serial_number.as_deref()),
                        opt_text(r.drive_letter.as_deref()),
                        opt_timestamp(r.created_date),
                        opt_timestamp(r.last_plug_date),
                        CellValue::Text(r.registry_key.clone()),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

fn load_usb_devices(source: &ForensicSource) -> Result<(Vec<UsbDeviceRecord>, Vec<DiagnosticWarning>), ForensicError> {
    let mut records = Vec::new();
    let mut warnings = Vec::new();

    if source.is_live() {
        #[cfg(not(windows))]
        return Err(ForensicError::unsupported_platform(
            "artifacts.usb_devices",
            "live artifacts.usb_devices requires Windows",
        ));

        #[cfg(windows)]
        {
            let mut mounted = BTreeMap::new();
            if let Ok((md_trees, w)) = scan_live_trees(
                &["HKLM\\SYSTEM\\MountedDevices"],
                Some(0),
                Some(500),
                "artifacts.usb_devices",
            ) {
                warnings.extend(w);
                if let Some(t) = md_trees.first() {
                    mounted = decode_mounted_devices_tree(t);
                }
            }

            let (usb_trees, w_usb) = scan_live_trees(
                &["HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB"],
                Some(4),
                Some(4_000),
                "artifacts.usb_devices",
            )?;
            warnings.extend(w_usb);

            let (stor_trees, w_stor) = scan_live_trees(
                &["HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"],
                Some(4),
                Some(2_000),
                "artifacts.usb_devices",
            )?;
            warnings.extend(w_stor);

            records.extend(decode_usb_trees(stor_trees.first(), usb_trees.first(), &mounted));
            if let Ok(snapshot) = live::enumerate_live_usb_snapshot() {
                live::merge_live_usb_snapshot(&mut records, &snapshot);
            }
        }
    } else {
        let hives = load_offline_hives(source, &["SYSTEM", "Windows\\System32\\config\\SYSTEM"])?;
        for (label, hive) in hives {
            let cs = resolve_system_control_set(&hive);
            let mounted = hive
                .find_key("MountedDevices")
                .map(|k| decode_mounted_devices_tree(&RegTree::from_hive_subkey(&hive, k, "MountedDevices")))
                .unwrap_or_default();

            let stor_path = format!("{cs}\\Enum\\USBSTOR");
            let usb_path = format!("{cs}\\Enum\\USB");
            let stor_tree = hive
                .find_key(&stor_path)
                .or_else(|| hive.find_key("Enum\\USBSTOR"))
                .map(|k| RegTree::from_hive_subkey(&hive, k, &format!("{label}\\{stor_path}")));
            let usb_tree = hive
                .find_key(&usb_path)
                .or_else(|| hive.find_key("Enum\\USB"))
                .map(|k| RegTree::from_hive_subkey(&hive, k, &format!("{label}\\{usb_path}")));

            records.extend(decode_usb_trees(stor_tree.as_ref(), usb_tree.as_ref(), &mounted));
        }
    }

    Ok((records, warnings))
}

impl TableProvider for UsbDevicesProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.usb_devices"
    }

    fn description(&self) -> &'static str {
        "USBSTOR, USB, MountedDevices, and SetupAPI USB device inventory"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "USB Devices View",
            vec![
                col("device_name", "DeviceName", ColumnType::Text, 220),
                col("description", "Description", ColumnType::Text, 240),
                col("device_type", "DeviceType", ColumnType::Text, 130),
                col("connected", "Connected", ColumnType::Bool, 90),
                col("safe_to_unplug", "SafeToUnplug", ColumnType::Bool, 100),
                col("vendor_id", "VendorID", ColumnType::Text, 90),
                col("product_id", "ProductID", ColumnType::Text, 90),
                col("serial_number", "SerialNumber", ColumnType::Text, 180),
                col("drive_letter", "DriveLetter", ColumnType::Text, 90),
                col("created_date", "CreatedDate", ColumnType::Timestamp, 180),
                col("last_plug_date", "LastPlugDate", ColumnType::Timestamp, 180),
                col("registry_key", "RegistryKey", ColumnType::Text, 300),
            ],
        )
        .with_default_sort(10, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}

// ---------------------------------------------------------------------------
// 11. artifacts.usb_log — USB Log View
// ---------------------------------------------------------------------------

pub struct UsbLogProvider {
    source: ForensicSource,
}

impl UsbLogProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    /// Exposes bounded live PnP event listening (`CM_Register_Notification`) separately from
    /// synchronous `TableProvider::query()` so `query()` always remains strictly non-blocking.
    pub fn watch_pnp_events(duration: Duration) -> Result<Vec<SetupApiUsbEvent>, ForensicError> {
        live::watch_pnp_events(duration)
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let (events, warnings) = load_usb_log_events(&self.source).map_err(|e| e.to_table_error())?;
        let rows: Vec<Row> = events
            .iter()
            .enumerate()
            .map(|(idx, ev)| {
                let detail = serde_json::to_value(ev).unwrap_or(serde_json::Value::Null);
                Row::new(
                    idx as u64 + 1,
                    vec![
                        opt_timestamp(ev.event_time),
                        CellValue::Text(ev.event_type.clone()),
                        non_empty_text(&ev.device_name),
                        non_empty_text(&ev.description),
                        CellValue::Text(ev.device_type.clone()),
                        opt_text(ev.drive_letter.as_deref()),
                        opt_text(ev.serial_number.as_deref()),
                        opt_text(ev.vendor_id.as_deref()),
                        opt_text(ev.product_id.as_deref()),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

fn load_usb_log_events(
    source: &ForensicSource,
) -> Result<(Vec<SetupApiUsbEvent>, Vec<DiagnosticWarning>), ForensicError> {
    let mut events = Vec::new();
    let mut warnings = Vec::new();

    match source {
        ForensicSource::OfflineBytes(bytes) => {
            events.extend(parse_setupapi_dev_log(bytes));
        }
        ForensicSource::OfflinePath(path) => {
            if !path.exists() {
                return Err(ForensicError::NotFound(path.display().to_string()));
            }
            if path.is_file() {
                let bytes =
                    fs::read(path).map_err(|err| ForensicError::io_classified(path.display().to_string(), err))?;
                events.extend(parse_setupapi_dev_log(&bytes));
            } else {
                for rel in [
                    "setupapi.dev.log",
                    "Windows\\INF\\setupapi.dev.log",
                    "INF\\setupapi.dev.log",
                ] {
                    let candidate = path.join(rel);
                    if candidate.is_file() {
                        let bytes = fs::read(&candidate)
                            .map_err(|err| ForensicError::io_classified(candidate.display().to_string(), err))?;
                        events.extend(parse_setupapi_dev_log(&bytes));
                    }
                }
            }
        }
        ForensicSource::Live => {
            #[cfg(not(windows))]
            return Err(ForensicError::unsupported_platform(
                "artifacts.usb_log",
                "live artifacts.usb_log requires Windows",
            ));

            #[cfg(windows)]
            {
                let log_path = live::live_setupapi_log_path();
                match fs::read(&log_path) {
                    Ok(bytes) => events.extend(parse_setupapi_dev_log(&bytes)),
                    Err(err) => warnings.push(DiagnosticWarning {
                        severity: WarningSeverity::Warn,
                        tool_id: "artifacts.usb_log".to_string(),
                        source: log_path.display().to_string(),
                        message: ForensicError::io_classified(log_path.display().to_string(), err).to_string(),
                    }),
                }

                // Supplement with live SetupAPI arrival/removal snapshot (strictly non-blocking)
                if let Ok(snapshot) = live::enumerate_live_usb_snapshot() {
                    for snap in snapshot.values() {
                        let (vid, pid, serial, dev_type) = extract_vid_pid_serial(&snap.instance_id);
                        if let Some(arr) = snap.last_arrival {
                            let desc = snap.description.clone().unwrap_or_else(|| snap.instance_id.clone());
                            let name = snap.friendly_name.clone().unwrap_or_else(|| desc.clone());
                            events.push(SetupApiUsbEvent {
                                event_time: Some(arr),
                                event_type: "Plug".to_string(),
                                instance_id: snap.instance_id.clone(),
                                device_name: name,
                                description: desc,
                                device_type: dev_type.clone(),
                                drive_letter: None,
                                serial_number: serial.clone(),
                                vendor_id: vid.clone(),
                                product_id: pid.clone(),
                                exit_status: None,
                            });
                        }
                        if let Some(rem) = snap.last_removal {
                            let desc = snap.description.clone().unwrap_or_else(|| snap.instance_id.clone());
                            let name = snap.friendly_name.clone().unwrap_or_else(|| desc.clone());
                            events.push(SetupApiUsbEvent {
                                event_time: Some(rem),
                                event_type: "Unplug".to_string(),
                                instance_id: snap.instance_id.clone(),
                                device_name: name,
                                description: desc,
                                device_type: dev_type,
                                drive_letter: None,
                                serial_number: serial,
                                vendor_id: vid,
                                product_id: pid,
                                exit_status: None,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok((events, warnings))
}

impl TableProvider for UsbLogProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.usb_log"
    }

    fn description(&self) -> &'static str {
        "setupapi.dev.log offline parser and live PnP plug/unplug notification view"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "USB Log View",
            vec![
                col("event_time", "EventTime", ColumnType::Timestamp, 180),
                col("event_type", "EventType", ColumnType::Text, 90),
                col("device_name", "DeviceName", ColumnType::Text, 220),
                col("description", "Description", ColumnType::Text, 240),
                col("device_type", "DeviceType", ColumnType::Text, 130),
                col("drive_letter", "DriveLetter", ColumnType::Text, 90),
                col("serial_number", "SerialNumber", ColumnType::Text, 180),
                col("vendor_id", "VendorID", ColumnType::Text, 90),
                col("product_id", "ProductID", ColumnType::Text, 90),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}

// ---------------------------------------------------------------------------
// 12. artifacts.vss — Shadow Copy Catalog
// ---------------------------------------------------------------------------

pub struct ShadowCopyProvider {
    source: ForensicSource,
}

impl ShadowCopyProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self { source }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let records: Vec<ShadowCopyRecord> = if self.source.is_live() {
            live::enumerate_live_shadow_copies().map_err(|e| e.to_table_error())?
        } else {
            load_offline_shadow_copies(&self.source).map_err(|e| e.to_table_error())?
        };

        let rows: Vec<Row> = records
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                let detail = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.shadow_copy_name.clone()),
                        CellValue::Text(r.device_object.clone()),
                        CellValue::Text(r.volume_name.clone()),
                        opt_timestamp(r.created_time),
                        CellValue::Text(r.snapshot_id.clone()),
                        non_empty_text(&r.originating_machine),
                        non_empty_text(&r.service_machine),
                        non_empty_text(&r.provider_id),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, Vec::new()))
    }
}

impl TableProvider for ShadowCopyProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.vss"
    }

    fn description(&self) -> &'static str {
        "Read-only WMI Win32_ShadowCopy/VSS enumeration and offline VSS catalog parser"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Shadow Copy Catalog",
            vec![
                col("shadow_copy_name", "ShadowCopyName", ColumnType::Text, 180),
                col("device_object", "DeviceObject", ColumnType::Text, 280),
                col("volume_name", "VolumeName", ColumnType::Text, 240),
                col("created_time", "CreatedTime", ColumnType::Timestamp, 180),
                col("snapshot_id", "SnapshotID", ColumnType::Text, 240),
                col("originating_machine", "OriginatingMachine", ColumnType::Text, 160),
                col("service_machine", "ServiceMachine", ColumnType::Text, 160),
                col("provider_id", "ProviderID", ColumnType::Text, 240),
            ],
        )
        .with_default_sort(3, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}

// ---------------------------------------------------------------------------
// 13. artifacts.previous — Previous File Versions
// ---------------------------------------------------------------------------

pub struct PreviousFilesProvider {
    source: ForensicSource,
    options: PreviousFilesOptions,
}

impl PreviousFilesProvider {
    pub fn new(source: ForensicSource) -> Self {
        Self {
            source,
            options: PreviousFilesOptions::default(),
        }
    }

    pub fn with_options(source: ForensicSource, options: PreviousFilesOptions) -> Self {
        Self { source, options }
    }

    pub fn query_with_warnings(&self, req: &TableQuery) -> Result<(TableData, Vec<DiagnosticWarning>), TableError> {
        let mut records: Vec<PreviousFileRecord> = Vec::new();
        let warnings = Vec::new();

        if self.source.is_live() {
            let shadows = live::enumerate_live_shadow_copies().map_err(|e| e.to_table_error())?;
            for s in shadows {
                let remaining = self.options.max_entries.saturating_sub(records.len());
                if remaining == 0 {
                    break;
                }
                let root = Path::new(&s.device_object);
                let mut per_shadow_opts = self.options.clone();
                per_shadow_opts.max_entries = remaining;
                let mut found = enumerate_shadow_root_files(root, s.created_time, &per_shadow_opts);
                records.append(&mut found);
            }
        } else {
            records = load_offline_previous_files(&self.source, &self.options).map_err(|e| e.to_table_error())?;
        }

        let rows: Vec<Row> = records
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                let detail = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.filename.clone()),
                        CellValue::Text(r.folder.clone()),
                        opt_timestamp(r.snapshot_date),
                        CellValue::Bytes(r.file_size),
                        opt_timestamp(r.modified_time),
                        CellValue::Text(r.shadow_volume_path.clone()),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let table = apply_rows(&self.schema(), &rows, req)?;
        Ok((table, warnings))
    }
}

impl TableProvider for PreviousFilesProvider {
    fn tool_id(&self) -> &'static str {
        "artifacts.previous"
    }

    fn description(&self) -> &'static str {
        "Read-only VSS shadow-volume file browser and safe copy-out restore view"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Previous File Versions",
            vec![
                col("filename", "Filename", ColumnType::Text, 200),
                col("folder", "Folder", ColumnType::Text, 280),
                col("snapshot_date", "SnapshotDate", ColumnType::Timestamp, 180),
                col("file_size", "FileSize", ColumnType::BytesSize, 110),
                col("modified_time", "ModifiedTime", ColumnType::Timestamp, 180),
                col("shadow_volume_path", "ShadowVolumePath", ColumnType::Text, 340),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.query_with_warnings(req).map(|(t, _)| t)
    }
}
