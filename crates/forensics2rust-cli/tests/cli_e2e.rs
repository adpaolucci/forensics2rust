#![forbid(unsafe_code)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use forensics2rust_core::FORENSIC_TOOL_CATALOG;
use forensics2rust_hive::regf::RegfBuilder;
use forensics2rust_report::{
    CustodyManifest, compute_merkle_root_sha256, compute_merkle_root_sha512, sha256_hex, sha512_hex,
};
use serde_json::{Value, json};
use tempfile::tempdir;

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_forensics2rust"))
}

fn create_offline_fixture_dir() -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let ntuser_v1 = RegfBuilder::new("ROOT")
        .add_sz("Software\\Demo", "Mode", "baseline")
        .add_dword("Software\\Demo", "Count", 1)
        .build();
    let ntuser_v2 = RegfBuilder::new("ROOT")
        .add_sz("Software\\Demo", "Mode", "updated")
        .add_dword("Software\\Demo", "Count", 2)
        .add_sz("Software\\Demo", "Extra", "added")
        .build();
    fs::write(root.join("NTUSER.DAT"), ntuser_v1).unwrap();
    fs::write(root.join("NTUSER_v2.DAT"), ntuser_v2).unwrap();

    fs::write(
        root.join("watch.reg"),
        "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Demo]\r\n\"WatchKey\"=\"enabled\"\r\n",
    )
    .unwrap();

    fs::write(
        root.join("Report.wer"),
        "Version=1\r\nEventType=APPCRASH\r\nAppName=notepad.exe\r\nAppPath=C:\\Windows\\System32\\notepad.exe\r\n",
    )
    .unwrap();
    fs::write(
        root.join("Report2.wer"),
        "Version=1\r\nEventType=BEX64\r\nAppName=calc.exe\r\nAppPath=C:\\Windows\\System32\\calc.exe\r\n",
    )
    .unwrap();

    fs::write(
        root.join("setupapi.dev.log"),
        ">>>  [Device Install (Hardware initiated) - USB\\VID_1234&PID_5678\\SER001]\r\n>>>  Section start 2025/01/15 10:00:00.000\r\n<<<  Section end 2025/01/15 10:00:01.000\r\n<<<  [Exit status: SUCCESS]\r\n",
    )
    .unwrap();

    fs::write(
        root.join("wua_updates.json"),
        r#"[{"title":"2025-01 Cumulative Update (KB5050001)","kb_article":"KB5050001","installed_on":"2025-01-15T12:00:00Z","result":"Succeeded","operation":"Installation","category":"Security Updates"}]"#,
    )
    .unwrap();

    fs::write(
        root.join("CBS.log"),
        "2025-01-15 12:00:00, Info                  CBS    Package Package_for_RollupFix~31bf3856ad364e35~amd64~~22621.4751.1.1 is Installed\r\n",
    )
    .unwrap();

    dir
}

#[test]
fn binary_help_version_list_diag_and_mcp_tools_work() {
    let help = Command::new(cli_bin()).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help_txt = String::from_utf8_lossy(&help.stdout);
    assert!(help_txt.contains("forensics2rust"));
    assert!(help_txt.contains("evtx"));
    assert!(help_txt.contains("hive"));
    assert!(help_txt.contains("srum"));
    assert!(help_txt.contains("artifacts"));
    assert!(help_txt.contains("crash"));
    assert!(help_txt.contains("posture"));

    let version = Command::new(cli_bin()).arg("--version").output().unwrap();
    assert!(version.status.success());

    let list = Command::new(cli_bin()).arg("list").output().unwrap();
    assert!(list.status.success());
    let list_txt = String::from_utf8_lossy(&list.stdout);
    assert_eq!(list_txt.lines().count(), FORENSIC_TOOL_CATALOG.len());

    let diag = Command::new(cli_bin()).args(["diag", "--json"]).output().unwrap();
    assert!(diag.status.success());
    let diag_json: Value = serde_json::from_slice(&diag.stdout).unwrap();
    assert_eq!(diag_json["catalog_tools"], 45);
    assert_eq!(diag_json["read_only"], true);

    let mcp_tools = Command::new(cli_bin()).args(["mcp", "--tools"]).output().unwrap();
    assert!(mcp_tools.status.success());
    let tools: Vec<Value> = serde_json::from_slice(&mcp_tools.stdout).unwrap();
    assert_eq!(tools.len(), 45);
    for tool in &tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], json!(true));
        assert_eq!(tool["annotations"]["destructiveHint"], json!(false));
    }
}

#[test]
fn binary_live_mcp_stdio_round_trip_succeeds() {
    let dir = create_offline_fixture_dir();
    let mut child = Command::new(cli_bin())
        .args(["mcp", "--source"])
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        )
        .unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        )
        .unwrap();
        writeln!(
            stdin,
            "{}",
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "crash.wer",
                    "arguments": {
                        "filter": "app_name == 'notepad.exe'",
                        "limit": 1,
                        "offset": 0
                    }
                }
            })
        )
        .unwrap();
        stdin.flush().unwrap();
    }
    drop(child.stdin.take());

    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut responses = Vec::new();
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap() > 0 {
        if !line.trim().is_empty() {
            responses.push(serde_json::from_str::<Value>(&line).unwrap());
        }
        line.clear();
    }

    let status = child.wait().unwrap();
    assert!(status.success());
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0]["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(responses[1]["result"]["tools"].as_array().unwrap().len(), 45);
    assert_eq!(responses[2]["result"]["isError"], json!(false));
    let call_payload: Value =
        serde_json::from_str(responses[2]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(call_payload["returned_rows"], 1);
}

#[test]
fn binary_offline_subcommand_query_export_and_custody_verification() {
    let dir = create_offline_fixture_dir();
    let out_csv = dir.path().join("out").join("wer.csv");
    let custody_path = dir.path().join("out").join("wer_custody.json");

    // 1. Offline WER with --filter, --limit, --offset, --format csv, --out, --custody
    let out = Command::new(cli_bin())
        .args([
            "--source",
            dir.path().to_str().unwrap(),
            "--filter",
            "app_name contains 'calc'",
            "--limit",
            "1",
            "--offset",
            "0",
            "--format",
            "csv",
            "--out",
            out_csv.to_str().unwrap(),
            "--custody",
            custody_path.to_str().unwrap(),
            "crash",
            "wer",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(out_csv.is_file());
    assert!(custody_path.is_file());

    let csv_bytes = fs::read(&out_csv).unwrap();
    let csv_text = String::from_utf8(csv_bytes.clone()).unwrap();
    assert!(csv_text.contains("calc.exe"));
    assert!(!csv_text.contains("notepad.exe"));

    let manifest: CustodyManifest = serde_json::from_slice(&fs::read(&custody_path).unwrap()).unwrap();
    let expected_256 = sha256_hex(&csv_bytes);
    let expected_512 = sha512_hex(&csv_bytes);
    assert_eq!(manifest.leaves[0].sha256, expected_256);
    assert_eq!(manifest.leaves[0].sha512, expected_512);
    assert_eq!(manifest.merkle_root_sha256, compute_merkle_root_sha256(&[expected_256]));
    assert_eq!(manifest.merkle_root_sha512, compute_merkle_root_sha512(&[expected_512]));

    // 2. Hive offline with --getnir and --format json
    let hive_out = Command::new(cli_bin())
        .args([
            "--offline",
            dir.path().join("NTUSER.DAT").to_str().unwrap(),
            "--getnir",
            "value_name == 'Mode'",
            "--format",
            "json",
            "hive",
            "offline",
        ])
        .output()
        .unwrap();
    assert!(
        hive_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&hive_out.stderr)
    );
    let hive_rows: Vec<Value> = serde_json::from_slice(&hive_out.stdout).unwrap();
    assert_eq!(hive_rows.len(), 1);
    assert_eq!(hive_rows[0]["value_name"], "Mode");
    assert_eq!(hive_rows[0]["data_decoded"], "baseline");

    // 3. Diff command comparing NTUSER.DAT vs NTUSER_v2.DAT
    let diff_out = Command::new(cli_bin())
        .args([
            "--format",
            "json",
            "diff",
            "--left",
            dir.path().join("NTUSER.DAT").to_str().unwrap(),
            "--right",
            dir.path().join("NTUSER_v2.DAT").to_str().unwrap(),
            "--tool",
            "hive.offline",
            "--keys",
            "key_path,value_name",
        ])
        .output()
        .unwrap();
    assert!(
        diff_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&diff_out.stderr)
    );
    let diff_rows: Vec<Value> = serde_json::from_slice(&diff_out.stdout).unwrap();
    assert!(!diff_rows.is_empty());

    // 4. Category bundle export
    let bundle_dir = dir.path().join("posture_bundle");
    let export_out = Command::new(cli_bin())
        .args([
            "--source",
            dir.path().to_str().unwrap(),
            "--format",
            "json",
            "--out",
            bundle_dir.to_str().unwrap(),
            "export",
            "--category",
            "posture",
        ])
        .output()
        .unwrap();
    assert!(
        export_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&export_out.stderr)
    );
    assert!(bundle_dir.join("custody_manifest.json").is_file());
}

#[test]
fn binary_stdout_custody_matches_exact_bytes_across_all_formats() {
    let dir = create_offline_fixture_dir();
    let formats = ["csv", "tsv", "json", "jsonl", "html", "html-vertical", "markdown"];

    for fmt in formats {
        let custody_path = dir.path().join(format!("stdout_{fmt}.custody.json"));
        let out = Command::new(cli_bin())
            .args([
                "--source",
                dir.path().to_str().unwrap(),
                "--format",
                fmt,
                "--custody",
                custody_path.to_str().unwrap(),
                "crash",
                "wer",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "format={fmt} stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.stdout.ends_with(b"\n"),
            "format={fmt} stdout should end with newline"
        );
        if fmt == "json" {
            let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert!(parsed.is_array());
        }

        let manifest: CustodyManifest = serde_json::from_slice(&fs::read(&custody_path).unwrap()).unwrap();
        assert_eq!(manifest.leaves.len(), 1, "format={fmt}");
        let expected_256 = sha256_hex(&out.stdout);
        let expected_512 = sha512_hex(&out.stdout);
        assert_eq!(
            manifest.leaves[0].size_bytes,
            out.stdout.len() as u64,
            "byte length mismatch for stdout format={fmt}"
        );
        assert_eq!(
            manifest.leaves[0].sha256, expected_256,
            "sha256 mismatch for stdout format={fmt}"
        );
        assert_eq!(
            manifest.leaves[0].sha512, expected_512,
            "sha512 mismatch for stdout format={fmt}"
        );
        assert_eq!(
            manifest.merkle_root_sha256,
            compute_merkle_root_sha256(&[expected_256]),
            "merkle sha256 mismatch for stdout format={fmt}"
        );
        assert_eq!(
            manifest.merkle_root_sha512,
            compute_merkle_root_sha512(&[expected_512]),
            "merkle sha512 mismatch for stdout format={fmt}"
        );
    }
}

#[test]
fn binary_mcp_notification_without_id_produces_zero_stdout_lines() {
    // 1. Standalone notification without "id" -> 0 stdout bytes, exit 0
    let mut silent_child = Command::new(cli_bin())
        .args(["mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = silent_child.stdin.as_mut().unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","method":"ping"}}"#).unwrap();
        stdin.flush().unwrap();
    }
    drop(silent_child.stdin.take());
    let silent_out = silent_child.wait_with_output().unwrap();
    assert!(silent_out.status.success());
    assert!(
        silent_out.stdout.is_empty(),
        "expected empty stdout for notification without id, got: {}",
        String::from_utf8_lossy(&silent_out.stdout)
    );

    // 2. Mixed stream: notifications (no "id") silent, "id": 1 and "id": null reply
    let mut mixed_child = Command::new(cli_bin())
        .args(["mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = mixed_child.stdin.as_mut().unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","method":"ping"}}"#).unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#).unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":null,"method":"ping"}}"#).unwrap();
        stdin.flush().unwrap();
    }
    drop(mixed_child.stdin.take());
    let mixed_out = mixed_child.wait_with_output().unwrap();
    assert!(mixed_out.status.success());
    let lines: Vec<Value> = String::from_utf8(mixed_out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["id"], json!(1));
    assert_eq!(lines[0]["result"], json!({}));
    assert_eq!(lines[1]["id"], Value::Null);
    assert_eq!(lines[1]["result"], json!({}));
}
