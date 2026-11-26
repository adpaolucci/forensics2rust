# Packaging Manifests (`WinGet` & `Homebrew`)

This directory stores package manager manifests for **`forensics2rust`**.

> Note: Replace the placeholder `0000...` SHA-256 checksums in the WinGet installer manifest and Homebrew formula with the published release archive checksums when cutting a GitHub Release.

## 1. Windows Package Manager (`winget`)

Validate and submit the YAML manifests in `packaging/winget/manifests/a/adpaolucci/forensics2rust/<version>/`:

```powershell
# Local validation using winget CLI
winget validate --manifest .\packaging\winget\manifests\a\adpaolucci\forensics2rust\0.1.0

# Or submit an automated PR to microsoft/winget-pkgs using wingetcreate
wingetcreate submit .\packaging\winget\manifests\a\adpaolucci\forensics2rust\0.1.0
```

Installed portable command aliases: `forensics2rust`, `forensics2rust-win32`, `forensics2rust-iced`.

## 2. Homebrew (`macOS` & `Linux`)

Copy `packaging/homebrew/forensics2rust.rb` into `Formula/forensics2rust.rb` of a tap repository (e.g., `adpaolucci/homebrew-tap`):

```bash
brew install adpaolucci/tap/forensics2rust
# Or test locally directly from file:
brew install --formula ./packaging/homebrew/forensics2rust.rb
brew test forensics2rust
```
