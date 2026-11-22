# aegiscore

[![Java](https://img.shields.io/badge/Java-17%2B-orange?style=flat-square)](https://openjdk.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen?style=flat-square)](#build)
[![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)](LICENSE)

Zero-dependency Java 17+ PC security and maintenance suite: multithreaded malware & script scanner, Windows persistence auditor, AES-256-GCM quarantine vault, safe temp cleaner, and SHA-256 verified ZIP backup manager.

```text
========================================================
  AEGISCORE v1.0.0  |  PC Security, Scanner & Backup Suite
========================================================
  [#########################] 100%  (412/412 files | 2 threats)

Scan Complete
  Files      : 412 inspected (0 skipped)
  Data       : 184.62 MB
  Duration   : 1.42 s
  Threats    : 2 detected

  [CRITICAL 100/100] C:\Users\dips\Downloads\eicar.txt
    SHA-256  : 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    - EICAR Standard Antivirus Test Signature detected
```

## Capabilities

- **Multithreaded Deep Malware Scanner (`scan`)**:
  - **PE32/PE32+ Binary Analysis**: Parses DOS/COFF/Optional headers, section tables, Shannon entropy, RWX memory flags, known packers (UPX, Themida, VMProtect, ASPack, MPRESS, Enigma), real Import Address Table (IAT) API clusters (process injection, keyloggers, credential stealers, anti-debug/AMSI evasion), and disguised executables (`photo.jpg` with `MZ` header).
  - **Script & Dropper Detection**: Inspects `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.hta`, `.py`, `.sh`, `.reg` for encoded PowerShell (`-enc`), remote download-and-exec, Defender tampering (`Add-MpPreference`), ransomware shadow-copy deletion (`vssadmin delete shadows`), double extensions, and webhook exfiltration.
  - **Signature Matching**: Supports EICAR verification and custom SHA-256 hash blocklists in `~/.aegiscore/signatures.txt`.
  - **JSON Reporting**: Export structured scan results with `--json <report.json>`.
- **AES-256-GCM Quarantine Vault (`quarantine`)**:
  - Encrypts and isolates detected files into `~/.aegiscore/quarantine/*.aegisq` so they cannot be executed.
  - List, restore to original path, or securely overwrite and delete quarantined items.
- **Windows Persistence & System Auditor (`audit`)**:
  - Audits `HKCU`/`HKLM` `Run` and `RunOnce` registry keys, Windows Startup folders, `hosts` file hijacking, and active processes running from Temp or with encoded PowerShell arguments.
- **Safe PC Temp Cleaner (`clean`)**:
  - Previews (`--dry-run`) and safely removes unlocked temporary files in `%TEMP%`, `%LOCALAPPDATA%\Temp`, `CrashDumps`, and `C:\Windows\Temp`.
- **Verified ZIP Backup & Restore (`backup` / `verify` / `restore`)**:
  - Compresses directories with an embedded SHA-256 manifest (`.aegis-manifest.txt`), verifies archive integrity against bit-rot/tampering, and restores safely with Zip Slip protection.
- **Interactive Menu + CLI**: Run without arguments for a guided console menu, or automate via CLI flags.

## Build

Requires **JDK 17+**. No Maven, Gradle, or third-party dependencies.

**Windows (PowerShell):**
```powershell
javac --release 17 -d out src\com\dips\aegiscore\*.java
mkdir dist -Force | Out-Null
jar cfe dist\aegiscore.jar com.dips.aegiscore.Main -C out .
```

**Linux / macOS:**
```bash
javac --release 17 -d out src/com/dips/aegiscore/*.java
mkdir -p dist
jar cfe dist/aegiscore.jar com.dips.aegiscore.Main -C out .
```

## Usage

```bash
# Interactive menu
java -jar dist/aegiscore.jar

# Quick scan (Desktop, Downloads, Temp, Startup)
java -jar dist/aegiscore.jar scan --quick

# Deep scan a folder or drive with JSON report and auto-quarantine
java -jar dist/aegiscore.jar scan C:\Users\you\Downloads --deep --quarantine --json report.json

# Windows persistence, hosts & process audit
java -jar dist/aegiscore.jar audit

# Quarantine vault management
java -jar dist/aegiscore.jar quarantine list
java -jar dist/aegiscore.jar quarantine restore <id>
java -jar dist/aegiscore.jar quarantine delete <id>

# Safe temp cleaner (preview first, then apply)
java -jar dist/aegiscore.jar clean --dry-run
java -jar dist/aegiscore.jar clean --apply

# Verified backup & restore
java -jar dist/aegiscore.jar backup C:\Users\you\Documents backup.zip
java -jar dist/aegiscore.jar verify backup.zip
java -jar dist/aegiscore.jar restore backup.zip C:\Users\you\Restored
```

## Project Structure

```text
aegiscore/
└── src/com/dips/aegiscore/
    ├── Main.java            Interactive console menu and CLI entrypoint
    ├── ThreatScanner.java   Multithreaded scan engine, signatures, and JSON reports
    ├── PeScanner.java       PE32/PE32+ header, entropy, packer, and IAT analyzer
    ├── ScriptScanner.java   PowerShell, batch, VBS, JS, and ransomware script rules
    ├── QuarantineVault.java AES-256-GCM encrypted file isolation and restoration
    ├── SystemAuditor.java   Registry Run keys, Startup, hosts, and process auditor
    ├── PcCleaner.java       Safe dry-run/apply temporary file cleaner
    ├── BackupManager.java   SHA-256 manifest ZIP backup, verification, and restore
    └── ConsoleUi.java       ANSI formatting, progress bar, and severity badges
```

## License

MIT
