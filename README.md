# BrowserFortify 🛡️

Cross-platform browser security remediation & hardening tool.

[![Build Status](https://github.com/revdjcoady/BrowserFortify/workflows/Build%20BrowserFortify%20Executables/badge.svg)](https://github.com/revdjcoady/BrowserFortify/actions)
[![Latest Release](https://img.shields.io/github/v/release/revdjcoady/BrowserFortify)](https://github.com/revdjcoady/BrowserFortify/releases/latest)

## 🚀 Quick Download

**Executables available at:** [Releases Page](https://github.com/revdjcoady/BrowserFortify/releases/latest)

- **Windows:** `BrowserFortify-windows.exe`
- **Linux:** `BrowserFortify-linux`
- **macOS:** `BrowserFortify-macos` (Universal Binary)

## 🎯 Features

- ✅ Detects and removes malicious browser extensions
- ✅ Clears enterprise policies set by malware
- ✅ Identifies homepage/search engine hijacking
- ✅ Backs up browser profiles before changes
- ✅ Cross-platform: Windows, macOS, Linux
- ✅ Multi-browser: Chrome, Edge, Firefox, Safari

## 🔧 Usage

```bash
# Scan only (safe, no changes)
./BrowserFortify --scan-only

# Full remediation with backup
./BrowserFortify --remediate --backup --clear-data --remove-suspicious

# Nuclear option - reset all profiles
./BrowserFortify --remediate --reset-profiles --backup

# Dry run - see what would be done
./BrowserFortify --remediate --dry-run

# Force mode - no prompts
./BrowserFortify --remediate --yes --force-kill
```

## 📊 Command Line Options

| Option | Description |
|--------|-------------|
| `--scan-only` | Just scan and report, don't make changes |
| `--remediate` | Apply security fixes |
| `--backup` | Backup profiles before changes |
| `--clear-data` | Clear browser caches and browsing data |
| `--reset-profiles` | Rename profiles for fresh start |
| `--remove-suspicious` | Remove extensions with suspicious permissions |
| `--dry-run` | Show what would be done without making changes |
| `--force-kill` | Force terminate browser processes |
| `-y, --yes` | Don't prompt for confirmation |

## 🛡️ Security Use Cases

- **Personal Security:** Clean compromised browsers
- **Incident Response:** Rapidly assess browser compromise
- **IT Support:** Bulk browser cleanup across fleet
- **Forensics:** Document browser-based threats

## 📈 Build Status

This repository automatically builds executables for all platforms using GitHub Actions.

**Latest Build:** [![Build Status](https://github.com/revdjcoady/BrowserFortify/workflows/Build%20BrowserFortify%20Executables/badge.svg)](https://github.com/revdjcoady/BrowserFortify/actions)

## 🔄 Updating

New releases are automatically built when tags are pushed. To get the latest version:

1. Check the [Releases page](https://github.com/revdjcoady/BrowserFortify/releases)
2. Download the latest executable for your platform
3. Replace your old version

## ⚠️ Important Notes

- **Always backup** your browser data before running
- **Close all browsers** before remediation
- **Run as administrator** on Windows for full functionality
- **Use sudo** on Linux for system-wide policy cleanup

## 📄 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/revdjcoady/BrowserFortify/issues)
- **Documentation:** [Wiki](https://github.com/revdjcoady/BrowserFortify/wiki)
