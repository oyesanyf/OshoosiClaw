# Support & Help for OpenỌ̀ṣọ́ọ̀sì (OshoosiClaw)

Thank you for using OpenỌ̀ṣọ́ọ̀sì! Whether you are deploying the EDR daemon on production hosts, integrating continuous HAR sensors, or training SkyRL active defense models, resources are available to help you succeed.

---

## 🧭 Where to Find Help

### 1. 📖 Technical Documentation & README
Before seeking assistance, check the [README.md](README.md) and technical guides:
- [60-Second Quick Start](README.md#60-second-quick-start)
- [WebUI Navigation Guide](README.md#webui-navigation-guide-http1270013030)
- [CLI Reference Guide](README.md#cli-reference)
- [Troubleshooting & Diagnostics](README.md#native-windows-service-lifecycle-osoosiedr)

### 2. 💬 Community Discussions & Questions
For general questions, configuration assistance, deployment tuning, or architecture inquiries:
- Join [GitHub Discussions](https://github.com/oyesanyf/OshoosiClaw/discussions) to ask questions and share feedback with other operators and maintainers.

### 3. 🐛 Bug Reports
If you encounter a reproducible bug, service crash, or unexpected behavior:
- Check existing [GitHub Issues](https://github.com/oyesanyf/OshoosiClaw/issues) to see if it has already been reported.
- If not, open a new [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) with full logs from `logs/osoosi.log`.

### 4. 🔒 Security Vulnerabilities
> [!IMPORTANT]
> For security vulnerabilities, agent bypasses, or potential exploits, **DO NOT** post in public forums or open public issues. Follow our [Security Policy](SECURITY.md) and report privately via [GitHub Security Advisories](https://github.com/oyesanyf/OshoosiClaw/security/advisories/new).

---

## 🛠️ Diagnostics & Diagnostic Artifacts

When requesting support, providing system diagnostics drastically speeds up triage:

```powershell
# 1. Check daemon status
osoosi-cli status

# 2. Check service logs
Get-Content logs/osoosi.log -Tail 50

# 3. Verify port 3030 connectivity
curl -s http://127.0.0.1:3030/api/status
```

---

## 📜 Community Code of Conduct
All participants in our support channels are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).
