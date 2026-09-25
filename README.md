# 🛡️ SIFO Anti Backdoor

<p align="center">
  <b>Advanced FiveM Security & Anti-Backdoor Scanner</b><br>
  Detect suspicious code, backdoors, RCE patterns, obfuscation, resource manipulation and other security indicators.
</p>

---

<div align="center">

# 🛒 SIFO STORE

### 🚀 Take Your FiveM Server to the Next Level

**Looking for quality FiveM scripts and resources for your server?**

Explore the **SIFO Tebex Store** and discover the available resources.

<br>

<a href="https://sifo.tebex.store/" target="_blank">
  <img src="https://img.shields.io/badge/🛍️%20VISIT%20SIFO%20STORE-FF6B00?style=for-the-badge&logo=shopify&logoColor=white" alt="Visit SIFO Store">
</a>

<br><br>

**👉 https://sifo.tebex.store/**

</div>

---


## ✨ Features

- 🔍 Threat intelligence database
- 🧠 Behavioral security analysis
- 🚨 Remote Code Execution (RCE) detection
- 🛡️ Dedicated txAdmin monitor RCE detection
- 🔐 Detection of known backdoor indicators
- 🌐 Suspicious network / HTTP activity detection
- ⚙️ Resource manipulation detection
- 💻 Command execution abuse detection
- 📦 Suspicious file access detection
- 🎭 Lua obfuscation detection
- 🔢 Encoded / Base64 payload indicators
- 🎯 Suspicious event and NUI patterns
- 💰 Economy and inventory manipulation indicators
- 🗄️ Suspicious database execution patterns
- 🌍 Entity / network abuse indicators
- 📊 Risk scoring per resource
- 🔔 Discord webhook reporting
- 🔄 Automatic GitHub update system
- 📁 Modular scanner architecture

---

## 🚨 txAdmin RCE Detection

SIFO Anti Backdoor includes a dedicated detector for the known txAdmin monitor Event-to-Code-Execution pattern.

The detector does **not** rely only on a specific event name. It analyzes the relationship between:

`RegisterNetEvent` → `AddEventHandler` → event argument → `load/loadstring` → function execution

This allows the scanner to identify renamed variants of the same dangerous behavior.

The known `monitor/resource/cl_playerlist.lua` pattern is also recognized and reported as a **CRITICAL** finding.

---

## 🧠 Behavioral Detection

The scanner does not automatically consider every FiveM API malicious.

Instead, it combines related indicators and analyzes suspicious behavior such as:

- Network request + dynamic code execution
- Downloaded content + code execution
- Network event + money/inventory manipulation
- NUI callback + sensitive server-side action
- Network event + entity lookup/control
- Network event + database execution
- Obfuscated strings + dynamic execution
- Remote manifest dependencies

This approach helps reduce false positives from legitimate resources.

---

## 📊 Risk Levels

Detected resources are assigned a risk level:

| Level | Score |
|---|---:|
| 🔴 CRITICAL | 80+ |
| 🟠 HIGH | 60–79 |
| 🟡 MEDIUM | 30–59 |
| 🔵 LOW | 1–29 |
| 🟢 CLEAN | 0 |

A finding's severity is based on the detected indicator or behavior. The score is intended as a triage signal, not proof by itself that a resource is malicious.

---

## 🔔 Discord Reports

You can configure separate Discord webhooks for:

- All findings
- Critical findings

Recommended configuration through `server.cfg`:

```cfg
set sifo_antibackdoor_all_webhook "YOUR_ALL_WEBHOOK"
set sifo_antibackdoor_critical_webhook "YOUR_CRITICAL_WEBHOOK"
```

Webhook URLs should not be committed to GitHub.

---

## 🔄 Automatic Updates

SIFO Anti Backdoor includes an automatic GitHub update checker.

When the resource starts, it checks the official repository for a newer version.

If an update is available:

1. The new files are downloaded.
2. The current running version remains active.
3. The downloaded version is loaded on the next resource/server restart.

### Version

Current release:

**v1.0.0**

---

## ⚙️ Commands

Run these commands from the server console:

```
sifo_scan
sifo_risk
```

### `sifo_scan`

Starts a complete security scan of the configured FiveM resources.

### `sifo_risk`

Displays resource risk information collected by the scanner.

---

## 📁 Project Structure

```text
sifo-antibackdoor/
│
├── fxmanifest.lua
├── config.lua
├── threats.lua
├── rules.lua
├── updater.lua
├── update_manifest.json
├── version.txt
│
└── server/
    ├── main.lua
    ├── threat_scanner.lua
    ├── behavior_scanner.lua
    ├── rules_scanner.lua
    ├── resource_scanner.lua
    ├── reporter.lua
    └── commands.lua
```

---

## 🛠️ Installation

1. Download or purchase the resource.
2. Place `sifo-antibackdoor` inside your FiveM resources folder.
3. Add it to `server.cfg`:

```cfg
ensure sifo-antibackdoor
```

4. Configure `config.lua` if needed.
5. Start/restart the server.
6. The scanner will automatically perform its startup scan.

---

## ⚙️ Configuration

Main settings are located in:

```text
config.lua
```

You can configure:

- Discord reporting
- Scan delay
- Automatic scanning
- Resource allowlist
- Indicator allowlist
- File extensions
- Obfuscation thresholds
- Local forensic reports

---

## 📋 Supported File Types

By default, the scanner checks:

```text
.lua
.js
.json
.cfg
.txt
.sql
.html
.css
```

The scanner uses resource metadata to determine which files are available to scan.

---

## ⚠️ Important Security Notice

SIFO Anti Backdoor is a **heuristic and signature-based security scanner**.

No static scanner can guarantee detection of every possible malicious resource, especially previously unknown or heavily customized attacks.

A **CRITICAL** finding should be investigated rather than treated as automatic proof of compromise.

For best security, combine the scanner with:

- Trusted resource sources
- Regular server audits
- Restricted server permissions
- Secure txAdmin configuration
- Protected server credentials
- Monitoring of unexpected resource changes

---

## 📜 License

This project is distributed by **SIFO Scripts**.

Do not redistribute, resell, re-upload or claim this resource as your own without permission.

---

## 📞 Support

For support, updates, bug reports and other SIFO Scripts:

**Discord:** https://discord.gg/CEw6y3SY9h

---

<p align="center">
  <b>© SIFO Scripts</b><br>
  FiveM Development • Security • Scripts
</p>
