# 🔥 Termux Pro Toolkit

> **Legal Recon & Learning Suite for Termux & Kali Linux** — Link Inspector • Phone Analyzer • IP Recon Panel • One-shot Setup

![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Kali%20Linux-green)
![Language](https://img.shields.io/badge/language-Bash-blue)
![License](https://img.shields.io/badge/use-ethical%20only-red)

---

## ✨ Modules

| # | Module | Description |
|---|--------|-------------|
| 🔎 | **Link Info Inspector** | Inspect links **you own or are authorized to test**: IP, country/ISP, page title, server type, redirect chain, SSL cert, WHOIS, security-header audit, top-10 open ports |
| 📱 | **Phone Number Analyzer** | Public numbering data for any number: validity, country, region, carrier, line type, timezones |
| 🕵️ | **My IP & Device Recon** | See exactly what any website sees about **your own** connection: IP, reverse DNS, ISP/ASN, location, VPN/proxy flags, device info |
| 🛠️ | **Termux Pro Setup** | One-shot installer: figlet, lolcat, nmap, whois, jq, openssl, python, git + custom ASCII boot banner |
| 📚 | **Ethical Use Guide** | Built-in reference: what's legal vs illegal (incl. Malaysia PDPA 2010 / CMA 1998) |

Stylish colorized terminal UI with ASCII banner, menu-driven, zero configuration.

---

## 🚀 Installation

### Termux (Android)
```bash
pkg update && pkg install -y git curl
git clone https://github.com/Janrahat/termux-pro-toolkit.git
cd termux-pro-toolkit
bash termux-pro-toolkit.sh
```

### Kali Linux
```bash
git clone https://github.com/Janrahat/termux-pro-toolkit.git
cd termux-pro-toolkit
chmod +x termux-pro-toolkit.sh
./termux-pro-toolkit.sh
```

The script auto-installs all dependencies on first launch.

---

## 📸 Screenshots

| Main Menu | Link Inspector | Phone Analyzer |
|-----------|----------------|----------------|
| *(screenshot here)* | *(screenshot here)* | *(screenshot here)* |

---

## ⚖️ Ethical Use Notice

This toolkit is built for **learning and authorized targets only**:

✅ **Allowed**
- Your own websites, links, and devices
- Your own phone number and IP
- Targets with **written permission**
- Practice labs: TryHackMe, HackTheBox, PortSwigger Academy

❌ **Not allowed**
- Scanning or harvesting other people
- Tracking anyone without consent
- Covert collection of personal data

Unauthorized collection of personal data is a crime in most jurisdictions — e.g. **PDPA 2010** and **CMA 1998 §233** in Malaysia. The author accepts no liability for misuse.

---

## 📜 License

MIT — use freely, use ethically.

---

**⭐ If this toolkit helped you learn, drop a star!**
