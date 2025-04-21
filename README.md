# 🛡️ Web Scanner

A powerful Python-based CLI tool for automating web security testing.  
**Web Scanner** helps ethical hackers and security professionals detect common web vulnerabilities like:

- 🔍 XSS (Reflected, Stored, and DOM-Based)
- 🧬 SQL Injection (Error-based, Boolean-based, Blind)
- 🛡️ WAF (Web Application Firewall) presence
- 📁 Directory/File Enumeration with progress meter
- 🌐 Real IP Detection behind CDNs like Cloudflare
- ☁️ Open cloud bucket misconfiguration scanning

---

## 📸 Screenshot

> Example: Scanning for WAF, Directories, SQLi and XSS

![Screenshot](screenshots/result.png)

---

## ⚙️ Features

- ✅ Lightweight & Terminal-Based
- 🌈 Color-coded output using `termcolor`
- 🧵 Multi-threaded directory enumeration with `%` progress
- 📡 Discover origin IP behind Cloudflare/CDNs
- 🛡️ WAF fingerprinting via headers, responses & anomalies
- ☁️ S3 bucket enumeration for misconfigured cloud storage
- 🔐 CLI-friendly for quick recon and testing

---

## 🚀 How to Use

```bash
git clone https://github.com/Rajesh-code-droid/web_scanner.git
cd web_scanner
python scanner.py
