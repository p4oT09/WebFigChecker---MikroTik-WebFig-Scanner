# WebFigChecker 🔍

**Fast Rust-based scanner to detect MikroTik WebFig services across IPs, CIDRs, Ranges, and ASNs.**  
Developed and maintained by **p4oT09**.

---

## ✨ Features
- 🚀 Ultra-fast scanning with Rust async runtime
- 🌐 Supports scanning by **IP, Range, CIDR, ASN**
- 🔑 Detects MikroTik WebFig instances
- ⚡ Adjustable concurrency & timeout
- 📦 Cross-platform support (Linux, Windows, Android/Termux)
- 🔄 ASN API fallback (bgpview + RIPE Stat)

---

## 📥 Installation

### 🐧 Linux
```bash
sudo apt update && sudo apt install -y git curl build-essential pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
git clone https://github.com/p4oT09/WebFigChecker---MikroTik-WebFig-Scanner.git
cd WebFigChecker---MikroTik-WebFig-Scanner
cargo build --release
```

Run:
```bash
./target/release/webfigchecker --help
```

---

### 🪟 Windows (PowerShell)
```powershell
winget install --id Rustlang.Rustup -e
git clone https://github.com/p4oT09/WebFigChecker---MikroTik-WebFig-Scanner.git
cd WebFigChecker---MikroTik-WebFig-Scanner
cargo build --release
```

Run:
```powershell
.	arget
elease\webfigchecker.exe --help
```

---

### 📱 Android (Termux)
```bash
pkg update && pkg upgrade
pkg install rust git clang cmake pkg-config openssl
git clone https://github.com/p4oT09/WebFigChecker---MikroTik-WebFig-Scanner.git
cd WebFigChecker---MikroTik-WebFig-Scanner
cargo build --release
```

Run:
```bash
./target/release/webfigchecker --help
```

---

## 🚀 Usage Examples

### Scan ASN
```bash
./target/release/webfigchecker --asn AS13335 --all-ports -c 600 --timeout-ms 1200
```

### Scan IP range
```bash
./target/release/webfigchecker 192.168.1.0/24 --ports 80,8080,8291
```

### Scan a single IP
```bash
./target/release/webfigchecker 1.1.1.1 --all-ports
```

---

## 📊 Sample Output
```
==============================================
🔍 WebFigChecker - MikroTik WebFig Scanner
👤 Author: p4oT09
==============================================

ASN AS13335 -> 20 prefixes
Targets: 20 | Ports: 5 | concurrency=400 | timeout=1000ms
198.51.100.20:80   -> WebFig
203.0.113.15:8291  -> RouterOS v6.49
```

---

## 🛠 Troubleshooting

- **ASN shows `0 prefixes`**  
  ✅ Try numeric format: `--asn 13335` instead of `AS13335`  
  ✅ Ensure API reachability:  
  ```bash
  curl -s 'https://api.bgpview.io/asn/13335/prefixes' | head
  ```

- **`cargo: command not found`**  
  → Install Rust:  
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- **Build fails in Termux**  
  → Ensure dependencies:  
  ```bash
  pkg install clang cmake pkg-config openssl
  ```

---

## 📂 Project Structure
```
├── Cargo.toml
├── LICENSE
├── README.md
└── src/
    └── main.rs
```

---

## 🧑‍💻 Author
Developed by **p4oT09**

---

## 📜 License
This project is licensed under the MIT License.  
© 2025 p4oT09
