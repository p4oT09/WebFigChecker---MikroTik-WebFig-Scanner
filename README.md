# 🚀 WebFigChecker – MikroTik Scanner

**Founder:** Ecbrain  
**Remodified:** p4oT09  

---

## ✨ Features
- 🎨 Colorful banner with credits
- Scan **single IPs, Ranges, CIDRs**
- `--all-ports` to scan all 65535 ports
- Default ports: 80,443,8080,8291,8443

---

## 🖥 Installation

### Linux
```bash
sudo apt update && sudo apt install -y git curl build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

git clone https://github.com/p4oT09/WebFigChecker---MikroTik-WebFig-Scanner.git
cd WebFigChecker---MikroTik-WebFig-Scanner
cargo build --release
```

### Android (Termux)
```bash
pkg update && pkg upgrade -y
pkg install rust git clang curl -y
git clone https://github.com/p4oT09/WebFigChecker---MikroTik-WebFig-Scanner.git
cd WebFigChecker---MikroTik-WebFig-Scanner
cargo build --release
```

### Windows (PowerShell)
```powershell
irm https://win.rustup.rs -UseBasicParsing | iex
git clone https://github.com/p4oT09/WebFigChecker---MikroTik-WebFig-Scanner.git
cd WebFigChecker---MikroTik-WebFig-Scanner
cargo build --release
```

---

## 📌 Usage Examples

### Single IP
```bash
./target/release/webfigchecker 192.168.1.1 --all-ports
```

### Range
```bash
./target/release/webfigchecker 192.168.1.10-192.168.1.50 --all-ports
```

### CIDR
```bash
./target/release/webfigchecker 192.168.1.0/24 --all-ports
```

---

## 🎨 Banner Demo
```
===========================================
   🚀 WebFigChecker – MikroTik Scanner 🚀
   Founder: Ecbrain
   Remodified: p4oT09
===========================================
```