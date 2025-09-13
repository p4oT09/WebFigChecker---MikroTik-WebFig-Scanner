# webfigchecker

> Fast Rust scanner to detect MikroTik WebFig across IPs, CIDRs, ranges, and ASNs

## Features

- 🔍 **ASN Scan** – যেকোনো Autonomous System (AS নম্বর) স্ক্যান করে প্রিফিক্স বের করে IP চেক করে।
- 🌐 **CIDR Scan** – যেকোনো CIDR রেঞ্জের সব বা স্যাম্পল IP স্ক্যান করে।
- 📝 **IP Range Scan** – শুরু থেকে শেষ IP পর্যন্ত সিকোয়েন্সিয়ালি স্ক্যান করে।
- ⚡ **All Ports or Custom Ports** – একসাথে সব পোর্ট (১–৬৫৫৩৫) বা নিজের কাস্টম পোর্ট লিস্ট স্ক্যান করতে পারো।
- 🔑 **Fast Async Engine** – Rust + Tokio দিয়ে একসাথে অনেক কানেকশন হ্যান্ডেল করে দ্রুত স্ক্যান।
- 🖥 **Cross Platform** – Termux (Android), Linux, Windows সবখানে রান করে।
- 📝 **Author Banner** – চালানোর সময় টুলের নাম আর Author: p4oT09 ব্যানার হিসেবে দেখায়।



![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Author](https://img.shields.io/badge/author-p4oT09-orange)



Detect MikroTik **WebFig** (RouterOS) across IPs, CIDRs, IPv4 ranges, or ASNs.

## Build

### Termux / Android
```bash
pkg update && pkg upgrade
pkg install rust
cargo build --release
```

### Windows
```powershell
winget install Rustlang.Rustup
cargo build --release
```

## Usage

```
webfigchecker [OPTIONS] <IP>
# or with flags (IP not needed):
--asn AS12345 | --cidr 192.168.1.0/24 | --ip-range 192.168.1.10-192.168.1.50
```

### Examples

**ASN (default ports 80,443,8080,8291):**
```bash
./target/release/webfigchecker --asn AS15169
```

**ASN + all ports (⚠ heavy):**
```bash
./target/release/webfigchecker --asn AS15169 --all-ports -c 600 --timeout-ms 1200
```

**ASN + expand all IPs (⚠ very heavy):**
```bash
./target/release/webfigchecker --asn AS15169 --expand-all-ips --ports 80,443,8291
```

**CIDR:**
```bash
./target/release/webfigchecker --cidr 192.168.1.0/24 --ports 80,8291
```

**IPv4 range:**
```bash
./target/release/webfigchecker --ip-range 192.168.1.10-192.168.1.50 --all-ports
# or shorthand within same /24:
./target/release/webfigchecker --ip-range 192.168.1.10-50 --ports 80,8291
```

**Single IP:**
```bash
./target/release/webfigchecker 203.0.113.20 --all-ports
```

### Flags

- `--ports 80,443,8080,8291` : custom port list  
- `--all-ports` : scan 1–65535  
- `--per-prefix N` : for ASN/CIDR, sample N IPs per prefix (default 1)  
- `--expand-all-ips` : expand every IP in each prefix (use with caution)  
- `-c, --concurrency` : max concurrent connections (default 400)  
- `--timeout-ms` : per-connection timeout (default 800ms)

### Notes

- Use **only on networks you own or have permission to scan**.
- On mobile devices, try `-c 300..600` and increase `--timeout-ms` if your network is slow.

## License

MIT

## Author

Created by **p4oT09**

## Installation

### Termux (Android)
```bash
pkg update && pkg upgrade
pkg install rust git
git clone https://github.com/p4oT09/webfigchecker.git
cd webfigchecker
cargo build --release
```

### Linux
```bash
sudo apt update
sudo apt install -y curl build-essential pkg-config libssl-dev git
curl https://sh.rustup.rs -sSf | sh
git clone https://github.com/p4oT09/webfigchecker.git
cd webfigchecker
cargo build --release
```

### Windows (PowerShell)
```powershell
winget install Rustlang.Rustup
git clone https://github.com/p4oT09/webfigchecker.git
cd webfigchecker
cargo build --release
```


## Run Commands

**Single IP:**
```bash
./target/release/webfigchecker 192.168.88.1 --all-ports
```

**ASN all ports (⚠ heavy):**
```bash
./target/release/webfigchecker --asn AS15169 --all-ports -c 600 --timeout-ms 1200
```

**CIDR:**
```bash
./target/release/webfigchecker --cidr 192.168.1.0/24 --ports 80,8291
```

**IP Range:**
```bash
./target/release/webfigchecker --ip-range 192.168.1.10-192.168.1.50 --all-ports
```

**Custom Ports:**
```bash
./target/release/webfigchecker 203.0.113.20 --ports 80,443,8291,8443
```

**Per-prefix sampling (ASN):**
```bash
./target/release/webfigchecker --asn AS15169 --ports 80,8291 --per-prefix 2
```

**Expand all IPs in ASN (⚠ very heavy):**
```bash
./target/release/webfigchecker --asn AS15169 --expand-all-ips --ports 80,443,8291
```

## Sample Output

Example ASN scan result:

```
$ ./target/release/webfigchecker --asn AS15169 --ports 80,8291 --per-prefix 1

ASN AS15169 -> 25 prefixes
Targets: 25 | Ports: 2 | concurrency=400 | timeout=800ms
203.0.113.10:80   -> RouterOS v6.49
203.0.113.20:8291 -> WebFig
198.51.100.5:80   -> MikroTik RouterOS
```
