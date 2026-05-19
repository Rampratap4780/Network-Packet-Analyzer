# 🔬 Network Packet Analyzer

<div align="center">

![C++17](https://img.shields.io/badge/C++-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![libpcap](https://img.shields.io/badge/libpcap-Core%20Library-blue?style=for-the-badge)
![CMake](https://img.shields.io/badge/CMake-064F8C?style=for-the-badge&logo=cmake&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A robust, modular network packet analyzer built for Linux environments.**  
Parse network traffic at the byte-level with support for live capture and offline `.pcap` analysis.

</div>

---

## 📖 Overview

Network Packet Analyzer is a high-performance, production-grade tool designed for network engineers, security researchers, and developers who need precise, low-level visibility into network traffic. Built on top of **libpcap** and architected in **modern C++17**, it combines raw packet parsing with an elegant, secure codebase.

Whether you're debugging network issues, analyzing captured traffic, or building your own intrusion detection pipeline — this tool gives you the byte-level control you need.

---

## 🚀 Features

| Feature | Description |
|---|---|
| 🔍 **Deep Packet Inspection** | Parses Ethernet, IPv4, TCP, UDP, and ICMP headers at the raw byte level |
| 🎯 **Advanced Traffic Filtering** | BPF (Berkeley Packet Filter) compilation via libpcap for precise protocol & port filtering |
| 🔄 **Dual Operation Modes** | Live network capture **and** offline `.pcap` file analysis |
| 📊 **Comprehensive Metrics** | Built-in statistics reporting for all analyzed traffic |
| 🛡️ **Secure Architecture** | RAII resource management, secure coding practices, zero memory leaks |
| 🧩 **Modular Design** | Highly decoupled C++17 architecture — easy to extend and maintain |

---

## 🛠️ Tech Stack

- **Language:** C++17
- **Core Library:** [libpcap](https://www.tcpdump.org/)
- **Build System:** CMake (≥ 3.15)
- **Platform:** Linux

---

## 📦 Prerequisites

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev

# Fedora / RHEL / CentOS
sudo dnf install -y gcc-c++ cmake libpcap-devel

# Arch Linux
sudo pacman -S base-devel cmake libpcap
```

> ⚠️ **Root privileges** (or `CAP_NET_RAW` capability) are required for live packet capture.

---

## 🔧 Build & Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/network-packet-analyzer.git
cd network-packet-analyzer

# 2. Configure the build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release

# 3. Compile
make -j$(nproc)

# 4. (Optional) Install system-wide
sudo make install
```

---

## 🚦 Usage

### Live Capture Mode

```bash
# Capture all traffic on eth0
sudo ./packet_analyzer --interface eth0

# Filter only TCP traffic on port 443 (HTTPS)
sudo ./packet_analyzer --interface eth0 --filter "tcp port 443"

# Filter ICMP packets (ping traffic)
sudo ./packet_analyzer --interface eth0 --filter "icmp"
```

### Offline Analysis Mode

```bash
# Analyze a saved .pcap file
./packet_analyzer --file capture.pcap

# Analyze with a BPF filter applied
./packet_analyzer --file capture.pcap --filter "udp port 53"
```

### Options Reference

```
Usage: packet_analyzer [OPTIONS]

Options:
  -i, --interface <name>   Network interface for live capture (e.g., eth0, wlan0)
  -f, --file <path>        Path to a .pcap file for offline analysis
  -F, --filter <expr>      BPF filter expression (e.g., "tcp port 80")
  -s, --stats              Print traffic statistics after capture
  -v, --verbose            Enable verbose output
  -h, --help               Show this help message
```

---

## 📐 Architecture

```
network-packet-analyzer/
├── src/
│   ├── main.cpp                 # Entry point & CLI argument parsing
│   ├── capture/
│   │   ├── LiveCapture.cpp      # Live packet capture via libpcap
│   │   └── FileCapture.cpp      # Offline .pcap file reader
│   ├── parsers/
│   │   ├── EthernetParser.cpp   # Layer 2: Ethernet frame parsing
│   │   ├── IPv4Parser.cpp       # Layer 3: IPv4 header parsing
│   │   ├── TCPParser.cpp        # Layer 4: TCP segment parsing
│   │   ├── UDPParser.cpp        # Layer 4: UDP datagram parsing
│   │   └── ICMPParser.cpp       # Layer 3: ICMP message parsing
│   ├── filter/
│   │   └── BPFFilter.cpp        # BPF filter compilation & application
│   └── stats/
│       └── StatsReporter.cpp    # Traffic metrics & reporting
├── include/                     # Header files
├── tests/                       # Unit & integration tests
├── CMakeLists.txt
└── README.md
```

### Design Principles

- **RAII:** All libpcap handles and file descriptors are managed through RAII wrappers — no resource leaks, even on exceptions.
- **Single Responsibility:** Each parser handles exactly one protocol layer.
- **Zero-Copy Parsing:** Headers are parsed in-place from the packet buffer — no unnecessary memory allocation.
- **Secure Coding:** Strict bounds checking on all packet buffers to prevent out-of-bounds reads.

---

## 📊 Sample Output

```
[2024-11-15 14:32:07] Packet #1042
  Ethernet : src=aa:bb:cc:dd:ee:ff  dst=11:22:33:44:55:66  type=IPv4
  IPv4     : src=192.168.1.5        dst=142.250.80.46       proto=TCP  ttl=64
  TCP      : src_port=52341         dst_port=443            flags=ACK  len=1448

--- Traffic Statistics ---
  Total Packets   :  10,482
  TCP Packets     :   8,314  (79.3%)
  UDP Packets     :   1,903  (18.1%)
  ICMP Packets    :     265   (2.5%)
  Avg Packet Size :   847 bytes
  Capture Duration:   30.4 seconds
```

---

## 🔒 Security & Permissions

Live capture requires elevated privileges. The recommended approach is to grant only the necessary capability rather than running as root:

```bash
# Grant CAP_NET_RAW to the binary (preferred over sudo)
sudo setcap cap_net_raw+ep ./packet_analyzer
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/add-ipv6-support`
3. **Commit** your changes: `git commit -m "feat: add IPv6 header parsing"`
4. **Push** to your branch: `git push origin feature/add-ipv6-support`
5. **Open** a Pull Request

Please ensure your code follows the existing style and includes tests where applicable.

---

## 🗺️ Roadmap

- [ ] IPv6 header parsing support
- [ ] DNS / HTTP layer-7 protocol dissection
- [ ] JSON / CSV export of captured traffic
- [ ] ncurses-based live terminal dashboard
- [ ] Packet injection / replay support

---


## 👨‍💻 Author

**Rampratap Singh Rajpoot**



<div align="center">
  <sub>Built with ❤️ and raw sockets in C++17</sub>
</div>
