//  File: PacketAnalyzer.cpp
// ============================================================
#include "PacketAnalyzer.h"
#include "Logger.h"
#include "Protocols.h"

#include <pcap/pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <vector>

// ── Constructor / Destructor ──────────────────────────────────
PacketAnalyzer::PacketAnalyzer(const AnalyzerConfig& cfg, Logger& log)
    : config_(cfg), logger_(log) {}

PacketAnalyzer::~PacketAnalyzer() {
    if (dumper_)     pcap_dump_close(static_cast<pcap_dumper_t*>(dumper_));
    if (pcapHandle_) pcap_close(static_cast<pcap_t*>(pcapHandle_));
}

// ── init() ───────────────────────────────────────────────────
bool PacketAnalyzer::init() {
    bool ok = config_.inputFile.empty() ? openLive() : openFile();
    if (!ok) return false;
    if (!config_.protocol.empty() || config_.filterPort) {
        if (!applyFilter()) return false;
    }
    if (!config_.outputFile.empty()) {
        if (!openDumper()) return false;
    }
    return true;
}

// ── openLive() ───────────────────────────────────────────────
bool PacketAnalyzer::openLive() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* h = pcap_open_live(config_.interface.c_str(),
                                65535, 1, 1000, errbuf);
    if (!h) {
        logger_.error("pcap_open_live: " + std::string(errbuf));
        return false;
    }
    pcapHandle_ = h;
    logger_.info("Capturing on interface: " + config_.interface);
    return true;
}

// ── openFile() ───────────────────────────────────────────────
bool PacketAnalyzer::openFile() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* h = pcap_open_offline(config_.inputFile.c_str(), errbuf);
    if (!h) {
        logger_.error("pcap_open_offline: " + std::string(errbuf));
        return false;
    }
    pcapHandle_ = h;
    logger_.info("Reading from file: " + config_.inputFile);
    return true;
}

// ── applyFilter() ────────────────────────────────────────────
bool PacketAnalyzer::applyFilter() {
    std::string expr;
    if (!config_.protocol.empty()) expr  = config_.protocol;
    if (config_.filterPort) {
        if (!expr.empty()) expr += " and ";
        expr += "port " + std::to_string(config_.filterPort);
    }

    struct bpf_program fp;
    pcap_t* h = static_cast<pcap_t*>(pcapHandle_);
    if (pcap_compile(h, &fp, expr.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        logger_.error("Filter compile error: " + std::string(pcap_geterr(h)));
        return false;
    }
    if (pcap_setfilter(h, &fp) == -1) {
        logger_.error("Filter apply error: " + std::string(pcap_geterr(h)));
        pcap_freecode(&fp);
        return false;
    }
    pcap_freecode(&fp);
    logger_.info("Filter applied: " + expr);
    return true;
}

// ── openDumper() ─────────────────────────────────────────────
bool PacketAnalyzer::openDumper() {
    pcap_dumper_t* d = pcap_dump_open(
        static_cast<pcap_t*>(pcapHandle_),
        config_.outputFile.c_str());
    if (!d) {
        logger_.error("Cannot open output file: " + config_.outputFile);
        return false;
    }
    dumper_ = d;
    logger_.info("Saving packets to: " + config_.outputFile);
    return true;
}

// ── Static callback ───────────────────────────────────────────
void PacketAnalyzer::packetCallback(uint8_t* user,
                                    const void* header,
                                    const uint8_t* packet) {
    auto* self = reinterpret_cast<PacketAnalyzer*>(user);
    self->processPacket(header, packet);
}

// ── run() ────────────────────────────────────────────────────
void PacketAnalyzer::run() {
    running_ = true;
    int limit = (config_.maxPackets > 0) ? config_.maxPackets : -1;
    logger_.info("Starting capture... (Ctrl+C to stop)");
    pcap_loop(static_cast<pcap_t*>(pcapHandle_),
              limit,
              packetCallback,
              reinterpret_cast<uint8_t*>(this));
    running_ = false;
    logger_.info("Capture complete.");
}

// ── processPacket() ──────────────────────────────────────────
void PacketAnalyzer::processPacket(const void* hdr, const uint8_t* data) {
    auto* ph = static_cast<const struct pcap_pkthdr*>(hdr);
    stats_.total++;
    stats_.totalBytes += ph->len;

    if (dumper_)
        pcap_dump(static_cast<u_char*>(dumper_), ph, data);

    parseEthernet(data, ph->caplen);
}

// ── parseEthernet() ──────────────────────────────────────────
void PacketAnalyzer::parseEthernet(const uint8_t* data, uint32_t len) {
    if (len < 14) return;
    uint16_t etherType = (data[12] << 8) | data[13];
    if (etherType == 0x0800)          // IPv4
        parseIPv4(data + 14, len - 14);
    else if (config_.verbose)
        logger_.debug("Non-IPv4 EtherType: 0x" +
                      std::to_string(etherType));
}

// ── parseIPv4() ──────────────────────────────────────────────
void PacketAnalyzer::parseIPv4(const uint8_t* data, uint32_t len) {
    if (len < 20) return;

    uint8_t  ihl      = (data[0] & 0x0F) * 4;
    uint8_t  proto    = data[9];
    struct in_addr srcA, dstA;
    memcpy(&srcA.s_addr, data + 12, 4);
    memcpy(&dstA.s_addr, data + 16, 4);
    std::string src = inet_ntoa(srcA);
    std::string dst = inet_ntoa(dstA);

    stats_.topSrcIPs[src]++;
    stats_.topDstIPs[dst]++;

    if (proto == IPPROTO_TCP) {
        stats_.tcpCount++;
        parseTCP(data + ihl, len - ihl, src, dst);
    } else if (proto == IPPROTO_UDP) {
        stats_.udpCount++;
        parseUDP(data + ihl, len - ihl, src, dst);
    } else if (proto == IPPROTO_ICMP) {
        stats_.icmpCount++;
        parseICMP(data + ihl, len - ihl);
    } else {
        stats_.otherCount++;
    }
}

// ── parseTCP() ───────────────────────────────────────────────
void PacketAnalyzer::parseTCP(const uint8_t* data, uint32_t len,
                               const std::string& src,
                               const std::string& dst) {
    if (len < 20) return;
    uint16_t sport = (data[0] << 8) | data[1];
    uint16_t dport = (data[2] << 8) | data[3];
    uint8_t  flags = data[13];
    stats_.topPorts[sport]++;
    stats_.topPorts[dport]++;

    if (config_.verbose) {
        std::string flagStr;
        if (flags & 0x02) flagStr += "SYN ";
        if (flags & 0x10) flagStr += "ACK ";
        if (flags & 0x01) flagStr += "FIN ";
        if (flags & 0x04) flagStr += "RST ";
        logger_.packet("[TCP] " + src + ":" + std::to_string(sport) +
                       " → " + dst + ":" + std::to_string(dport) +
                       "  [" + flagStr + "]");
    }
}

// ── parseUDP() ───────────────────────────────────────────────
void PacketAnalyzer::parseUDP(const uint8_t* data, uint32_t len,
                               const std::string& src,
                               const std::string& dst) {
    if (len < 8) return;
    uint16_t sport = (data[0] << 8) | data[1];
    uint16_t dport = (data[2] << 8) | data[3];
    stats_.topPorts[sport]++;
    stats_.topPorts[dport]++;

    if (config_.verbose) {
        logger_.packet("[UDP] " + src + ":" + std::to_string(sport) +
                       " → " + dst + ":" + std::to_string(dport));
    }
}

// ── parseICMP() ──────────────────────────────────────────────
void PacketAnalyzer::parseICMP(const uint8_t* data, uint32_t len) {
    if (len < 4) return;
    uint8_t type = data[0];
    uint8_t code = data[1];
    if (config_.verbose) {
        std::string desc;
        if (type == 8)  desc = "Echo Request";
        else if (type == 0)  desc = "Echo Reply";
        else if (type == 3)  desc = "Dest Unreachable";
        else if (type == 11) desc = "Time Exceeded";
        else desc = "Type=" + std::to_string(type);
        logger_.packet("[ICMP] " + desc + " Code=" + std::to_string(code));
    }
}

// ── printStats() ─────────────────────────────────────────────
void PacketAnalyzer::printStats() const {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout <<   "║           CAPTURE STATISTICS             ║\n";
    std::cout <<   "╠══════════════════════════════════════════╣\n";
    auto row = [](const std::string& k, auto v) {
        std::cout << "║  " << std::left << std::setw(20) << k
                  << std::right << std::setw(18) << v << "  ║\n";
    };
    row("Total Packets",  stats_.total);
    row("Total Bytes",    stats_.totalBytes);
    row("TCP",            stats_.tcpCount);
    row("UDP",            stats_.udpCount);
    row("ICMP",           stats_.icmpCount);
    row("Other",          stats_.otherCount);

    // Top 5 source IPs
    std::cout << "╠══════════════════════════════════════════╣\n";
    std::cout << "║  Top Source IPs                          ║\n";
    using P = std::pair<std::string,uint64_t>;
    std::vector<P> srcVec(stats_.topSrcIPs.begin(), stats_.topSrcIPs.end());
    std::sort(srcVec.begin(), srcVec.end(),
              [](const P& a, const P& b){ return a.second > b.second; });
    int cnt = 0;
    for (auto& [ip, n] : srcVec) {
        if (cnt++ >= 5) break;
        row(ip, n);
    }

    // Top 5 ports
    std::cout << "╠══════════════════════════════════════════╣\n";
    std::cout << "║  Top Ports                               ║\n";
    using PP = std::pair<uint16_t,uint64_t>;
    std::vector<PP> portVec(stats_.topPorts.begin(), stats_.topPorts.end());
    std::sort(portVec.begin(), portVec.end(),
              [](const PP& a, const PP& b){ return a.second > b.second; });
    cnt = 0;
    for (auto& [port, n] : portVec) {
        if (cnt++ >= 5) break;
        row("Port " + std::to_string(port), n);
    }

    std::cout << "╚══════════════════════════════════════════╝\n" << std::endl;
}
