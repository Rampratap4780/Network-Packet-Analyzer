// ============================================================
//  File: PacketAnalyzer.h
// ============================================================
#pragma once

#include <string>
#include <map>
#include <cstdint>
#include "Logger.h"

// ── Config passed from CLI ────────────────────────────────────
struct AnalyzerConfig {
    std::string interface;
    std::string inputFile;
    std::string outputFile;
    std::string protocol;   // "tcp" | "udp" | "icmp" | ""
    int         filterPort  = 0;
    int         maxPackets  = 0;
    bool        verbose     = false;
};

// ── Per-session statistics ────────────────────────────────────
struct Stats {
    uint64_t total     = 0;
    uint64_t tcpCount  = 0;
    uint64_t udpCount  = 0;
    uint64_t icmpCount = 0;
    uint64_t otherCount= 0;
    uint64_t totalBytes= 0;
    std::map<std::string, uint64_t> topSrcIPs;
    std::map<std::string, uint64_t> topDstIPs;
    std::map<uint16_t,    uint64_t> topPorts;
};

// ── Main analyzer class ───────────────────────────────────────
class PacketAnalyzer {
public:
    PacketAnalyzer(const AnalyzerConfig& cfg, Logger& log);
    ~PacketAnalyzer();

    bool init();
    void run();
    void stop();
    void printStats() const;

private:
    AnalyzerConfig config_;
    Logger&        logger_;
    Stats          stats_;
    void*          pcapHandle_ = nullptr;   // pcap_t*  (opaque)
    void*          dumper_     = nullptr;   // pcap_dumper_t* (opaque)
    bool           running_    = false;

    // Internal helpers
    bool  openLive();
    bool  openFile();
    bool  applyFilter();
    bool  openDumper();
    void  processPacket(const void* header, const uint8_t* data);
    void  parseEthernet(const uint8_t* data, uint32_t len);
    void  parseIPv4(const uint8_t* data, uint32_t len);
    void  parseTCP(const uint8_t* data, uint32_t len,
                   const std::string& src, const std::string& dst);
    void  parseUDP(const uint8_t* data, uint32_t len,
                   const std::string& src, const std::string& dst);
    void  parseICMP(const uint8_t* data, uint32_t len);

    static void packetCallback(uint8_t* user,
                               const void* header,
                               const uint8_t* packet);
};
