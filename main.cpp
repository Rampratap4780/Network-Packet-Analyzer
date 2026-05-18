// ============================================================
//  Network Packet Analyzer - Main Entry Point
//  File: main.cpp
// ============================================================

#include "PacketAnalyzer.h"
#include "Logger.h"
#include <iostream>
#include <string>

void printBanner() {
    std::cout << R"(
╔══════════════════════════════════════════════════════╗
║         NETWORK PACKET ANALYZER  v1.0                ║
║         C++ | Cisco-Style | Pcap-based               ║
╚══════════════════════════════════════════════════════╝
)" << std::endl;
}

void printUsage(const char* progName) {
    std::cout << "Usage:\n"
              << "  " << progName << " -i <interface>        Live capture\n"
              << "  " << progName << " -f <file.pcap>        Read pcap file\n"
              << "  " << progName << " -p <port>             Filter by port\n"
              << "  " << progName << " -P <protocol>         Filter: tcp|udp|icmp\n"
              << "  " << progName << " -c <count>            Max packets to capture\n"
              << "  " << progName << " -o <output.pcap>      Save capture to file\n"
              << "  " << progName << " -v                    Verbose mode\n"
              << "  " << progName << " -h                    Show this help\n\n"
              << "Examples:\n"
              << "  " << progName << " -i eth0 -P tcp -c 100\n"
              << "  " << progName << " -f capture.pcap -v\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    printBanner();

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    AnalyzerConfig config;
    config.verbose    = false;
    config.maxPackets = 0;
    config.filterPort = 0;

    // Parse CLI arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h") { printUsage(argv[0]); return 0; }
        else if (arg == "-v") { config.verbose = true; }
        else if (arg == "-i" && i + 1 < argc) { config.interface  = argv[++i]; }
        else if (arg == "-f" && i + 1 < argc) { config.inputFile  = argv[++i]; }
        else if (arg == "-o" && i + 1 < argc) { config.outputFile = argv[++i]; }
        else if (arg == "-P" && i + 1 < argc) { config.protocol   = argv[++i]; }
        else if (arg == "-p" && i + 1 < argc) { config.filterPort = std::stoi(argv[++i]); }
        else if (arg == "-c" && i + 1 < argc) { config.maxPackets = std::stoi(argv[++i]); }
        else {
            std::cerr << "[ERROR] Unknown argument: " << arg << "\n";
            printUsage(argv[0]);
            return 1;
        }
    }

    if (config.interface.empty() && config.inputFile.empty()) {
        std::cerr << "[ERROR] Specify -i <interface> or -f <file.pcap>\n";
        return 1;
    }

    Logger logger(config.verbose);
    PacketAnalyzer analyzer(config, logger);

    if (!analyzer.init()) {
        std::cerr << "[ERROR] Initialization failed.\n";
        return 1;
    }

    analyzer.run();
    analyzer.printStats();

    return 0;
}
