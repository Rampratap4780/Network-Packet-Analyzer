// ============================================================
//  File: Protocols.h  — well-known port / protocol helpers
// ============================================================
#pragma once
#include <string>
#include <cstdint>

inline std::string protocolName(uint8_t proto) {
    switch (proto) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 89: return "OSPF";
        default: return "Unknown(" + std::to_string(proto) + ")";
    }
}

inline std::string wellKnownPort(uint16_t port) {
    switch (port) {
        case 20:  return "FTP-Data";
        case 21:  return "FTP";
        case 22:  return "SSH";
        case 23:  return "Telnet";
        case 25:  return "SMTP";
        case 53:  return "DNS";
        case 67:  return "DHCP-Server";
        case 68:  return "DHCP-Client";
        case 80:  return "HTTP";
        case 110: return "POP3";
        case 123: return "NTP";
        case 143: return "IMAP";
        case 161: return "SNMP";
        case 443: return "HTTPS";
        case 514: return "Syslog";
        case 1723:return "PPTP";
        case 3306:return "MySQL";
        case 3389:return "RDP";
        case 5060:return "SIP";
        case 8080:return "HTTP-Alt";
        default:  return std::to_string(port);
    }
}
