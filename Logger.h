// ============================================================
//  File: Logger.h
// ============================================================
#pragma once
#include <string>
#include <iostream>
#include <ctime>

class Logger {
public:
    explicit Logger(bool verbose = false) : verbose_(verbose) {}

    void info(const std::string& msg)   const { print("[INFO]   ", msg, "\033[32m"); }
    void error(const std::string& msg)  const { print("[ERROR]  ", msg, "\033[31m"); }
    void debug(const std::string& msg)  const { if (verbose_) print("[DEBUG]  ", msg, "\033[33m"); }
    void packet(const std::string& msg) const { print("[PKT]    ", msg, "\033[36m"); }

private:
    bool verbose_;

    static std::string timestamp() {
        time_t t = time(nullptr);
        char buf[20];
        strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&t));
        return std::string(buf);
    }

    void print(const std::string& level,
               const std::string& msg,
               const std::string& color) const {
        std::cout << color
                  << timestamp() << "  " << level << msg
                  << "\033[0m" << "\n";
    }
};
