cmake_minimum_required(VERSION 3.14)
project(NetworkPacketAnalyzer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Sources ───────────────────────────────────────────────────
add_executable(packet_analyzer
    main.cpp
    PacketAnalyzer.cpp
)

# ── Find libpcap ──────────────────────────────────────────────
find_library(PCAP_LIB pcap REQUIRED)
target_link_libraries(packet_analyzer PRIVATE ${PCAP_LIB})

# ── Includes ─────────────────────────────────────────────────
target_include_directories(packet_analyzer PRIVATE ${CMAKE_SOURCE_DIR})

# ── Compiler flags ────────────────────────────────────────────
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(packet_analyzer PRIVATE
        -Wall -Wextra -O2 -g)
endif()

message(STATUS "Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler   : ${CMAKE_CXX_COMPILER_ID}")
