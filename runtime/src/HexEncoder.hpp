#pragma once
#include <array>
#include <cstring>
#include <ostream>
#include <span>
#include <string>
#include <cstdint>

// 256-entry table: hex_pairs[b] encodes byte b as two uppercase hex chars
// packed little-endian in a uint16_t (low byte = high nibble, high byte = low nibble).
// One table lookup gives both output chars; avoids two shift+mask+index ops per byte.
inline constexpr std::array<uint16_t, 256> make_hex_pair_table() {
    constexpr char h[] = "0123456789ABCDEF";
    std::array<uint16_t, 256> t{};
    for (int i = 0; i < 256; ++i)
        t[i] = static_cast<uint16_t>(h[i >> 4] | (h[i & 0xF] << 8));
    return t;
}
inline constexpr auto k_hex_pairs = make_hex_pair_table();

// Write raw bytes as uppercase hex into an ostream, 4 KB buffered.
inline void write_hex_bytes(std::ostream& os, std::span<const uint8_t> bytes) {
    char buf[4096];
    std::size_t pos = 0;
    for (uint8_t b : bytes) {
        std::memcpy(&buf[pos], &k_hex_pairs[b], 2);
        pos += 2;
        if (pos == sizeof(buf)) { os.write(buf, pos); pos = 0; }
    }
    if (pos) os.write(buf, pos);
}

// Encode bytes as uppercase hex into a std::string (used when a string is needed).
inline std::string hex_encode_upper(std::span<const uint8_t> bytes) {
    std::string out;
    out.resize(bytes.size() * 2);
    char* p = out.data();
    for (uint8_t b : bytes) {
        uint16_t pair = k_hex_pairs[b];
        p[0] = static_cast<char>(pair & 0xFF);
        p[1] = static_cast<char>(pair >> 8);
        p += 2;
    }
    return out;
}
