// BER framing of a stream longer than 4 GiB, generated on the fly (never
// on disk): 4400 pairs of a 1 MiB OCTET STRING record and a 3-octet INTEGER
// record, then a truncated record. Checks every frame's 64-bit offset, the
// absolute offset of the final error past 2^32, and that memory stays at
// the size of one record (book.md "Reading Records from Files and Streams").
// The same stream is framed by the Rust (ber::frames) and Java
// (BerFramesTest) tests.
#include <sys/resource.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <asn1cpp/codec/BerFrames.hpp>

using namespace asn1;

namespace {

constexpr std::uint64_t kContent = 1 << 20;                   // 1 MiB
constexpr std::uint8_t kBigHeader[] = {0x04, 0x83, 0x10, 0x00, 0x00};
constexpr std::uint8_t kSmall[] = {0x02, 0x01, 0x05};
constexpr std::uint8_t kTail[] = {0x04, 0x05, 0x00};          // 5 contents octets claimed, 1 given
constexpr std::uint64_t kBig = sizeof kBigHeader + kContent;
constexpr std::uint64_t kPair = kBig + sizeof kSmall;
constexpr std::uint64_t kPairs = 4400;
constexpr std::uint64_t kTotal = kPairs * kPair + sizeof kTail;

/// The stream above, octet by octet as asked for: big header, zero
/// contents, small record, per pair; then the tail.
class Generated final : public IByteInput {
    std::uint64_t pos_ = 0;

    std::uint8_t at(std::uint64_t p) const {
        if (p >= kPairs * kPair) return kTail[p - kPairs * kPair];
        std::uint64_t q = p % kPair;
        if (q < sizeof kBigHeader) return kBigHeader[q];
        if (q < kBig) return 0;
        return kSmall[q - kBig];
    }

public:
    Expected<std::size_t, DecodeError> read(std::span<std::uint8_t> dst) override {
        std::size_t n = 0;
        while (n < dst.size() && pos_ < kTotal) {
            const std::uint64_t q = pos_ % kPair;
            if (pos_ < kPairs * kPair && q >= sizeof kBigHeader && q < kBig) {
                const std::size_t run = std::min<std::uint64_t>(kBig - q, dst.size() - n);
                std::memset(dst.data() + n, 0, run);
                n += run;
                pos_ += run;
            } else {
                dst[n++] = at(pos_++);
            }
        }
        return n;
    }
};

} // namespace

int main() {
    Generated in;
    BerFrameReader frames{in};
    std::uint64_t count = 0;
    bool offsets_ok = true;
    for (;;) {
        auto f = frames.next();
        if (!f) {
            const bool ok = f.error().message.rfind("truncated:", 0) == 0 && f.error().offset == kTotal;
            printf("  %s  final error \"%s\" at %zu (expected %llu)\n", ok ? "PASS" : "FAIL",
                   f.error().message.c_str(), f.error().offset, static_cast<unsigned long long>(kTotal));
            if (!ok) return 1;
            break;
        }
        if (!*f) {
            printf("  FAIL  stream ended without the truncated tail\n");
            return 1;
        }
        const std::uint64_t pair = count / 2;
        const std::uint64_t want = pair * kPair + (count % 2 ? kBig : 0);
        const std::uint64_t want_len = count % 2 ? sizeof kSmall : kBig;
        if ((**f).offset != want || (**f).bytes.size() != want_len) offsets_ok = false;
        ++count;
    }
    printf("  %s  %llu frames, offsets and lengths%s\n", offsets_ok && count == 2 * kPairs ? "PASS" : "FAIL",
           static_cast<unsigned long long>(count), offsets_ok ? "" : " differ");
    if (!offsets_ok || count != 2 * kPairs) return 1;

    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    const long max_mib = ru.ru_maxrss / 1024;   // Linux: kilobytes
    const bool bounded = max_mib < 64;
    printf("  %s  peak memory %ld MiB for a %llu-octet stream\n", bounded ? "PASS" : "FAIL", max_mib,
           static_cast<unsigned long long>(kTotal));
    return bounded ? 0 : 1;
}
