// BER record framing (book.md "Reading Records from Files and Streams"):
// every vector of tests/framing/framing.vectors through BerSpanFrames,
// BerFrameReader over a std::istream, a FILE* and an input that delivers one
// octet per read. All four must report exactly the frames and the result
// given there; the stream readers must also leave the input at the end of
// each frame. Then decode_frame: a decoded frame and a rebased error offset.
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/BerFrames.hpp>

using namespace asn1;

static int failures = 0;

static void check(const std::string& label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label.c_str());
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label.c_str()); ++failures; }
}

struct Expect {
    std::string file;
    std::size_t max_frame;
    std::vector<std::pair<std::uint64_t, std::size_t>> frames;
    std::string result;   ///< "end" or "error REASON OFFSET"
};

static std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    out.push_back(cur);
    return out;
}

static std::vector<Expect> load(const std::string& dir) {
    std::ifstream f(dir + "/framing.vectors");
    std::vector<Expect> out;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto cols = split(line, '\t');
        Expect e;
        e.file = cols[0];
        e.max_frame = cols[1] == "-" ? FrameLimits{}.max_frame : std::stoull(cols[1]);
        if (cols[2] != "-")
            for (auto& fr : split(cols[2], ',')) {
                auto plus = fr.find('+');
                e.frames.emplace_back(std::stoull(fr.substr(0, plus)), std::stoull(fr.substr(plus + 1)));
            }
        e.result = cols[3];
        out.push_back(e);
    }
    return out;
}

static std::vector<std::uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), {}};
}

/// One octet per read, to exercise every partial-read path of the framer.
class OneOctetInput final : public IByteInput {
    std::span<const std::uint8_t> data_;
    std::size_t pos_ = 0;
public:
    explicit OneOctetInput(std::span<const std::uint8_t> d) : data_(d) {}
    Expected<std::size_t, DecodeError> read(std::span<std::uint8_t> dst) override {
        if (pos_ >= data_.size() || dst.empty()) return std::size_t{0};
        dst[0] = data_[pos_++];
        return std::size_t{1};
    }
    std::size_t pos() const { return pos_; }
};

/// Run one framer to the end and render what it reported in the
/// framing.vectors notation; \p consumed (if given) is checked after each frame.
template <class Framer>
static std::string run(Framer& framer, const std::vector<std::uint8_t>& data,
                       std::vector<std::pair<std::uint64_t, std::size_t>>& frames,
                       const std::function<std::uint64_t()>& consumed, bool& exact) {
    exact = true;
    for (;;) {
        auto fr = framer.next();
        if (!fr) {
            const auto& msg = fr.error().message;
            // A stopped framer keeps reporting the same error.
            auto again = framer.next();
            if (again || again.error().message != msg) return "error-not-sticky";
            return "error " + msg.substr(0, msg.find(':')) + " " + std::to_string(fr.error().offset);
        }
        if (!*fr) return "end";
        const BerFrame& f = **fr;
        frames.emplace_back(f.offset, f.bytes.size());
        if (f.offset + f.bytes.size() > data.size() ||
            !std::equal(f.bytes.begin(), f.bytes.end(), data.begin() + static_cast<std::ptrdiff_t>(f.offset)))
            return "frame-bytes-differ";
        if (consumed && consumed() != f.offset + f.bytes.size()) exact = false;
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: test_ber_frames <tests/framing dir>\n");
        return 2;
    }
    const std::string dir = argv[1];
    const auto vectors = load(dir);
    check("framing.vectors has vectors", vectors.size() > 20);

    for (const auto& v : vectors) {
        printf("=== %s ===\n", v.file.c_str());
        const std::string path = dir + "/" + v.file;
        const auto data = read_file(path);
        const FrameLimits limits{v.max_frame};

        auto expect = [&](const char* how, const std::string& result,
                          const std::vector<std::pair<std::uint64_t, std::size_t>>& frames, bool exact) {
            check(std::string(how) + ": frames", frames == v.frames);
            check(std::string(how) + ": " + v.result + (result == v.result ? "" : " (got " + result + ")"),
                  result == v.result);
            check(std::string(how) + ": input left at the end of each frame", exact);
        };

        {
            BerSpanFrames framer{data, limits};
            std::vector<std::pair<std::uint64_t, std::size_t>> frames;
            bool exact;
            auto result = run(framer, data, frames, {}, exact);
            expect("span", result, frames, exact);
        }
        {
            std::ifstream f(path, std::ios::binary);
            IstreamInput in{f};
            BerFrameReader framer{in, limits};
            std::vector<std::pair<std::uint64_t, std::size_t>> frames;
            bool exact;
            auto result = run(framer, data, frames,
                              [&] { return static_cast<std::uint64_t>(f.tellg()); }, exact);
            expect("istream", result, frames, exact);
        }
        {
            std::FILE* f = std::fopen(path.c_str(), "rb");
            FileInput in{f};
            BerFrameReader framer{in, limits};
            std::vector<std::pair<std::uint64_t, std::size_t>> frames;
            bool exact;
            auto result = run(framer, data, frames,
                              [&] { return static_cast<std::uint64_t>(std::ftell(f)); }, exact);
            std::fclose(f);
            expect("FILE*", result, frames, exact);
        }
        {
            OneOctetInput in{data};
            BerFrameReader framer{in, limits};
            std::vector<std::pair<std::uint64_t, std::size_t>> frames;
            bool exact;
            auto result = run(framer, data, frames, [&] { return static_cast<std::uint64_t>(in.pos()); }, exact);
            expect("one octet per read", result, frames, exact);
        }
    }

    printf("=== decode_frame ===\n");
    {
        // Two INTEGER records after 100 octets of other input: the second has
        // no contents octets, which X.690 §8.3.1 forbids.
        const std::vector<std::uint8_t> data = {0x02, 0x01, 0x05, 0x02, 0x00};
        BerSpanFrames framer{data, {}, 100};
        auto a = framer.next();
        Integer i{};
        auto ok = decode_frame(**a, Integer::asn_DEF, &i);
        check("first frame decodes", ok.has_value() && i == 5);
        auto b = framer.next();
        check("second frame framed at offset 103", b && *b && (**b).offset == 103);
        Integer j{};
        auto bad = decode_frame(**b, Integer::asn_DEF, &j);
        check("decode error offset is absolute", !bad && bad.error().offset >= 103);
        check("framer continues after a decode error", framer.next() && !*framer.next());
    }
    {
        std::istringstream bad("x");
        bad.setstate(std::ios::badbit);
        IstreamInput in{bad};
        BerFrameReader framer{in};
        auto fr = framer.next();
        check("a failing stream is a read error", !fr && fr.error().message.rfind("read error:", 0) == 0);
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
