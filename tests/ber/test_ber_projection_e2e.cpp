// End-to-end test: BerProjection against a real PS_PDU frame.
//
// Usage: test_ber_projection_e2e <path-to-file.etsi>
//
// Reads the first PS_PDU BER TLV from the file, then:
//  1. Full BerCodec::decode<PS_PDU>()  — establishes reference LIID and seqNum
//  2. BerProjection apply()            — must produce identical values
//  3. In-place LIID patch via commit() + re-decode  — verifies round-trip
//
// Paths projected:
//   pSHeader/lawfulInterceptionIdentifier  →  OctetString (= LIID)
//   pSHeader/sequenceNumber                →  Integer

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>
#include <asn1cpp/codec/BerProjection.hpp>
#include <asn1cpp/codec/BerCodec.hpp>
#include <asn1cpp/codec/BerCursor.hpp>
#include <asn1cpp/codec/BerReader.hpp>
#include <asn1cpp/types/Integer.hpp>
#include <asn1cpp/types/OctetString.hpp>

// Generated PS_PDU types
#include "PS_PDU.hpp"
#include "PSHeader.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond, const char* detail = "") {
    if (cond) {
        printf("  \033[32mPASS\033[0m  %s\n", name);
    } else {
        printf("  \033[31mFAIL\033[0m  %s%s%s\n", name, *detail ? " — " : "", detail);
        ++failures;
    }
}

// Read first complete BER TLV from a file (definite-length only).
static std::vector<uint8_t> read_first_tlv(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        fprintf(stderr, "cannot open: %s\n", path);
        return {};
    }
    // Read tag byte(s)
    uint8_t tag0 = 0;
    f.read(reinterpret_cast<char*>(&tag0), 1);
    if (!f) return {};
    std::vector<uint8_t> header = {tag0};

    // Long-form tag
    if ((tag0 & 0x1F) == 0x1F) {
        uint8_t b;
        do {
            f.read(reinterpret_cast<char*>(&b), 1);
            header.push_back(b);
        } while (b & 0x80);
    }

    // Length
    uint8_t l0 = 0;
    f.read(reinterpret_cast<char*>(&l0), 1);
    if (!f) return {};
    header.push_back(l0);

    size_t vlen = 0;
    if (l0 < 0x80) {
        vlen = l0;
    } else {
        size_t nbytes = l0 & 0x7F;
        if (nbytes > 8) return {};
        for (size_t i = 0; i < nbytes; ++i) {
            uint8_t b;
            f.read(reinterpret_cast<char*>(&b), 1);
            if (!f) return {};
            header.push_back(b);
            vlen = (vlen << 8) | b;
        }
    }

    std::vector<uint8_t> buf = header;
    buf.resize(header.size() + vlen);
    f.read(reinterpret_cast<char*>(buf.data() + header.size()), static_cast<std::streamsize>(vlen));
    if (!f) return {};
    return buf;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.etsi>\n", argv[0]);
        return EXIT_FAILURE;
    }

    auto frame = read_first_tlv(argv[1]);
    if (frame.empty()) {
        fprintf(stderr, "failed to read first TLV from %s\n", argv[1]);
        return EXIT_FAILURE;
    }
    printf("Frame: %zu bytes\n", frame.size());

    // ── 1. Full decode — establish reference values ───────────────────────────

    PS_PDU full{};
    {
        BerReader reader{std::span<const uint8_t>(frame.data(), frame.size())};
        BerDecodeStream s{reader};
        auto ok = BerCodec::instance().decode(s, PS_PDU::asn_DEF, &full);
        if (!ok) {
            fprintf(stderr, "full decode failed: %s\n", ok.error().message.c_str());
            return EXIT_FAILURE;
        }
    }

    const OctetString& ref_liid  = full.pSHeader.lawfulInterceptionIdentifier;
    const Integer&     ref_seqno = full.pSHeader.sequenceNumber;

    printf("Reference LIID:  %zu bytes\n", ref_liid.bytes().size());
    printf("Reference seqno: %lld\n", static_cast<long long>(ref_seqno.value()));

    // ── 2. Projection — must match full decode ────────────────────────────────

    printf("=== Projection vs full decode ===\n");

    BerProjection proj{PS_PDU::asn_DEF};
    auto h_liid  = proj.add_path("pSHeader/lawfulInterceptionIdentifier");
    auto h_seqno = proj.add_path("pSHeader/sequenceNumber");
    proj.finalize();

    BerProjectionResult res{proj};

    // Generated ETSI descriptors use per-member local TypeDescriptors (different
    // pointer from Integer::asn_DEF / OctetString::asn_DEF, but same ber_handler).
    // bind/load accept same ber_handler as equivalent.
    res.apply(std::span<const uint8_t>(frame.data(), frame.size()));

    Asn1Optional<OctetString> liid;
    Asn1Optional<Integer>     seqno;
    res.load(h_liid,  liid);
    res.load(h_seqno, seqno);

    check("proj_liid_found",  liid.found);
    check("proj_seqno_found", seqno.found);

    if (liid.found) {
        const OctetString& proj_liid = static_cast<OctetString&>(liid);
        bool liid_match = proj_liid.bytes().size() == ref_liid.bytes().size()
            && std::memcmp(proj_liid.bytes().data(), ref_liid.bytes().data(),
                           ref_liid.bytes().size()) == 0;
        check("proj_liid_matches_full_decode", liid_match);
    }

    if (seqno.found) {
        check("proj_seqno_matches_full_decode",
              static_cast<Integer&>(seqno).value() == ref_seqno.value());
    }

    // ── 3. In-place LIID patch via commit() ───────────────────────────────────

    printf("=== In-place LIID patch ===\n");

    // commit() requires a binding; bind h_liid before the mutable apply.
    res.bind(h_liid, liid);

    std::vector<uint8_t> patched_frame = frame;
    res.apply(std::span<uint8_t>(patched_frame.data(), patched_frame.size()));
    check("mut_liid_found", liid.found);

    if (liid.found) {
        // Flip the first byte of the LIID value (same length — commit must succeed).
        OctetString& mutable_liid = static_cast<OctetString&>(liid);
        auto bytes = mutable_liid.bytes();
        std::vector<uint8_t> new_bytes(bytes.begin(), bytes.end());
        new_bytes[0] ^= 0xFF;
        mutable_liid.set(std::span<const uint8_t>(new_bytes.data(), new_bytes.size()));

        bool committed = res.commit(h_liid);
        check("commit_returned_true", committed);

        if (committed) {
            // Re-decode the patched frame and verify the LIID changed.
            PS_PDU re_decoded{};
            BerReader re_reader{std::span<const uint8_t>(patched_frame.data(), patched_frame.size())};
            BerDecodeStream re_s{re_reader};
            auto re_ok = BerCodec::instance().decode(re_s, PS_PDU::asn_DEF, &re_decoded);
            check("patched_decode_ok", re_ok.has_value());
            if (re_ok) {
                const auto& re_liid = re_decoded.pSHeader.lawfulInterceptionIdentifier;
                check("patched_liid_first_byte",
                      !re_liid.bytes().empty() &&
                      re_liid.bytes()[0] == (ref_liid.bytes()[0] ^ 0xFF));
                check("patched_seqno_unchanged",
                      re_decoded.pSHeader.sequenceNumber.value() == ref_seqno.value());
            }
        }
    }

    // ── 4. Multi-frame: apply the same projection 100× without state bleed ───

    printf("=== 100-frame no-bleed ===\n");
    int bleed = 0;
    for (int i = 0; i < 100; ++i) {
        res.apply(std::span<const uint8_t>(frame.data(), frame.size()));
        res.load(h_liid,  liid);
        res.load(h_seqno, seqno);
        if (!seqno.found) ++bleed;
        if (!liid.found)  ++bleed;
        if (seqno.found &&
            static_cast<Integer&>(seqno).value() != ref_seqno.value()) ++bleed;
    }
    check("100_frame_no_bleed", bleed == 0);

    printf("\n%s — %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
