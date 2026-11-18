// Regression test for issue #109: self-referential SEQUENCE OF in namespace mode.
// Generated with -fprefix=testns; Tree.hpp must include TreeChildren.hpp AFTER the
// closing `} // namespace testns` brace, not before (which caused a compile error
// because Tree was incomplete at the point of VectorSeqOf<Tree> instantiation).
#include <cstdio>
#include <memory>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/BerCodec.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include <sys/resource.h>
#include <vector>
#include "Tree.hpp"

using namespace asn1;

static int failures = 0;
static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

int main() {
    printf("\n── ns_recursive_seqof (issue #109) ──\n");

    testns::Tree root{};
    root.value = Integer{1};
    root.children = std::make_unique<testns::TreeChildren>();
    testns::Tree child{};
    child.value = Integer{2};
    root.children->push_back(std::move(child));

    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream es{w};
    BerCodec::instance().encode(es, testns::Tree::asn_DEF, &root);
    check("encode non-empty", !buf.empty());

    testns::Tree decoded{};
    BerReader rd{buf};
    BerDecodeStream ds{rd};
    bool ok = BerCodec::instance().decode(ds, testns::Tree::asn_DEF, &decoded).has_value();
    check("decode ok", ok);
    check("root value == 1", ok && (int64_t)decoded.value == 1);
    check("children present", ok && decoded.children != nullptr);
    check("children count == 1", ok && decoded.children && decoded.children->size() == 1);
    check("child value == 2", ok && decoded.children && decoded.children->size() == 1
                               && (int64_t)(*decoded.children)[0].value == 2);

    // X.691 §20.6: one octet (C4) announces a fragment of 65536 elements.
    // 127 nested Trees, each "children present, value 0, 64K children", give
    // a 397-octet input that ends after the first child of every level. The
    // list must grow with the elements decoded, not to the announced count:
    // pre-sized, the nesting held 127 x 65536 Trees (195 MB) at once.
    printf("\n── PER: announced SEQUENCE OF count vs bits present ──\n");
    {
        std::vector<bool> bits;
        auto put = [&](uint32_t v, int n) { for (int i = n - 1; i >= 0; --i) bits.push_back((v >> i) & 1); };
        for (int level = 0; level < 127; ++level) {
            put(1, 1);       // children present
            put(1, 8);       // INTEGER length 1
            put(0, 8);       // value 0
            put(0xC4, 8);    // 4 x 16K children
        }
        std::vector<uint8_t> in((bits.size() + 7) / 8, 0);
        for (std::size_t i = 0; i < bits.size(); ++i)
            if (bits[i]) in[i / 8] |= static_cast<uint8_t>(0x80 >> (i % 8));
        rusage before{}, after{};
        getrusage(RUSAGE_SELF, &before);
        testns::Tree t{};
        PerDecodeStream ps{std::span<const uint8_t>(in)};
        bool per_ok = PerCodec::instance().decode(ps, testns::Tree::asn_DEF, &t).has_value();
        getrusage(RUSAGE_SELF, &after);
        long grew_kb = after.ru_maxrss - before.ru_maxrss;
        printf("  input %zu octets, peak RSS grew %ld KB\n", in.size(), grew_kb);
        check("truncated nested list fails", !per_ok);
        check("peak RSS grows < 16 MB", grew_kb < 16 * 1024);
    }

    printf("\n  %s\n", failures ? "FAILED" : "All tests passed.");
    return failures ? 1 : 0;
}
