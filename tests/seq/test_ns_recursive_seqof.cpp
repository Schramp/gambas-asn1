// Regression test for issue #109: self-referential SEQUENCE OF in namespace mode.
// Generated with -fprefix=testns; Tree.hpp must include TreeChildren.hpp AFTER the
// closing `} // namespace testns` brace, not before (which caused a compile error
// because Tree was incomplete at the point of VectorSeqOf<Tree> instantiation).
#include <cstdio>
#include <memory>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/BerCodec.hpp>
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

    printf("\n  %s\n", failures ? "FAILED" : "All tests passed.");
    return failures ? 1 : 0;
}
