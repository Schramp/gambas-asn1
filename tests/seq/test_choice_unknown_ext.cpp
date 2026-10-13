// CHOICE extension alternative unknown to the receiver (X.691 §23.8;
// per_choice_unknown_ext_test.asn1): MsgV2 is a later version of MsgV1.
//   - A MsgV2 extension alternative decodes as MsgV1: the open type is
//     skipped (counted in skipped_extensions()), no alternative selected.
//   - A root alternative encodes identically in both versions and decodes.
#include <cstdio>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "MsgV1.hpp"
#include "MsgV2.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static std::vector<uint8_t> per_enc(const TypeDescriptor& def, const Asn1Object* obj) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    IEncodeStream& es = s;
    PerCodec::instance().encode(es, def, obj);
    s.flush();
    return buf;
}

int main() {
    MsgV2 ext;
    ext.set_present(MsgV2::PR::b);
    ext.b() = Boolean{true};
    auto ext_bytes = per_enc(MsgV2::asn_DEF, &ext);
    {
        MsgV1 v1;
        PerDecodeStream s{std::span<const uint8_t>{ext_bytes}};
        IDecodeStream& ds = s;
        bool ok = PerCodec::instance().decode(ds, MsgV1::asn_DEF, &v1).has_value();
        check("MsgV2 extension alternative decodes as MsgV1", ok);
        check("the unknown alternative is skipped and counted", s.skipped_extensions() == 1);
        check("no MsgV1 alternative is selected", v1.present() == MsgV1::PR::NOTHING);
    }

    MsgV2 root2;
    root2.set_present(MsgV2::PR::a);
    root2.a() = Integer{5};
    MsgV1 root1;
    root1.set_present(MsgV1::PR::a);
    root1.a() = Integer{5};
    auto root_bytes = per_enc(MsgV2::asn_DEF, &root2);
    check("a root alternative encodes identically in both versions",
          root_bytes == per_enc(MsgV1::asn_DEF, &root1));
    {
        MsgV1 v1;
        PerDecodeStream s{std::span<const uint8_t>{root_bytes}};
        IDecodeStream& ds = s;
        bool ok = PerCodec::instance().decode(ds, MsgV1::asn_DEF, &v1).has_value();
        check("MsgV2 root alternative decodes as MsgV1",
              ok && v1.present() == MsgV1::PR::a && v1.a().value() == 5);
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
