// BER/XER round-trip tests for recursive types (self-referencing via unique_ptr).
// Covers: linked list, binary tree, mutually recursive pair.
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>
#include <span>
#include <memory>
#include <asn1cpp/asn1cpp.hpp>
#include "Node.hpp"
#include "Tree.hpp"
#include "Even.hpp"
#include "Odd.hpp"

using namespace asn1;

static int failures = 0;
static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else       { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static std::vector<uint8_t> ber_enc(const TypeDescriptor& def, const Asn1Object* p) {
    std::vector<uint8_t> buf;
    BerWriter w{buf}; BerEncodeStream s{w};
    BerCodec::instance().encode(s, def, p);
    return buf;
}

static bool ber_dec(std::span<const uint8_t> bytes, const TypeDescriptor& def, Asn1Object* p) {
    BerReader r{bytes}; BerDecodeStream s{r};
    return BerCodec::instance().decode(s, def, p).has_value();
}

static std::string xer_enc(const TypeDescriptor& def, const Asn1Object* p) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, def, p);
    return oss.str();
}

static bool xer_dec(const std::string& xml, const TypeDescriptor& def, Asn1Object* p) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, def, p).has_value();
}

int main() {
    // --- Node: single element (no next) ---
    printf("Node — single\n");
    {
        Node enc{};
        enc.value = Integer{42};

        auto bytes = ber_enc(Node::asn_DEF, &enc);
        check("Node single BER encode non-empty", !bytes.empty());

        Node dec{};
        check("Node single BER decode ok", ber_dec(bytes, Node::asn_DEF, &dec));
        check("Node single value",         (int64_t)dec.value == 42);
        check("Node single next absent",   !dec.next);
    }

    // --- Node: chain of depth 3 ---
    printf("Node — chain depth 3\n");
    {
        Node enc{};
        enc.value = Integer{1};
        enc.next  = std::make_unique<Node>();
        enc.next->value = Integer{2};
        enc.next->next  = std::make_unique<Node>();
        enc.next->next->value = Integer{3};

        auto bytes = ber_enc(Node::asn_DEF, &enc);
        check("Node chain BER encode non-empty", !bytes.empty());

        Node dec{};
        check("Node chain BER decode ok",        ber_dec(bytes, Node::asn_DEF, &dec));
        check("Node chain value[0]",             (int64_t)dec.value == 1);
        check("Node chain next[0] present",      !!dec.next);
        check("Node chain value[1]",             dec.next && (int64_t)dec.next->value == 2);
        check("Node chain next[1] present",      dec.next && !!dec.next->next);
        check("Node chain value[2]",             dec.next && dec.next->next &&
                                                 (int64_t)dec.next->next->value == 3);
        check("Node chain next[2] absent",       dec.next && dec.next->next &&
                                                 !dec.next->next->next);

        // BER encode again from decoded — must be identical
        auto bytes2 = ber_enc(Node::asn_DEF, &dec);
        check("Node chain BER idempotent",       bytes == bytes2);
    }

    // --- Node: XER round-trip ---
    printf("Node — XER chain\n");
    {
        Node enc{};
        enc.value = Integer{10};
        enc.next  = std::make_unique<Node>();
        enc.next->value = Integer{20};

        std::string xer = xer_enc(Node::asn_DEF, &enc);
        check("Node XER encode non-empty", !xer.empty());

        Node dec{};
        check("Node XER decode ok",        xer_dec(xer, Node::asn_DEF, &dec));
        check("Node XER value[0]",         (int64_t)dec.value == 10);
        check("Node XER next present",     !!dec.next);
        check("Node XER value[1]",         dec.next && (int64_t)dec.next->value == 20);
        check("Node XER next[1] absent",   dec.next && !dec.next->next);
    }

    // --- Tree: single node ---
    printf("Tree — single\n");
    {
        Tree enc{};
        enc.value = Integer{5};

        auto bytes = ber_enc(Tree::asn_DEF, &enc);
        check("Tree single BER encode non-empty", !bytes.empty());

        Tree dec{};
        check("Tree single BER decode ok",        ber_dec(bytes, Tree::asn_DEF, &dec));
        check("Tree single value",                (int64_t)dec.value == 5);
        check("Tree single left absent",          !dec.left);
        check("Tree single right absent",         !dec.right);
    }

    // --- Tree: depth 2 (root + left + right) ---
    printf("Tree — depth 2\n");
    {
        Tree enc{};
        enc.value = Integer{1};
        enc.left  = std::make_unique<Tree>();
        enc.left->value = Integer{2};
        enc.right = std::make_unique<Tree>();
        enc.right->value = Integer{3};

        auto bytes = ber_enc(Tree::asn_DEF, &enc);
        check("Tree depth-2 BER encode non-empty", !bytes.empty());

        Tree dec{};
        check("Tree depth-2 BER decode ok",  ber_dec(bytes, Tree::asn_DEF, &dec));
        check("Tree root value",             (int64_t)dec.value == 1);
        check("Tree left present",           !!dec.left);
        check("Tree left value",             dec.left  && (int64_t)dec.left->value  == 2);
        check("Tree right present",          !!dec.right);
        check("Tree right value",            dec.right && (int64_t)dec.right->value == 3);
        check("Tree left children absent",   dec.left  && !dec.left->left  && !dec.left->right);
        check("Tree right children absent",  dec.right && !dec.right->left && !dec.right->right);

        auto bytes2 = ber_enc(Tree::asn_DEF, &dec);
        check("Tree depth-2 BER idempotent", bytes == bytes2);
    }

    // --- Mutual recursion: Even ↔ Odd ---
    printf("Even/Odd — mutual recursion depth 2\n");
    {
        Even enc{};
        enc.n   = Integer{0};
        enc.odd = std::make_unique<Odd>();
        enc.odd->n    = Integer{1};
        enc.odd->even = std::make_unique<Even>();
        enc.odd->even->n = Integer{2};

        auto bytes = ber_enc(Even::asn_DEF, &enc);
        check("Even BER encode non-empty",   !bytes.empty());

        Even dec{};
        check("Even BER decode ok",          ber_dec(bytes, Even::asn_DEF, &dec));
        check("Even n",                      (int64_t)dec.n == 0);
        check("Even odd present",            !!dec.odd);
        check("Even odd.n",                  dec.odd && (int64_t)dec.odd->n == 1);
        check("Even odd.even present",       dec.odd && !!dec.odd->even);
        check("Even odd.even.n",             dec.odd && dec.odd->even &&
                                             (int64_t)dec.odd->even->n == 2);
        check("Even odd.even.odd absent",    dec.odd && dec.odd->even &&
                                             !dec.odd->even->odd);

        auto bytes2 = ber_enc(Even::asn_DEF, &dec);
        check("Even BER idempotent",         bytes == bytes2);
    }

    printf("\n%s  %d failure(s)\n", failures ? "\033[31mFAIL\033[0m" : "\033[32mPASS\033[0m", failures);
    return failures ? 1 : 0;
}
