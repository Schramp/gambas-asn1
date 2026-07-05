// TypedVisitor / TypedMutator unit test.
//
// Schema (typed_visitor_test.asn1):
//   Coord     ::= SEQUENCE { lat INTEGER, lon INTEGER }
//   Payload   ::= CHOICE   { raw OCTET STRING, loc Coord }
//   Item      ::= SEQUENCE { id INTEGER, where Coord, payload Payload }
//   ItemList  ::= SEQUENCE OF Item
//   Container ::= SEQUENCE { home Coord, items ItemList }
//
// Exercises: Coord appearing as a plain member (home / where), a CHOICE
// alternative (payload.loc), and inside a SEQUENCE OF element — all reached in
// one pass; multi-type registration; SkipChildren; Stop; and mutation.

#include <cstdio>
#include <string>
#include <vector>

#include <asn1cpp/codec/TypedVisitor.hpp>

#include "Coord.hpp"
#include "Payload.hpp"
#include "Item.hpp"
#include "ItemList.hpp"
#include "Container.hpp"

using namespace asn1;

static int failures = 0;
static void check(const char* name, bool cond, const std::string& detail = "") {
    if (cond) {
        printf("  \033[32mPASS\033[0m  %s\n", name);
    } else {
        printf("  \033[31mFAIL\033[0m  %s%s%s\n", name,
               detail.empty() ? "" : " — ", detail.c_str());
        ++failures;
    }
}

// Build:
//   home = (1,2)
//   items[0] = { id 10, where (3,4), payload loc (5,6) }
//   items[1] = { id 11, where (7,8), payload raw {DE AD} }
// Coord nodes in document order: home, items[0].where, items[0].payload.loc,
//                                items[1].where   → 4 total.
// Item nodes: items[0], items[1] → 2 total.
static Container make_container() {
    Container c;
    c.home.lat = 1; c.home.lon = 2;

    Item i0;
    i0.id = 10;
    i0.where.lat = 3; i0.where.lon = 4;
    i0.payload.set_present(Payload::PR::loc);
    i0.payload.loc().lat = 5; i0.payload.loc().lon = 6;
    c.items.push_back(std::move(i0));

    Item i1;
    i1.id = 11;
    i1.where.lat = 7; i1.where.lon = 8;
    i1.payload.set_present(Payload::PR::raw);
    static const uint8_t rb[] = {0xDE, 0xAD};
    i1.payload.raw() = OctetString{std::span<const uint8_t>{rb, 2}};
    c.items.push_back(std::move(i1));

    return c;
}

int main() {
    printf("TypedVisitor tests\n");

    // 1. All Coord nodes reached, in document order.
    {
        Container c = make_container();
        std::vector<std::pair<int64_t, int64_t>> seen;
        TypedVisitor v;
        v.on<Coord>([&](const Coord& co) {
            seen.emplace_back((int64_t)co.lat.value(), (int64_t)co.lon.value());
            return VisitControl::Continue;
        });
        v.visit(c);
        std::vector<std::pair<int64_t, int64_t>> expect = {{1,2},{3,4},{5,6},{7,8}};
        check("visits every Coord (member, CHOICE alt, SEQUENCE OF) in order",
              seen == expect, "got " + std::to_string(seen.size()) + " coords");
    }

    // 2. Two types registered, one pass, correct counts.
    {
        Container c = make_container();
        int coords = 0, items = 0;
        TypedVisitor v;
        v.on<Coord>([&](const Coord&) { ++coords; return VisitControl::Continue; });
        v.on<Item>([&](const Item&)   { ++items;  return VisitControl::Continue; });
        v.visit(c);
        check("multi-type single pass: 4 Coord + 2 Item",
              coords == 4 && items == 2,
              "coords=" + std::to_string(coords) + " items=" + std::to_string(items));
    }

    // 3. SkipChildren on Item prunes the Coords beneath each Item.
    {
        Container c = make_container();
        int coords = 0, items = 0;
        TypedVisitor v;
        v.on<Coord>([&](const Coord&) { ++coords; return VisitControl::Continue; });
        v.on<Item>([&](const Item&)   { ++items;  return VisitControl::SkipChildren; });
        v.visit(c);
        // home Coord still visited; both Items fire but their subtrees are pruned.
        check("SkipChildren prunes subtree (only home Coord remains)",
              coords == 1 && items == 2,
              "coords=" + std::to_string(coords) + " items=" + std::to_string(items));
    }

    // 4. Stop aborts the whole traversal at the first Coord (home).
    {
        Container c = make_container();
        int coords = 0;
        TypedVisitor v;
        v.on<Coord>([&](const Coord&) { ++coords; return VisitControl::Stop; });
        v.visit(c);
        check("Stop aborts after first match", coords == 1,
              "coords=" + std::to_string(coords));
    }

    // 5. TypedMutator modifies every Coord in place.
    {
        Container c = make_container();
        TypedMutator m;
        m.on<Coord>([&](Coord& co) { co.lat = 99; return VisitControl::Continue; });
        m.visit(c);
        bool all99 = c.home.lat == 99
                  && c.items[0].where.lat == 99
                  && c.items[0].payload.loc().lat == 99
                  && c.items[1].where.lat == 99;
        // lon untouched
        bool lon_ok = c.home.lon == 2 && c.items[1].where.lon == 8;
        check("TypedMutator writes every Coord.lat in place", all99 && lon_ok);
    }

    // 6. Registering the root type fires for the root object itself.
    {
        Container c = make_container();
        int roots = 0;
        TypedVisitor v;
        v.on<Container>([&](const Container&) { ++roots; return VisitControl::Continue; });
        v.visit(c);
        check("root type callback fires once", roots == 1,
              "roots=" + std::to_string(roots));
    }

    printf(failures ? "\n%d failure(s)\n" : "\nAll tests passed\n", failures);
    return failures ? 1 : 0;
}
