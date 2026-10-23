// Rust leg of the contained-values test (containing_test.asn1 +
// containing_test.container.json); mirrors tests/seq/test_containing.cpp.
// OCTET STRING fields holding the encoding of another type, from a contents
// constraint (X.682 §11) or the sidecar.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::containing::{
    decode_value, ContainedDecoders, ContainedOptions, ContainedResult, ContainedStatus, Containing, Outer,
};
use asn1cpp_wire::integer::Integer;
use asn1cpp_wire::{ber, per};
use Envelope::Envelope as Env;
use Holder::Holder as Hold;
use Inner::Inner as In;
use Kind::Kind as K;
use Pick::Pick as P;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn inner(id: i64) -> In {
    In { id: Integer(id), name: None }
}

fn holder(kind: K) -> Hold {
    let mut h = Hold { kind, ..Default::default() };
    h.viaConstraint.set_value(inner(1));
    h.viaAlias.set_value(inner(2));
    // viaConfig is configured `decoder: zero_padding`: the encoding of an
    // Inner followed by block padding.
    let mut bytes = ber::object::encode_pdu(&inner(3)).unwrap();
    bytes.extend_from_slice(&[0; 5]);
    h.viaConfig.set_raw(bytes);
    h.raw = asn1cpp_wire::octet_string::OctetString(vec![0xDE, 0xAD]);
    h.viaSized.set_value(inner(5));
    h
}

fn pb_bytes(p: &P) -> Vec<u8> {
    match p {
        P::inner(c) => c.bytes().to_vec(),
        _ => Vec::new(),
    }
}

fn id_of(c: &Containing<In>) -> Option<i64> {
    c.value().map(|v| v.id.0)
}

fn main() {
    let mut f = 0;

    println!("BER SEQUENCE");
    let wire = ber::object::encode_pdu(&holder(K::plain)).unwrap();
    let d: Hold = ber::object::decode_pdu(&wire).unwrap();
    check("CONTAINING member decoded", d.viaConstraint.status() == ContainedStatus::Decoded && id_of(&d.viaConstraint) == Some(1), &mut f);
    check("CONTAINING through an alias decoded", id_of(&d.viaAlias) == Some(2), &mut f);
    check("sidecar member decoded past its zero padding", id_of(&d.viaConfig) == Some(3) && d.viaConfig.error().is_empty(), &mut f);
    check("not dirty after decode", !d.viaConstraint.dirty() && !d.viaConfig.dirty(), &mut f);
    check("re-encodes byte-exact (padding kept)", ber::object::encode_pdu(&d).unwrap() == wire, &mut f);
    let s: Hold = ber::object::decode_pdu(&ber::object::encode_pdu(&holder(K::scrambled)).unwrap()).unwrap();
    check("when mismatch skips the field", s.viaConfig.status() == ContainedStatus::Skipped && !s.viaConfig.has_value(), &mut f);
    check("other fields still decoded", s.viaConstraint.status() == ContainedStatus::Decoded, &mut f);
    let mut m = d.clone();
    m.viaConstraint.value_mut().unwrap().id = Integer(77);
    let r: Hold = ber::object::decode_pdu(&ber::object::encode_pdu(&m).unwrap()).unwrap();
    check("modified value round-trips", id_of(&r.viaConstraint) == Some(77), &mut f);
    check("clone keeps inner values", id_of(&d.clone().viaConfig) == Some(3), &mut f);

    println!("BER inner failures");
    let mut h = holder(K::plain);
    h.viaConstraint.set_raw(vec![0x30, 0x05, 0x02]);
    h.viaConfig.set_raw(vec![0x30, 0x03, 0x80, 0x01, 0x03, 0x00, 0x09]);
    let wire = ber::object::encode_pdu(&h).unwrap();
    let d: Hold = ber::object::decode_pdu(&wire).unwrap();
    check("bad inner value is Failed, raw bytes kept",
          d.viaConstraint.status() == ContainedStatus::Failed && !d.viaConstraint.has_value()
              && d.viaConstraint.bytes().len() == 3 && !d.viaConstraint.error().is_empty(), &mut f);
    check("non-zero padding keeps the value with a warning",
          id_of(&d.viaConfig) == Some(3) && !d.viaConfig.error().is_empty(), &mut f);
    check("failed value re-encodes its raw bytes", ber::object::encode_pdu(&d).unwrap() == wire, &mut f);

    println!("Decode options");
    let wire = ber::object::encode_pdu(&holder(K::plain)).unwrap();
    let off = ContainedOptions { off: true, ..Default::default() };
    let d: Hold = ber::object::decode_pdu_with(&wire, &off).unwrap();
    check("off: nothing decoded", d.viaConstraint.status() == ContainedStatus::Skipped && d.viaConfig.status() == ContainedStatus::Skipped, &mut f);
    let mut reg = ContainedDecoders::default();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<i64>::new()));
    let seen2 = seen.clone();
    reg.add(
        "zero_padding",
        Box::new(move |a| {
            if let Outer::Seq(o) = a.outer {
                if let asn1cpp_wire::spec::object::MemberRef::Enumerated(slot, _) = o.get_member(0) {
                    seen2.lock().unwrap().push(slot.enum_get());
                }
            }
            let mut used = 0;
            let r = decode_value(a, Some(&mut used));
            if r.status == ContainedStatus::Decoded { ContainedResult::ok() } else { r }
        }),
        None,
    );
    let opts = ContainedOptions { decoders: Some(reg), ..Default::default() };
    let h: Hold = ber::object::decode_pdu_with(&wire, &opts).unwrap();
    check("hook called once with the enclosing value", *seen.lock().unwrap() == vec![K::plain as i64], &mut f);
    check("hook result stored", id_of(&h.viaConfig) == Some(3), &mut f);
    check("built-ins still used for the other fields", h.viaConstraint.status() == ContainedStatus::Decoded, &mut f);

    println!("BER CHOICE");
    let mut c: Containing<In> = Containing::default();
    c.set_value(inner(9));
    let wire = ber::object::encode_pdu(&P::inner(c)).unwrap();
    let d: P = ber::object::decode_pdu(&wire).unwrap();
    check("contained alternative decoded", matches!(&d, P::inner(c) if id_of(c) == Some(9)), &mut f);

    println!("XER/JER (same text as the C++ runtime)");
    let pb: P = ber::object::decode_pdu(&[0x80, 0x08, 0x30, 0x06, 0x80, 0x01, 0x09, 0x81, 0x01, 0x78]).unwrap();
    let x = asn1cpp_wire::xer::object::encode_pdu(&pb).unwrap();
    check("configured XER inline", x == "<Pick>\n    <inner>\n        <Inner>\n            <id>9</id>\n            <name>x</name>\n        </Inner>\n    </inner>\n</Pick>\n", &mut f);
    let j = asn1cpp_wire::jer::object::encode_pdu(&pb).unwrap();
    check("configured JER inline_raw", j == r#"{"inner":{"containing":{"id":9,"name":"x"},"raw":"3006800109810178"}}"#, &mut f);
    let xd: P = asn1cpp_wire::xer::object::decode_pdu(&x).unwrap();
    check("XER inline decodes", matches!(&xd, P::inner(c) if id_of(c) == Some(9) && c.bytes() == pb_bytes(&pb)), &mut f);
    let jd: P = asn1cpp_wire::jer::object::decode_pdu(&j.replace("3006800109810178", "300680010981017800")).unwrap();
    check("JER inline_raw: raw bytes kept as given", matches!(&jd, P::inner(c) if id_of(c) == Some(9) && c.bytes().len() == 9), &mut f);
    let hb: Hold = ber::object::decode_pdu(&ber::object::encode_pdu(&holder(K::plain)).unwrap()).unwrap();
    let hx = asn1cpp_wire::xer::object::encode_pdu(&hb).unwrap();
    let hxd: Hold = asn1cpp_wire::xer::object::decode_pdu(&hx).unwrap();
    check("XER hex decodes the inner values", id_of(&hxd.viaConstraint) == Some(1) && id_of(&hxd.viaConfig) == Some(3), &mut f);
    let hjd: Hold = asn1cpp_wire::jer::object::decode_pdu(&asn1cpp_wire::jer::object::encode_pdu(&hb).unwrap()).unwrap();
    check("JER hex decodes the inner values", id_of(&hjd.viaAlias) == Some(2), &mut f);

    println!("Recursive contained type");
    let mut e2 = Env { depth: Integer(2), nested: None };
    e2.depth = Integer(2);
    let mut c1 = Containing::default();
    c1.set_value(e2);
    let e1 = Env { depth: Integer(1), nested: Some(c1) };
    let mut c0 = Containing::default();
    c0.set_value(e1);
    let e = Env { depth: Integer(0), nested: Some(c0) };
    let d: Env = ber::object::decode_pdu(&ber::object::encode_pdu(&e).unwrap()).unwrap();
    let l1 = d.nested.as_ref().and_then(|c| c.value());
    let l2 = l1.and_then(|v| v.nested.as_ref()).and_then(|c| c.value());
    check("two levels decoded", l1.map(|v| v.depth.0) == Some(1) && l2.map(|v| v.depth.0) == Some(2), &mut f);
    let mut bytes = ber::object::encode_pdu(&Env::default()).unwrap();
    for _ in 0..400 {
        let mut c = Containing::default();
        c.set_raw(bytes);
        bytes = ber::object::encode_pdu(&Env { depth: Integer(0), nested: Some(c) }).unwrap();
    }
    let deep: Env = ber::object::decode_pdu(&bytes).unwrap();
    let mut levels = 0;
    let mut cur = &deep;
    while let Some(next) = cur.nested.as_ref().and_then(|c| c.value()) {
        cur = next;
        levels += 1;
    }
    check("deep chain: stops at the nesting limit",
          levels < 400 && cur.nested.as_ref().map(|c| c.status()) == Some(ContainedStatus::Failed), &mut f);

    println!("PER");
    let wire = per::object::encode_pdu(&holder(K::plain)).unwrap();
    let d: Hold = per::object::decode_pdu(&wire).unwrap();
    check("CONTAINING member decoded as PER", id_of(&d.viaConstraint) == Some(1), &mut f);
    check("sidecar member decoded as BER", id_of(&d.viaConfig) == Some(3), &mut f);
    check("sized alias member decoded", id_of(&d.viaSized) == Some(5), &mut f);
    check("re-encodes byte-exact", per::object::encode_pdu(&d).unwrap() == wire, &mut f);

    // Contents without ENCODED BY follow the outer encoding (X.682 §11.4):
    // bytes known to be in other rules are re-derived when written as PER.
    println!("Outer-encoding contents across transfer syntaxes");
    let ber_wire = ber::object::encode_pdu(&holder(K::plain)).unwrap();
    let b: Hold = ber::object::decode_pdu(&ber_wire).unwrap();
    let bp: Hold = per::object::decode_pdu(&per::object::encode_pdu(&b).unwrap()).unwrap();
    check("BER-decoded value written as PER decodes",
          bp.viaConstraint.status() == ContainedStatus::Decoded && id_of(&bp.viaConstraint) == Some(1)
              && bp.viaAlias.status() == ContainedStatus::Decoded, &mut f);
    check("BER-decoded value re-encodes as BER byte-exact", ber::object::encode_pdu(&b).unwrap() == ber_wire, &mut f);
    let mut pc = Containing::default();
    pc.set_value(inner(4));
    let px: P = asn1cpp_wire::xer::object::decode_pdu(&asn1cpp_wire::xer::object::encode_pdu(&P::inner(pc)).unwrap()).unwrap();
    let pp: P = per::object::decode_pdu(&per::object::encode_pdu(&px).unwrap()).unwrap();
    check("inline XER value written as PER decodes",
          matches!(&pp, P::inner(c) if c.status() == ContainedStatus::Decoded && id_of(c) == Some(4)), &mut f);

    if f > 0 {
        println!("FAILED");
        std::process::exit(1);
    }
    println!("all passed");
}
