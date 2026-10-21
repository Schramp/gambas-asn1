// Fixed-seed fuzz smoke run for the Rust decoders (BER/PER/XER/JER) —
// the Rust counterpart of tests/seq/test_fuzz_ber.cpp, on
// roundtrip_test.asn1's Container (every primitive kind, SEQUENCE OF,
// OPTIONAL). A valid Container is encoded in every codec, then each
// encoding is mutated (bit flip, byte overwrite, truncation, insertion,
// deletion) and decoded. A decode error is the expected outcome; any panic
// fails the run. The full sweep across every schema is
// `xval_sweep.py --fuzz`.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::{ber, jer, per, xer};
use Container::Container as ContainerT;

const SEED: u64 = 0x5EED_0769;
const MUTATIONS: usize = 4000;

const SEED_XER: &str = "<Container>\
<prims><b><false/></b><i>451</i><ui>183434</ui><r>1.5</r><n></n><os>7227190E75</os>\
<bs>0101010110011001</bs><oid>1.3.6.1.97</oid><utc>240101120000Z</utc><gen>20240101120000Z</gen>\
<utf8>caf\u{e9}</utf8><ia5>K(jZ2DP</ia5><vis>XL$qY</vis><num>2783 1</num><en><beta/></en></prims>\
<items>\
<Item><key>SU1</key><value>63542</value></Item>\
<Item><key>iJyEuxXew</key><value>2964</value></Item>\
</items>\
<opt><b><true/></b><i>-415</i><ui>183434</ui><r>1.5</r><n></n><os>105E4F</os>\
<bs>0101010110011001</bs><oid>1.3.6.1.97</oid><utc>240101120000Z</utc><gen>20240101120000Z</gen>\
<utf8>caf\u{e9}</utf8><ia5>K(jZ2DP</ia5><vis>XL$qY</vis><num>2783 1</num><en><gamma/></en></opt>\
</Container>";

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn mutate(data: &[u8], rng: &mut XorShift) -> Vec<u8> {
    let mut b = data.to_vec();
    if b.is_empty() {
        return vec![rng.next() as u8];
    }
    let i = rng.below(b.len());
    match rng.below(5) {
        0 => b[i] ^= 1 << rng.below(8),
        1 => b[i] = [0x00, 0xFF, 0x7F, 0x80, rng.next() as u8][rng.below(5)],
        2 => b.truncate(i),
        3 => {
            let n = 1 + rng.below(8);
            let ins: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            b.splice(i..i, ins);
        }
        _ => {
            let end = (i + 1 + rng.below(8)).min(b.len());
            b.drain(i..end);
        }
    }
    b
}

fn main() {
    let seed: ContainerT = xer::object::decode_pdu(SEED_XER).expect("seed Container decodes from XER");
    let seeds: [(&str, Vec<u8>, fn(&[u8]) -> bool); 4] = [
        ("BER", ber::object::encode_pdu(&seed).unwrap(), |d| ber::object::decode_pdu::<ContainerT>(d).is_ok()),
        ("PER", per::object::encode_pdu(&seed).unwrap(), |d| per::object::decode_pdu::<ContainerT>(d).is_ok()),
        ("XER", xer::object::encode_pdu(&seed).unwrap().into_bytes(), |d| {
            xer::object::decode_pdu::<ContainerT>(&String::from_utf8_lossy(d)).is_ok()
        }),
        ("JER", jer::object::encode_pdu(&seed).unwrap().into_bytes(), |d| {
            jer::object::decode_pdu::<ContainerT>(&String::from_utf8_lossy(d)).is_ok()
        }),
    ];
    let mut failures = 0;
    for (codec, valid, decode) in &seeds {
        if !decode(valid) {
            println!("  \x1b[31mFAIL\x1b[0m  {codec}: seed encoding does not decode");
            failures += 1;
            continue;
        }
        let mut rng = XorShift(SEED);
        let mut rejected = 0;
        for _ in 0..MUTATIONS {
            if !decode(&mutate(valid, &mut rng)) {
                rejected += 1;
            }
        }
        println!("  \x1b[32mPASS\x1b[0m  {codec}: {MUTATIONS} mutated inputs decoded without panicking ({rejected} rejected)");
    }
    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "PASSED" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
