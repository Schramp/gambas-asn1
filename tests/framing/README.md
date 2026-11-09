# BER framing vectors

Shared test input for the BER framers of the C++, Rust and Java runtimes
(book.md, "Reading Records from Files and Streams"). Each runtime reads every
file listed in `framing.vectors` and must report exactly the frames and the
result given there.

- `*.ber`: the input files, records back to back.
- `framing.vectors`: one tab-separated line per file:

  ```
  file  max_frame  frames  result
  ```

  - `max_frame`: `-` for the default limit (64 MiB), or a number of octets.
  - `frames`: `-`, or a comma list of `offset+length`, in input order.
  - `result`: `end` when the input ends cleanly after the last frame, or
    `error REASON OFFSET`. `REASON` is the reason key the error message
    starts with (`truncated`, `tag-too-long`, `length-field-too-long`,
    `indefinite-primitive`, `frame-too-large`, `too-deep`), and `OFFSET`
    is the absolute octet offset of the error.
- `records/*.der`: the definite-length records, encoded by asn1c from
  `framing.asn1`.
- `make_framing_vectors.py`: builds the `*.ber` files and `framing.vectors`.
  `--records` re-encodes `records/*.der` first, which needs asn1c on `PATH`.

The valid records are asn1c's: `records/*.der`, and the records of asn1c's
own test suite in `../tests-c-compiler/data-62`, only the ones asn1c
decodes (indefinite length, nested indefinite length, a high tag number).
Malformed input is built by the generator from those records. asn1c cannot
produce a framing fault. The expected results follow from how each file is
put together, not from parsing it.

Regenerate after changing the generator, and commit the result:

```bash
python3 tests/framing/make_framing_vectors.py
```
