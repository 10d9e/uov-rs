# uov

Rust implementation of **UOV (Unbalanced Oil and Vinegar)** signatures with a small, byte-oriented SDK.

This crate exposes:

- **A simple SDK**: generate keys, sign messages, verify signatures (`KeyPair`, `SigningKey`, `VerifyingKey`, `Signature`).
- **Multiple parameter sets** (Level I / III / V style variants) and **key-compression variants**.
- **Known-answer tests (KATs)** and **Criterion benchmarks**.

## Status / security notes

- This repository is an **experimental/reference implementation**. It has not been audited.

## Install

Add to your `Cargo.toml`:

```toml
[dependencies]
uov-rs = "0.1.1"
```

Or, if/when published to crates.io, replace the path dependency with a version.

## Quickstart

Generate a keypair, sign, verify:

```rust
use uov_rs::{KeyPair, Scheme};

fn main() {
    let kp = KeyPair::generate(Scheme::IpPkcSkc);
    let msg = b"hello world";

    let sig = kp.signing_key.sign(msg);
    assert!(kp.verifying_key.verify(msg, &sig));
}
```

Round-trip keys/signatures as bytes:

```rust
use uov_rs::{KeyPair, Scheme, SigningKey, Signature, VerifyingKey};

fn main() {
    let scheme = Scheme::IpPkcSkc;
    let kp = KeyPair::generate(scheme);

    // Serialize/deserialize keys
    let sk_bytes = kp.signing_key.as_bytes().to_vec();
    let pk_bytes = kp.verifying_key.as_bytes().to_vec();

    let sk = SigningKey::from_bytes(scheme, &sk_bytes);
    let vk = VerifyingKey::from_bytes(scheme, &pk_bytes);

    // Serialize/deserialize signature
    let msg = b"roundtrip";
    let sig = sk.sign(msg);
    let sig2 = Signature::from_bytes(sig.as_bytes());

    assert!(vk.verify(msg, &sig2));
}
```

## Schemes (parameter sets)

Select a scheme via `Scheme`:

- **Level I (GF(256))**: `Scheme::Ip`, `Scheme::IpPkc`, `Scheme::IpPkcSkc`
- **Level I (GF(16))**: `Scheme::Is`, `Scheme::IsPkc`, `Scheme::IsPkcSkc`
- **Level III (GF(256))**: `Scheme::III`, `Scheme::IIIPkc`, `Scheme::IIIPkcSkc`
- **Level V (GF(256))**: `Scheme::V`, `Scheme::VPkc`, `Scheme::VPkcSkc`

Where the suffixes mean:

- **(no suffix)**: classic (uncompressed) keys
- **`Pkc`**: compressed public key
- **`PkcSkc`**: compressed public + secret key

If you want to iterate through all variants, see `uov_rs::uov_all()` (lower-level API; used by the KAT tests).

## Sizes (keys and signatures)

All sizes below are **bytes** as produced/consumed by `as_bytes()` / `from_bytes()` and `Signature::as_bytes()`.

| Scheme | Public key (pk) | Secret key (sk) | Signature (sig) |
| --- | ---:| ---:| ---:|
| `Ip` | 278,432 | 237,896 | 128 |
| `IpPkc` | 43,576 | 237,896 | 128 |
| `IpPkcSkc` | 43,576 | 32 | 128 |
| `Is` | 412,160 | 348,704 | 96 |
| `IsPkc` | 66,576 | 348,704 | 96 |
| `IsPkcSkc` | 66,576 | 32 | 96 |
| `III` | 1,225,440 | 1,044,320 | 200 |
| `IIIPkc` | 189,232 | 1,044,320 | 200 |
| `IIIPkcSkc` | 189,232 | 32 | 200 |
| `V` | 2,869,440 | 2,436,704 | 260 |
| `VPkc` | 446,992 | 2,436,704 | 260 |
| `VPkcSkc` | 446,992 | 32 | 260 |

Notes:

- **`Pkc`** drastically reduces public-key size by storing a seed plus the \(P_3\) part of the public map.
- **`PkcSkc`** stores only a **32-byte** secret seed and expands the full secret key on demand.

## Public API overview

The primary types are defined in `src/lib.rs`:

- `Scheme`: selects a parameter set
- `KeyPair::generate(scheme) -> KeyPair`: generates a signing/verifying key
- `SigningKey`:
  - `sign(msg) -> Signature`
  - `as_bytes() -> &[u8]`
  - `from_bytes(scheme, bytes) -> SigningKey` (validates expected length)
- `VerifyingKey`:
  - `verify(msg, sig) -> bool`
  - `as_bytes() -> &[u8]`
  - `from_bytes(scheme, bytes) -> VerifyingKey` (validates expected length)
- `Signature`:
  - `as_bytes() -> &[u8]`
  - `from_bytes(bytes) -> Signature`

## Build, test, bench

Build:

```bash
cargo build
```

Run tests (includes the SDK tests and KAT checks):

```bash
cargo test
```

Run benchmarks (Criterion):

```bash
cargo bench
```

The benchmark harness is `benches/uov_bench.rs` and produces Criterion output (including HTML reports via the `html_reports` feature).

## Repository layout

- `src/lib.rs`: implementation + public SDK
- `tests/sdk_test.rs`: SDK usage tests (sign/verify, byte roundtrips, all schemes)
- `tests/kat_test.rs`: deterministic KAT generation/verification
- `benches/uov_bench.rs`: Criterion benchmarks

## Development notes

- Dependencies include `aes`, `ctr`, `sha3` (SHAKE256), and `cipher`.
- KAT tests also use `sha2` and `hex`.

## License

Licensed under either of:

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

