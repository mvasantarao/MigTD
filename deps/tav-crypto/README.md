# TEE Attestation Verification Crypto

## MigTD-maintained patch

This is a local copy of TAV `tav-1.0.7`, commit
[`7fb2c2535180b73e56cc25a46a88cf679b5b8239`](https://github.com/microsoft/TEE-Attestation-Verification/tree/7fb2c2535180b73e56cc25a46a88cf679b5b8239/crypto),
under its original [MIT license](LICENSE). It is not an upstream release or
an upstream endorsement of these modifications.

The legacy feature name `crypto_pure_rust` is retained for TAV compatibility,
but its RSA verification now uses the workspace's patched ring, including
native code/assembly. ECDSA, X.509 parsing, signature-parameter checks and
certificate-path policy remain upstream RustCrypto/TAV implementations.
The affected `rsa` package and its SHA-2 compatibility dependency are removed,
not renamed or hidden by an advisory exception. This crate exposes no new
RSA private-key operation.

Subsequent workspace lint maintenance removes a redundant ECDSA signature
borrow and rewrites critical-extension iterators in `x509_certificate.rs`
and the `x509_policy.rs` test backend. These mechanical changes preserve
verification decisions, critical-extension ordering and certificate-path
policy; those files are no longer byte-identical upstream copies.

PKCS#1 v1.5 and PSS support SHA-256/384/512. SPKI requires `rsaEncryption`
with NULL parameters, an octet-aligned BIT STRING, strict PKCS#1 DER, an odd
2048-4096-bit modulus and an odd exponent in `3..2^33`. The former 4096-bit
upper limit is retained; the 2048-bit minimum intentionally rejects weaker
keys unsupported by the selected ring verification algorithms. Existing
AMD Milan/Genoa certificate chains use supported keys and are tested.
PSS requires the same MGF1 hash as the message hash and digest-length salt.
Malformed input fails explicitly; no permissive or alternate-backend fallback.

The default is narrowed to the explicitly selected legacy feature, so adding
this package to the workspace does not implicitly enable OpenSSL. PAL and
emulator dependencies still disable defaults. Native Linux is tested;
WASM/Windows use of the modified fallback is not qualified.

The workspace Git-source patch selects this crate for the pinned TAV library.
`cargo xtask lib-test` includes its upstream and added regression tests:

```bash
cargo test --locked -p tee-attestation-verification-crypto \
  --no-default-features --features crypto_pure_rust
```

Future upstream refreshes must retain the license/provenance, reapply or retire
the patch, check ring's supported key/parameter limits, rerun RSA negative
vectors and AMD-chain tests, and verify that no affected `rsa` package returns.
The existing PKCS#1 `0.8.0-rc.4` parser compatibility pin remains required.
The added PSS fixtures use ring's public test key and message
`MigTD TAV ring RSA verification`. Python cryptography independently verifies
them with SHA-256 and either salt length 20, or MGF1-SHA384 with salt length
32; both fail the standard SHA-256/MGF1-SHA256/salt32 check.

## Upstream overview

Rather than implementing any cryptographic primitives, this crate dispatches these to one of several backends.
It narrowly exposes a unified surface for signature verification and certificate chain verification across native and WebCrypto backends.
There is a RustCrypto/ring fallback for workloads without WebCrypto or OpenSSL.

## Backends

At least one target-compatible backend feature must be enabled. If multiple
backend features are enabled, `build.rs` selects the target-preferred backend.

| Feature | Platforms | sync | async | Notes |
|---|---|---:|---:|---|
| `crypto_openssl` | Native | yes | yes | Uses OpenSSL for native certificate-chain verification and primitive verification. |
| `crypto_webcrypto` | WASM | no | yes | Uses `globalThis.crypto.subtle` for primitive verification and the shared X.509 path validator. |
| `crypto_pure_rust` | Native; WASM unqualified | yes | yes | RustCrypto ECDSA/X.509, ring RSA, shared X.509 path validator. |
| `crypto_windows` | Windows | yes | yes | Uses Windows CNG for primitive verification and Crypt32 for certificate-chain verification. |

Windows targets prefer `crypto_windows` whenever it is enabled, including when
`crypto_openssl` is also enabled. Other native targets prefer `crypto_openssl`
when enabled, then `crypto_pure_rust`.
WASM targets prefer `crypto_webcrypto` when enabled, then `crypto_pure_rust`.
Use `--no-default-features --features crypto_windows` to select only the
Windows backend.

## Scope

This crate is intentionally limited to just what is required to verify SNP attestations, and in the future UVM endorsements.
This narrow scope ensures we don't need to implement generic cryptographic primitives.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.