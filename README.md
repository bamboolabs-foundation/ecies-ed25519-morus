# ecies-ed25519-morus

Experimental [ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) on [Twisted Edwards Curve25519](https://en.wikipedia.org/wiki/Curve25519) and [MORUS-1280-128](https://competitions.cr.yp.to/round3/morusv2.pdf)

## Notes

- [Flexible Symmetric Cryptography - Impractical plaintext recovery attack](https://eprint.iacr.org/2018/464.pdf).
- This work misuses the `sign & verify` keypair in the `ed25519` scheme for accomplishing `ECIES`. We call this, a perversion because we should only use the `ephemeral ones` (except for the recipient).
- No security audits, and perhaps will not happen.

## Example

```rust
use rand_core::RngCore;
use ecies_ed25519_morus::{encrypt_into, decrypt_into};

const BUFFER_SIZE: usize = 512 * 1024; // avoid higher than this to prevent stackoverflow
let mut rng = rand_core::OsRng::default();
let sender_keypair = ed25519_dalek::SigningKey::generate(&mut rng);
let receiver_keypair = ed25519_dalek::SigningKey::generate(&mut rng);
let sender_public = sender_keypair.verifying_key();
let receiver_public = receiver_keypair.verifying_key();
let mut random_message = [0u8; BUFFER_SIZE];
let mut decrypted_message = [0u8; BUFFER_SIZE];
let mut ciphertext = [0u8; BUFFER_SIZE];
rng.fill_bytes(&mut random_message);

let decrypt_materials = encrypt_into(
    &sender_keypair,
    &receiver_public,
    &mut rng,
    &random_message[..],
    &mut ciphertext[..],
)
.unwrap();
decrypt_into(
    &receiver_keypair,
    &sender_public,
    &decrypt_materials,
    &ciphertext[..],
    &mut decrypted_message[..],
)
.unwrap();

assert_eq!(random_message, decrypted_message);
assert_ne!(sender_public, receiver_public);
```

## Features

- `no-std` environment (for example: [wasm](https://en.wikipedia.org/wiki/WebAssembly)):

```bash
cargo add ecies-ed25519-morus --no-default-features --features="pure"
```

- `std` environment (default):

```bash
cargo add ecies-ed25519-morus
```

- `std` and `aarch64` environment (for example: [Apple Silicon](https://en.wikipedia.org/wiki/Apple_silicon))

```bash
cargo add ecies-ed25519-morus --features="aarch64-optimizations"
```

## Inspirations

This work is heavily inspired by:

- [ecies-ed25519](https://github.com/phayes/ecies-ed25519), which uses [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) and ephemeral keypairs (see: [notes](#notes))
- [rust-morus](https://github.com/jedisct1/rust-morus), modified for pure `no-std` (see: [these lines](https://github.com/Ujang360/ecies-ed25519-morus/blob/f5de81f344858df5d3864dc294cdaad7d8c2c0a7/src/morus.rs#L1-L7))

## Future Works

- [ ] Encrypt & Decrypt with associated data
- [ ] Improve tests with fuzzers & harnesses
- [ ] Add benchmark information
- [ ] Add example and diagrams to elaborate use cases
- [ ] Implement `python` and `c/c++` wrappers
