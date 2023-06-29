// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2021 Frank Denis
//
// Origin: https://github.com/jedisct1/rust-morus/blob/342cd3c35fabe9e4f2f04f209fbb1160e647bc48/src/lib.rs
// Modifications:
// - thiserror-no-std impl instead of std::error::Error of lines 20-21
// - readability modifications

use arrayref::{array_mut_ref, array_ref};

/// Morus-1280-128 authentication tag
pub type Tag = [u8; 16]; // 128-bit

/// Morus-1280-128 key
pub type Key = [u8; 16]; // 128-bit

/// Morus-1280-128 nonce
pub type Nonce = [u8; 16]; // 128-bit

#[repr(align(32))]
#[derive(Debug, Clone, Copy)]
struct Lane {
    inner: [u64; 4],
}

impl Lane {
    #[inline]
    fn from_bytes(source: &[u8; 32]) -> Self {
        Lane {
            inner: [
                u64::from_le_bytes(*array_ref![source, 0, 8]),
                u64::from_le_bytes(*array_ref![source, 8, 8]),
                u64::from_le_bytes(*array_ref![source, 16, 8]),
                u64::from_le_bytes(*array_ref![source, 24, 8]),
            ],
        }
    }

    #[inline]
    fn write(&self, destination: &mut [u8; 32]) {
        array_mut_ref![destination, 0, 8].copy_from_slice(&self.inner[0].to_le_bytes());
        array_mut_ref![destination, 8, 8].copy_from_slice(&self.inner[1].to_le_bytes());
        array_mut_ref![destination, 16, 8].copy_from_slice(&self.inner[2].to_le_bytes());
        array_mut_ref![destination, 24, 8].copy_from_slice(&self.inner[3].to_le_bytes());
    }
}

#[repr(align(32))]
#[derive(Debug, Clone, Copy)]
struct State {
    inner: [Lane; 5],
}

impl State {
    fn update(&mut self, input: Lane) {
        let s = &mut self.inner;
        s[0].inner[0] ^= s[3].inner[0];
        s[0].inner[1] ^= s[3].inner[1];
        s[0].inner[2] ^= s[3].inner[2];
        s[0].inner[3] ^= s[3].inner[3];

        let t = s[3].inner[3];
        s[3].inner[3] = s[3].inner[2];
        s[3].inner[2] = s[3].inner[1];
        s[3].inner[1] = s[3].inner[0];
        s[3].inner[0] = t;
        s[0].inner[0] ^= s[1].inner[0] & s[2].inner[0];
        s[0].inner[1] ^= s[1].inner[1] & s[2].inner[1];
        s[0].inner[2] ^= s[1].inner[2] & s[2].inner[2];
        s[0].inner[3] ^= s[1].inner[3] & s[2].inner[3];
        s[0].inner[0] = s[0].inner[0].rotate_left(13);
        s[0].inner[1] = s[0].inner[1].rotate_left(13);
        s[0].inner[2] = s[0].inner[2].rotate_left(13);
        s[0].inner[3] = s[0].inner[3].rotate_left(13);
        s[1].inner[0] ^= input.inner[0];
        s[1].inner[1] ^= input.inner[1];
        s[1].inner[2] ^= input.inner[2];
        s[1].inner[3] ^= input.inner[3];
        s[1].inner[0] ^= s[4].inner[0];
        s[1].inner[1] ^= s[4].inner[1];
        s[1].inner[2] ^= s[4].inner[2];
        s[1].inner[3] ^= s[4].inner[3];
        s[4].inner.swap(3, 1);
        s[4].inner.swap(2, 0);
        s[1].inner[0] ^= s[2].inner[0] & s[3].inner[0];
        s[1].inner[1] ^= s[2].inner[1] & s[3].inner[1];
        s[1].inner[2] ^= s[2].inner[2] & s[3].inner[2];
        s[1].inner[3] ^= s[2].inner[3] & s[3].inner[3];
        s[1].inner[0] = s[1].inner[0].rotate_left(46);
        s[1].inner[1] = s[1].inner[1].rotate_left(46);
        s[1].inner[2] = s[1].inner[2].rotate_left(46);
        s[1].inner[3] = s[1].inner[3].rotate_left(46);
        s[2].inner[0] ^= input.inner[0];
        s[2].inner[1] ^= input.inner[1];
        s[2].inner[2] ^= input.inner[2];
        s[2].inner[3] ^= input.inner[3];
        s[2].inner[0] ^= s[0].inner[0];
        s[2].inner[1] ^= s[0].inner[1];
        s[2].inner[2] ^= s[0].inner[2];
        s[2].inner[3] ^= s[0].inner[3];

        let t = s[0].inner[0];
        s[0].inner[0] = s[0].inner[1];
        s[0].inner[1] = s[0].inner[2];
        s[0].inner[2] = s[0].inner[3];
        s[0].inner[3] = t;
        s[2].inner[0] ^= s[3].inner[0] & s[4].inner[0];
        s[2].inner[1] ^= s[3].inner[1] & s[4].inner[1];
        s[2].inner[2] ^= s[3].inner[2] & s[4].inner[2];
        s[2].inner[3] ^= s[3].inner[3] & s[4].inner[3];
        s[2].inner[0] = s[2].inner[0].rotate_left(38);
        s[2].inner[1] = s[2].inner[1].rotate_left(38);
        s[2].inner[2] = s[2].inner[2].rotate_left(38);
        s[2].inner[3] = s[2].inner[3].rotate_left(38);
        s[3].inner[0] ^= input.inner[0];
        s[3].inner[1] ^= input.inner[1];
        s[3].inner[2] ^= input.inner[2];
        s[3].inner[3] ^= input.inner[3];
        s[3].inner[0] ^= s[1].inner[0];
        s[3].inner[1] ^= s[1].inner[1];
        s[3].inner[2] ^= s[1].inner[2];
        s[3].inner[3] ^= s[1].inner[3];
        s[1].inner.swap(3, 1);
        s[1].inner.swap(2, 0);
        s[3].inner[0] ^= s[4].inner[0] & s[0].inner[0];
        s[3].inner[1] ^= s[4].inner[1] & s[0].inner[1];
        s[3].inner[2] ^= s[4].inner[2] & s[0].inner[2];
        s[3].inner[3] ^= s[4].inner[3] & s[0].inner[3];
        s[3].inner[0] = s[3].inner[0].rotate_left(7);
        s[3].inner[1] = s[3].inner[1].rotate_left(7);
        s[3].inner[2] = s[3].inner[2].rotate_left(7);
        s[3].inner[3] = s[3].inner[3].rotate_left(7);
        s[4].inner[0] ^= input.inner[0];
        s[4].inner[1] ^= input.inner[1];
        s[4].inner[2] ^= input.inner[2];
        s[4].inner[3] ^= input.inner[3];
        s[4].inner[0] ^= s[2].inner[0];
        s[4].inner[1] ^= s[2].inner[1];
        s[4].inner[2] ^= s[2].inner[2];
        s[4].inner[3] ^= s[2].inner[3];

        let t = s[2].inner[3];
        s[2].inner[3] = s[2].inner[2];
        s[2].inner[2] = s[2].inner[1];
        s[2].inner[1] = s[2].inner[0];
        s[2].inner[0] = t;
        s[4].inner[0] ^= s[0].inner[0] & s[1].inner[0];
        s[4].inner[1] ^= s[0].inner[1] & s[1].inner[1];
        s[4].inner[2] ^= s[0].inner[2] & s[1].inner[2];
        s[4].inner[3] ^= s[0].inner[3] & s[1].inner[3];
        s[4].inner[0] = s[4].inner[0].rotate_left(4);
        s[4].inner[1] = s[4].inner[1].rotate_left(4);
        s[4].inner[2] = s[4].inner[2].rotate_left(4);
        s[4].inner[3] = s[4].inner[3].rotate_left(4);
    }

    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        let c = [
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9,
            0x79, 0x62, 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42,
            0x73, 0xb5, 0x28, 0xdd,
        ];
        let k0 = u64::from_le_bytes(*array_ref![key, 0, 8]);
        let k1 = u64::from_le_bytes(*array_ref![key, 8, 8]);
        let mut state = State {
            inner: [
                Lane {
                    inner: [
                        u64::from_le_bytes(*array_ref![nonce, 0, 8]),
                        u64::from_le_bytes(*array_ref![nonce, 8, 8]),
                        0,
                        0,
                    ],
                },
                Lane {
                    inner: [k0, k1, k0, k1],
                },
                Lane {
                    inner: [!0, !0, !0, !0],
                },
                Lane {
                    inner: [0, 0, 0, 0],
                },
                Lane::from_bytes(&c),
            ],
        };

        for _ in 0..16 {
            state.update(Lane { inner: [0u64; 4] });
        }

        state.inner[1].inner[0] ^= k0;
        state.inner[1].inner[1] ^= k1;
        state.inner[1].inner[2] ^= k0;
        state.inner[1].inner[3] ^= k1;

        state
    }

    fn enc(&mut self, destination: &mut [u8; 32], source: &[u8; 32]) {
        let p = Lane::from_bytes(source);
        let c = {
            let s = &self.inner;
            Lane {
                inner: [
                    p.inner[0] ^ s[0].inner[0] ^ s[1].inner[1] ^ (s[2].inner[0] & s[3].inner[0]),
                    p.inner[1] ^ s[0].inner[1] ^ s[1].inner[2] ^ (s[2].inner[1] & s[3].inner[1]),
                    p.inner[2] ^ s[0].inner[2] ^ s[1].inner[3] ^ (s[2].inner[2] & s[3].inner[2]),
                    p.inner[3] ^ s[0].inner[3] ^ s[1].inner[0] ^ (s[2].inner[3] & s[3].inner[3]),
                ],
            }
        };
        c.write(destination);
        self.update(p);
    }

    fn dec(&mut self, destination: &mut [u8; 32], source: &[u8; 32]) {
        let c = Lane::from_bytes(source);
        let p = {
            let s = &self.inner;
            Lane {
                inner: [
                    c.inner[0] ^ s[0].inner[0] ^ s[1].inner[1] ^ (s[2].inner[0] & s[3].inner[0]),
                    c.inner[1] ^ s[0].inner[1] ^ s[1].inner[2] ^ (s[2].inner[1] & s[3].inner[1]),
                    c.inner[2] ^ s[0].inner[2] ^ s[1].inner[3] ^ (s[2].inner[2] & s[3].inner[2]),
                    c.inner[3] ^ s[0].inner[3] ^ s[1].inner[0] ^ (s[2].inner[3] & s[3].inner[3]),
                ],
            }
        };
        p.write(destination);
        self.update(p);
    }

    fn dec_partial(&mut self, destination: &mut [u8; 32], source: &[u8]) {
        let len = source.len();
        let mut src_padded = [0u8; 32];
        src_padded[..len].copy_from_slice(source);
        let c = Lane::from_bytes(&src_padded);
        let p = {
            let s = &self.inner;
            Lane {
                inner: [
                    c.inner[0] ^ s[0].inner[0] ^ s[1].inner[1] ^ (s[2].inner[0] & s[3].inner[0]),
                    c.inner[1] ^ s[0].inner[1] ^ s[1].inner[2] ^ (s[2].inner[1] & s[3].inner[1]),
                    c.inner[2] ^ s[0].inner[2] ^ s[1].inner[3] ^ (s[2].inner[2] & s[3].inner[2]),
                    c.inner[3] ^ s[0].inner[3] ^ s[1].inner[0] ^ (s[2].inner[3] & s[3].inner[3]),
                ],
            }
        };
        p.write(destination);
        destination[len..].fill(0);
        let p = Lane::from_bytes(destination);
        self.update(p);
    }

    fn mac(&mut self, associated_data_length: usize, message_length: usize) -> Tag {
        let t = Lane {
            inner: [
                associated_data_length as u64 * 8,
                message_length as u64 * 8,
                0,
                0,
            ],
        };

        {
            let s = &mut self.inner;
            s[4].inner[0] ^= s[0].inner[0];
            s[4].inner[1] ^= s[0].inner[1];
            s[4].inner[2] ^= s[0].inner[2];
            s[4].inner[3] ^= s[0].inner[3];
        }

        for _ in 0..10 {
            self.update(t);
        }

        let s = &mut self.inner;
        s[0].inner[0] ^= s[1].inner[1] ^ (s[2].inner[0] & s[3].inner[0]);
        s[0].inner[1] ^= s[1].inner[2] ^ (s[2].inner[1] & s[3].inner[1]);
        s[0].inner[2] ^= s[1].inner[3] ^ (s[2].inner[2] & s[3].inner[2]);
        s[0].inner[3] ^= s[1].inner[0] ^ (s[2].inner[3] & s[3].inner[3]);

        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&s[0].inner[0].to_le_bytes());
        tag[8..16].copy_from_slice(&s[0].inner[1].to_le_bytes());

        tag
    }
}

#[repr(transparent)]
pub struct Morus(State);

impl Morus {
    /// Create a new AEAD instance.
    /// `key` and `nonce` must be 16 bytes long.
    pub fn new(nonce: &Nonce, key: &Key) -> Self {
        Morus(State::new(key, nonce))
    }

    /// Encrypts a message using Morus-1280-128
    /// # Arguments
    /// * `message` - Message
    /// * `associated_data` - Associated data
    /// # Returns
    /// Encrypted message and authentication tag.
    #[cfg(feature = "std")]
    pub fn encrypt(mut self, message: &[u8], associated_data: &[u8]) -> (Vec<u8>, Tag) {
        let state = &mut self.0;
        let message_length = message.len();
        let associated_data_length = associated_data.len();
        let mut ciphertext = Vec::with_capacity(message_length);
        let mut source = [0u8; 32];
        let mut destination = [0u8; 32];
        let mut i = 0;

        while i + 32 <= associated_data_length {
            source.copy_from_slice(&associated_data[i..][..32]);
            state.enc(&mut destination, &source);
            i += 32;
        }

        if associated_data_length % 32 != 0 {
            source.fill(0);
            source[..associated_data_length % 32].copy_from_slice(&associated_data[i..]);
            state.enc(&mut destination, &source);
        }

        i = 0;

        while i + 32 <= message_length {
            source.copy_from_slice(&message[i..][..32]);
            state.enc(&mut destination, &source);
            ciphertext.extend_from_slice(&destination);
            i += 32;
        }

        if message_length % 32 != 0 {
            source.fill(0);
            source[..message_length % 32].copy_from_slice(&message[i..]);
            state.enc(&mut destination, &source);
            ciphertext.extend_from_slice(&destination[..message_length % 32]);
        }

        let tag = state.mac(associated_data_length, message_length);

        (ciphertext, tag)
    }

    /// Encrypts a message in-place using Morus-1280-128
    /// # Arguments
    /// * `in_out_buffer` - Input and output buffer
    /// * `associated_data` - Associated data
    /// # Returns
    /// Encrypted message and authentication tag.
    pub fn encrypt_in_place(mut self, in_out_buffer: &mut [u8], associated_data: &[u8]) -> Tag {
        let state = &mut self.0;
        let in_out_buffer_length = in_out_buffer.len();
        let associated_data_length = associated_data.len();
        let mut source = [0u8; 32];
        let mut destination = [0u8; 32];
        let mut i = 0;

        while i + 32 <= associated_data_length {
            source.copy_from_slice(&associated_data[i..][..32]);
            state.enc(&mut destination, &source);
            i += 32;
        }

        if associated_data_length % 32 != 0 {
            source.fill(0);
            source[..associated_data_length % 32].copy_from_slice(&associated_data[i..]);
            state.enc(&mut destination, &source);
        }

        i = 0;

        while i + 32 <= in_out_buffer_length {
            source.copy_from_slice(&in_out_buffer[i..][..32]);
            state.enc(&mut destination, &source);
            in_out_buffer[i..][..32].copy_from_slice(&destination);
            i += 32;
        }

        if in_out_buffer_length % 32 != 0 {
            source.fill(0);
            source[..in_out_buffer_length % 32].copy_from_slice(&in_out_buffer[i..]);
            state.enc(&mut destination, &source);
            in_out_buffer[i..].copy_from_slice(&destination[..in_out_buffer_length % 32]);
        }

        state.mac(associated_data_length, in_out_buffer_length)
    }

    /// Decrypts a message using Morus-1280-128
    /// # Arguments
    /// * `ciphertext` - Ciphertext
    /// * `tag` - Authentication tag
    /// * `associated_data` - Associated data
    /// # Returns
    /// Decrypted message.
    #[cfg(feature = "std")]
    pub fn decrypt(
        mut self,
        ciphertext: &[u8],
        tag: &Tag,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, crate::errors::Error> {
        let state = &mut self.0;
        let ciphertext_length = ciphertext.len();
        let associated_data_length = associated_data.len();
        let mut decrypted_message = Vec::with_capacity(ciphertext_length);
        let mut source = [0u8; 32];
        let mut destination = [0u8; 32];
        let mut i = 0;

        while i + 32 <= associated_data_length {
            source.copy_from_slice(&associated_data[i..][..32]);
            state.enc(&mut destination, &source);
            i += 32;
        }

        if associated_data_length % 32 != 0 {
            source.fill(0);
            source[..associated_data_length % 32].copy_from_slice(&associated_data[i..]);
            state.enc(&mut destination, &source);
        }

        i = 0;

        while i + 32 <= ciphertext_length {
            source.copy_from_slice(&ciphertext[i..][..32]);
            state.dec(&mut destination, &source);
            decrypted_message.extend_from_slice(&destination);
            i += 32;
        }

        if ciphertext_length % 32 != 0 {
            state.dec_partial(&mut destination, &ciphertext[i..]);
            decrypted_message.extend_from_slice(&destination[0..ciphertext_length % 32]);
        }

        let tag2 = state.mac(associated_data_length, ciphertext_length);
        let mut acc = 0;

        for (a, b) in tag.iter().zip(tag2.iter()) {
            acc |= a ^ b;
        }

        if acc != 0 {
            decrypted_message.fill(0xaa);

            return Err(crate::errors::Error::InvalidTag);
        }

        Ok(decrypted_message)
    }

    /// Decrypts a message in-place using Morus-1280-128
    /// # Arguments
    /// * `in_out_buffer` - Input and output buffer
    /// * `tag` - Authentication tag
    /// * `associated_data` - Associated data
    pub fn decrypt_in_place(
        mut self,
        in_out_buffer: &mut [u8],
        tag: &Tag,
        associated_data: &[u8],
    ) -> Result<(), crate::errors::Error> {
        let state = &mut self.0;
        let in_out_length = in_out_buffer.len();
        let associated_data_length = associated_data.len();
        let mut source = [0u8; 32];
        let mut destination = [0u8; 32];
        let mut i = 0;

        while i + 32 <= associated_data_length {
            source.copy_from_slice(&associated_data[i..][..32]);
            state.enc(&mut destination, &source);
            i += 32;
        }

        if associated_data_length % 32 != 0 {
            source.fill(0);
            source[..associated_data_length % 32].copy_from_slice(&associated_data[i..]);
            state.enc(&mut destination, &source);
        }

        i = 0;

        while i + 32 <= in_out_length {
            source.copy_from_slice(&in_out_buffer[i..][..32]);
            state.dec(&mut destination, &source);
            in_out_buffer[i..][..32].copy_from_slice(&destination);
            i += 32;
        }

        if in_out_length % 32 != 0 {
            state.dec_partial(&mut destination, &in_out_buffer[i..]);
            in_out_buffer[i..].copy_from_slice(&destination[0..in_out_length % 32]);
        }

        let tag2 = state.mac(associated_data_length, in_out_length);
        let mut acc = 0;

        for (a, b) in tag.iter().zip(tag2.iter()) {
            acc |= a ^ b;
        }

        if acc != 0 {
            in_out_buffer.fill(0xaa);

            return Err(crate::errors::Error::InvalidTag);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "std")]
    fn test_morus() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let (c, tag) = Morus::new(&nonce, key).encrypt(m, ad);
        let expected_c = [
            113, 42, 233, 132, 67, 60, 238, 160, 68, 138, 106, 79, 53, 175, 212, 107, 66, 244, 45,
            105, 49, 110, 66, 170, 84, 38, 77, 253, 137, 81, 41, 59, 110, 214, 118, 201, 168, 19,
            231, 244, 39, 69, 230, 33, 13, 233, 200, 44, 74, 198, 127, 222, 87, 105, 92, 45, 30,
            31, 47, 48, 38, 130, 241, 24, 198, 137, 89, 21, 222, 143, 166, 61, 225, 187, 121, 140,
            122, 23, 140, 227, 41, 13, 254, 53, 39, 195, 112, 164, 198, 91, 224, 28, 165, 91, 122,
            187, 38, 181, 115, 173, 233, 7, 108, 191, 155, 140, 6, 172, 199, 80, 71, 10, 69, 36,
        ];
        let expected_tag = [
            254, 11, 243, 234, 96, 11, 3, 85, 235, 83, 93, 221, 53, 50, 14, 27,
        ];
        assert_eq!(c, expected_c);
        assert_eq!(tag, expected_tag);

        let m2 = Morus::new(&nonce, key).decrypt(&c, &tag, ad).unwrap();
        assert_eq!(m2, m);
    }

    #[test]
    fn test_morus_in_place() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let mut mc = m.to_vec();
        let tag = Morus::new(&nonce, key).encrypt_in_place(&mut mc, ad);
        let expected_mc = [
            113, 42, 233, 132, 67, 60, 238, 160, 68, 138, 106, 79, 53, 175, 212, 107, 66, 244, 45,
            105, 49, 110, 66, 170, 84, 38, 77, 253, 137, 81, 41, 59, 110, 214, 118, 201, 168, 19,
            231, 244, 39, 69, 230, 33, 13, 233, 200, 44, 74, 198, 127, 222, 87, 105, 92, 45, 30,
            31, 47, 48, 38, 130, 241, 24, 198, 137, 89, 21, 222, 143, 166, 61, 225, 187, 121, 140,
            122, 23, 140, 227, 41, 13, 254, 53, 39, 195, 112, 164, 198, 91, 224, 28, 165, 91, 122,
            187, 38, 181, 115, 173, 233, 7, 108, 191, 155, 140, 6, 172, 199, 80, 71, 10, 69, 36,
        ];
        let expected_tag = [
            254, 11, 243, 234, 96, 11, 3, 85, 235, 83, 93, 221, 53, 50, 14, 27,
        ];
        assert_eq!(mc, expected_mc);
        assert_eq!(tag, expected_tag);

        Morus::new(&nonce, key)
            .decrypt_in_place(&mut mc, &tag, ad)
            .unwrap();
        assert_eq!(mc, m);
    }
}
