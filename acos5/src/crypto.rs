/*
 * crypto.rs: Driver 'acos5' - cos5 cryptographic bindings and functions
 *
 * Copyright (C) 2019-  OpenSSL
 * Copyright (C) 2019-  Carsten Blüggel <bluecars@posteo.eu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor  Boston, MA 02110  USA
 */

//from openssl  des.h and rand.h

#![allow(nonstandard_style, reason = "..")]
#![allow(clippy::upper_case_acronyms, reason = "..")]

use std::os::raw::c_long;
use std::os::raw::c_int;

use crate::constants_types::safe_int_try_from;

pub(crate) const DES_KEY_SZ_u8 : u8    = 8; // sizeof(DES_cblock)
pub(crate) const DES_KEY_SZ    : usize = 8; // sizeof(DES_cblock)
pub(crate) const AES_BLOCK_SIZE: usize = 16;

pub(crate) const Encrypt: i32 = 1;
pub(crate) const Decrypt: i32 = 0;

pub(crate) type DES_cblock       = [u8; DES_KEY_SZ];
/*
pub type const_DES_cblock = [u8; DES_KEY_SZ];
pub type DES_LONG = c_ulong;

pub const OPENSSL_VERSION:     i32 =  0;
pub const OPENSSL_CFLAGS:      i32 =  1;
pub const OPENSSL_BUILT_ON:    i32 =  2;
pub const OPENSSL_PLATFORM:    i32 =  3;
pub const OPENSSL_DIR:         i32 =  4;
pub const OPENSSL_ENGINES_DIR: i32 =  5;
*/
#[repr(C)]
#[derive(Default, Debug)]
struct DES_key_schedule {
    ks: [DES_cblock; 16],
}

#[repr(C)]
#[derive(/*Default,*/ Debug)]
struct AES_KEY {
    rd_key: [u32; 60],
    rounds: c_int,
}

impl Default for AES_KEY {
    fn default() -> Self {
        Self {
            rd_key: [0; 60],
            rounds: 0
        }
    }
}

unsafe extern "C" {
//    pub fn OpenSSL_version_num() -> c_ulong;
//    pub fn OpenSSL_version(type_: i32) -> *const c_char;
    /// from openssl/rand.h: `RAND_bytes()` generates num random bytes using a cryptographically secure
    /// pseudo random generator (CSPRNG) and stores them in buf. buf MUST NOT be NULL.
    /// <https://docs.openssl.org/master/man3/RAND_bytes/>
    pub(crate) fn RAND_bytes(buf: *mut u8, num: i32) -> i32; // RAND_bytes() returns 1 on success, 0 otherwise

    /// from openssl/des.h: `DES_set_odd_parity()` sets the parity of the passed key to odd.
    /// <https://docs.openssl.org/master/man3/DES_random_key/>
    pub(crate) fn DES_set_odd_parity(key: *mut DES_cblock);
    /// from openssl/des.h: `DES_set_key_checked()` will check that the key passed is of odd parity
    /// and is not a weak or semi-weak key.
    /// <https://docs.openssl.org/master/man3/DES_random_key/>
    fn DES_set_key_checked  (block_key: *const u8, ks: *mut DES_key_schedule) -> i32;
//  fn DES_set_key_unchecked(block_key: *const u8, ks: *mut DES_key_schedule);
/// from openssl/des.h: `DES_ecb3_encrypt()` encrypts/decrypts the input block by using three-key
/// Triple-DES encryption in ECB mode. This involves encrypting the input with ks1, decrypting with
/// the key schedule ks2, and then encrypting with ks3.
/// <https://docs.openssl.org/master/man3/DES_random_key/>
    fn DES_ecb3_encrypt(input: *const u8, output: *mut u8,
                        ks1: *const DES_key_schedule,
                        ks2: *const DES_key_schedule,
                        ks3: *const DES_key_schedule,
                        enc: i32);
    /* DES_ede3_cbc_encrypt encrypts (or decrypts, if enc is DES_DECRYPT) len bytes from in to out with 3DES in CBC mode.
       3DES uses three keys, thus the function takes three different DES_key_schedules.*/
    /// from openssl/des.h: `DES_ede3_cbc_encrypt()` implements outer triple CBC DES encryption with
    /// three keys. This means that each DES operation inside the CBC mode is C=E(ks3,D(ks2,E(ks1,M))).
    /// <https://docs.openssl.org/master/man3/DES_random_key/>
    fn DES_ede3_cbc_encrypt(input: *const u8, output: *mut u8,
                            length: c_long,
                            ks1: *const DES_key_schedule,
                            ks2: *const DES_key_schedule,
                            ks3: *const DES_key_schedule,
                            ivec: *mut DES_cblock,
                            enc: i32);
    // return 0 for success, -1 if userKey or key is NULL, or -2 if the number of bits is unsupported.

    /// <https://mta.openssl.org/pipermail/openssl-users/2021-August/014103.html>
    //#[expect(dead_code, reason = "..")]
    fn AES_set_encrypt_key(userKey: *const u8, bits: i32, key: *mut AES_KEY) -> i32;
    //#[expect(dead_code, reason = "..")]
    fn AES_set_decrypt_key(userKey: *const u8, bits: i32, key: *mut AES_KEY) -> i32;

    /// <https://docs.openssl.org/3.1/man7/migration_guide>
    //#[expect(dead_code, reason = "..")]
    fn AES_ecb_encrypt(in_: *const u8, out: *mut u8, key: *const AES_KEY, enc: i32);
    /// <https://docs.openssl.org/3.1/man7/migration_guide>
    //#[expect(dead_code, reason = "..")]
    fn AES_cbc_encrypt(in_: *const u8, out: *mut u8, length: usize, key: *const AES_KEY, ivec: *mut u8, enc: i32);
}

/*
from https://github.com/tkaitchuck/aHash/blob/master/src/operations.rs
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes", not(miri)))]
#[allow(unused)]
#[inline(always)]
pub(crate) fn aesenc(value: u128, xor: u128) -> u128 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    use core::mem::transmute;
    unsafe {
        let value = transmute(value);
        transmute(_mm_aesenc_si128(value, transmute(xor)))
    }
}
*/

/*
//  from https://gist.github.com/vincascm/fda1cff664fa027937a53446ba8ef605
//! triple des(3des) ecb pkcs5 padding encrypt/decrypt function for rust, use openssl crypto
//! library.
//! refer to <http://blog.csdn.net/lyjinger/article/details/1722570>
//! coded by vinoca.
//! 2017.11.24
pub fn des_ecb3_pad_pkcs5(data: &[u8], key: &str, mode: i32) -> Vec<u8> {

    // pad data
    let mut data = data.to_vec();
    let mut pad = 8 - data.len() % 8;
    if pad == 8 {
        pad = 0;
    }
    for _ in 0..pad {
        data.push(pad as u8);
    }

    // pad key
    let mut key = key.as_bytes().to_vec();
    key.truncate(24);
    for _ in 0..24 - key.len() {
        key.push(0);
    }

    let mut ks = Vec::new();
    for _ in 0..3 {
        ks.push(DES_key_schedule::default());
    }
    let mut out_block = vec![0u8; 8];
    let mut output = Box::new(Vec::with_capacity(data.len()));
    unsafe {
        for (i, item) in key.chunks(8).enumerate() {
            DES_set_key_unchecked(item.as_ptr(), &mut ks[i]);
        }

        for i in data.chunks(8) {
            DES_ecb3_encrypt(i.as_ptr(), out_block.as_mut_ptr(), &ks[0], &ks[1], &ks[2], mode);
            output.extend_from_slice(&out_block);
        }
    }
    if mode == Decrypt {
        let pad = *output.last().unwrap();
        (*output).truncate(data.len() - pad as usize);
        *output
    } else {
        *output
    }
}
*/

/* this gets used currently only for Encrypt and data.len() known to be multiple of DES_KEY_SZ */
/// Document this !
#[must_use]
pub(crate) fn des_ecb3_unpadded_8(data: &[u8], key: &[u8], mode: i32) -> Vec<u8> { // -> [u8; DES_KEY_SZ] {
    assert!(data.len().is_multiple_of(DES_KEY_SZ));
    assert_eq!(24, key.len());

    let mut ks = [DES_key_schedule::default(), DES_key_schedule::default(), DES_key_schedule::default()];
    let mut output = vec![0_u8; data.len()];
    unsafe {
        for (i, item) in key.chunks_exact(DES_KEY_SZ).enumerate() {
            let rv = DES_set_key_checked(item.as_ptr(), &raw mut ks[i]);
            if rv != 0 {
                return output;
            }
        }

        for (i, chunk) in data.chunks_exact(DES_KEY_SZ).enumerate() {
            DES_ecb3_encrypt(chunk.as_ptr(), output.as_mut_ptr().add(i*DES_KEY_SZ), &raw const ks[0], &raw const ks[1], &raw const ks[2], mode);
        }
    }
    output
}

/*
acos5 applies padding only if ! data.len().is_multiple_of(DES_KEY_SZ)
acos5 sets a padding indicator byte pi while encrypting:
pi is relevant here only for Decrypt:
if pi==01, then it's known, that  a 0x80 byte was added (padding was applied and must be stripped in mode == Decrypt)
if pi==00, then it's known, that no 0x80 byte was added
*/
/// Document this !
#[must_use]
pub(crate) fn des_ede3_cbc_pad_80(data: &[u8], key: &[u8], ivec: &mut DES_cblock, mode: i32, pi: u8) -> Vec<u8> {
    assert_eq!(3*DES_KEY_SZ, key.len());
    assert!(mode==Encrypt || data.len().is_multiple_of(DES_KEY_SZ));

    let mut data = data.to_vec();
    // mode==Encrypt: pad data, if necessary
    if ! data.len().is_multiple_of(DES_KEY_SZ) {
        data.push(0x80);
        while ! data.len().is_multiple_of(DES_KEY_SZ) { data.push(0); }
    }

    let mut ks = [DES_key_schedule::default(), DES_key_schedule::default(), DES_key_schedule::default()];
    let mut output = vec![0_u8; data.len()];
    unsafe {
        for (i, item) in key.chunks_exact(DES_KEY_SZ).enumerate() {
            // DES_set_key_unchecked(item.as_ptr(), &mut ks[i]);
            let rv = DES_set_key_checked(item.as_ptr(), &raw mut ks[i]);
            if rv != 0 {
                return output;
            }
        }

        DES_ede3_cbc_encrypt(data.as_ptr(), output.as_mut_ptr(), safe_int_try_from(data.len()),
                             &raw const ks[0], &raw const ks[1], &raw const ks[2], ivec, mode);
    }

    if mode == Decrypt && pi==1 {
        while output.last().unwrap_or(&1) == &0  { let _unused = output.pop(); }
        if let Some(&b) = output.last() {
            if b == 0x80  { let _unused = output.pop(); }
            else { unreachable!("Incorrect padding detected!") }
        }
    }
    output
}

/// Document this !
#[must_use]
pub(crate) fn des_ede3_cbc_pad_80_mac(data: &[u8], key: &[u8], ivec: &mut DES_cblock) -> Vec<u8> {
    let mut result = des_ede3_cbc_pad_80(data, key, ivec, Encrypt, 0);
    assert!(result.len() >= DES_KEY_SZ);
    while result.len()>DES_KEY_SZ { let _unused = result.remove(0); }
    result
}

// AES
/* this will be used by EVO only for Encrypt and data known to be a multiple of AES_BLOCK_SIZE */
/// Document this !
#[cfg(test)]
#[must_use]
fn aes_ecb_unpadded_16(data: &[u8], key: &[u8], mode: i32) -> Vec<u8> {
    assert!(data.len().is_multiple_of(AES_BLOCK_SIZE));
    assert!([16, 24, 32].contains(&key.len()));
    // assert_eq!(Encrypt, mode); // TODO missing AES_set_decrypt_key

    let mut aes_key = AES_KEY::default();
    let mut out_block = [0_u8; AES_BLOCK_SIZE];
    let mut output = Vec::with_capacity(data.len());
    let res;
    unsafe {
        if mode == Encrypt {
            res = AES_set_encrypt_key(key.as_ptr(), 8* i32::try_from(key.len()).unwrap(), &raw mut aes_key);
        }
        else {
            res = AES_set_decrypt_key(key.as_ptr(), 8* i32::try_from(key.len()).unwrap(), &raw mut aes_key);
        }
        assert_eq!(0, res);

        for chunk in data.chunks_exact(AES_BLOCK_SIZE) {
            AES_ecb_encrypt(chunk.as_ptr(), out_block.as_mut_ptr(), &raw const aes_key, mode);
            output.extend_from_slice(&out_block[..]);
        }
    }
    output
}

/*
acos5 applies padding only if ! data.len().is_multiple_of(AES_BLOCK_SIZE)
acos5 sets a padding indicator byte pi while encrypting:
pi is relevant here only for Decrypt:
if pi==01, then it's known, that  a 0x80 byte was added (padding was applied and must be stripped in mode == Decrypt)
if pi==00, then it's known, that no 0x80 byte was added
*/
/// Document this !
#[cfg(test)]
#[must_use]
fn aes_cbc_pad_80(data: &[u8], key: &[u8], ivec: &mut [u8; AES_BLOCK_SIZE], mode: i32, pi: u8) -> Vec<u8> {
    assert!(mode==Encrypt || data.len().is_multiple_of(AES_BLOCK_SIZE));
    assert!([16, 24, 32].contains(&key.len()));

    let mut data = data.to_vec();
    // mode==Encrypt: pad data, if necessary
    if ! data.len().is_multiple_of(AES_BLOCK_SIZE) {
        data.push(0x80);
        while ! data.len().is_multiple_of(AES_BLOCK_SIZE) { data.push(0); }
    }

    let mut aes_key = AES_KEY::default();
    let mut output = vec![0_u8; data.len()];
    let res;
    unsafe {
        if mode == Encrypt {
            res = AES_set_encrypt_key(key.as_ptr(), 8* i32::try_from(key.len()).unwrap(), &raw mut aes_key);
        }
        else {
            res = AES_set_decrypt_key(key.as_ptr(), 8* i32::try_from(key.len()).unwrap(), &raw mut aes_key);
        }
        assert_eq!(0, res);

        AES_cbc_encrypt(data.as_ptr(), output.as_mut_ptr(), data.len(), &raw const aes_key, ivec.as_mut_ptr(), mode);
    }

    if mode == Decrypt && pi==1 {
        while output.last().unwrap_or(&1) == &0  { let _unused = output.pop(); }
        if let Some(&b) = output.last() {
            if b == 0x80  { let _unused = output.pop(); }
            else { panic!("Incorrect padding detected!") }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use crate::constants_types::prev_multiple_of;
    use super::{Encrypt, Decrypt, DES_KEY_SZ, DES_cblock, des_ecb3_unpadded_8, des_ede3_cbc_pad_80,
                des_ede3_cbc_pad_80_mac /*, des_ecb3_pad_pkcs5*/,
                AES_BLOCK_SIZE, aes_ecb_unpadded_16, aes_cbc_pad_80, DES_set_odd_parity, };
/*
    #[test]
    fn test_des_ecb3_pad_pkcs5() {
        let data = "hello world!";
        let key = "01234567899876543210";
        let e = des_ecb3_pad_pkcs5(&data.as_bytes(), &key, Encrypt);
        let d = des_ecb3_pad_pkcs5(&e, &key, Decrypt);
        println!("{:X?}", d);
        //println!("{:?}", std::str::from_utf8(&d).unwrap());
    }
*/

    #[test]
    fn test_multiple() {
        assert_eq!(16, prev_multiple_of(22, 8)); // equivalent: (integral_number / integral_step_size) * integral_step_size
        assert_eq!(24, 22_u8.next_multiple_of(8)); // if integral_number % integral_step_size == 0 {integral_number}
                                                       // else { (integral_number / integral_step_size +1) * integral_step_size }

        assert_eq!(24, prev_multiple_of(24, 8)); // no selection of smaller multiple !!
        assert_eq!(24, 24_u8.next_multiple_of(8)); // no selection of larger  multiple !!
    }

    #[test]
    fn test_des_ecb3_unpadded_8() {
        let data = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
        let mut key  = [0x32, 0x31, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x33, 0x31, 0x32, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x34, 0x31, 0x32, 0x33, 0x35, 0x36, 0x37, 0x38];
        for i in 0..3 {
            unsafe { DES_set_odd_parity(key.as_mut_ptr().add(i*8) as *mut DES_cblock); }
        }
        let e = des_ecb3_unpadded_8(&data, &key, Encrypt);
        let d = des_ecb3_unpadded_8(&e, &key, Decrypt);
//println!("{:X?}", e);
//println!("{:X?}", d);
        assert_eq!(&data[..], d.as_slice());
    }

    #[test]
    fn test_aes_ecb_unpadded_16() {// $ cargo test test_aes_ecb_unpadded_16 -- --nocapture
        let data = [
            0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x20,
            0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
            0x68, 0x65, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20,
            0x66, 0x6F, 0x72, 0x20, 0x00, 0x31, 0x00, 0x00,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xf1, 0xe0, 0xd3, 0xc2, 0xb5, 0xa4, 0x97, 0x86
        ];
        let key  = [
            0x32, 0x31, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x33, 0x31, 0x32, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x34, 0x31, 0x32, 0x33, 0x35, 0x36, 0x37, 0x38,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        ];
        let e = aes_ecb_unpadded_16(&data, &key, Encrypt);
        let d = aes_ecb_unpadded_16(&e, &key, Decrypt);
// println!("{:X?}", e);
// println!("{:X?}", d);
        assert_eq!(&data[..], d.as_slice());
    }

    #[test]
    fn test_des_ede3_cbc_pad_80() {
        let data = [
            0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x20,
            0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
            0x68, 0x65, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20,
            0x66, 0x6F, 0x72, 0x20, 0x00, 0x31, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33
        ];
        let key  = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                     0xf1, 0xe0, 0xd3, 0xc2, 0xb5, 0xa4, 0x97, 0x86,
                     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let mut ivec : DES_cblock = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let e = des_ede3_cbc_pad_80(&data, &key, &mut ivec, Encrypt, 0);
        assert!(e.len().is_multiple_of(DES_KEY_SZ));
        ivec = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let d = des_ede3_cbc_pad_80(&e, &key, &mut ivec, Decrypt, 1);
//println!("{:X?}", e);
//println!("{:X?}", d);
        assert_eq!(&data[..], d.as_slice());

        ivec = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let e = des_ede3_cbc_pad_80_mac(&data, &key, &mut ivec);
        assert!(e.len().is_multiple_of(DES_KEY_SZ));
        assert_eq!(&[0xBF, 0x59, 0xFF, 0x28, 0xE3, 0x23, 0xB9, 0xF4][..], e.as_slice());
//println!("{:X?}", e);
    }

    #[test]
    fn test_aes_cbc_pad_80() {
        let data = [
            0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x20,
            0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
            0x68, 0x65, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20,
            0x66, 0x6F, 0x72, 0x20, 0x00, 0x31, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33
        ];
        let key  = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xf1, 0xe0, 0xd3, 0xc2, 0xb5, 0xa4, 0x97, 0x86,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let mut ivec : [u8; AES_BLOCK_SIZE] = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let e = aes_cbc_pad_80(&data, &key, &mut ivec, Encrypt, 0);
        assert!(e.len().is_multiple_of(AES_BLOCK_SIZE));
        ivec = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let d = aes_cbc_pad_80(&e, &key, &mut ivec, Decrypt, 1);
//println!("{:X?}", e);
//println!("{:X?}", d);
        assert_eq!(&data[..], d.as_slice());
/*
        ivec = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let e = des_ede3_cbc_pad_80_mac(&data, &key, &mut ivec);
        assert!(e.len().is_multiple_of(DES_KEY_SZ));
        assert_eq!(&[0xBF, 0x59, 0xFF, 0x28, 0xE3, 0x23, 0xB9, 0xF4][..], e.as_slice());
*/
//println!("{:X?}", e);
    }
}

/* ACOS5-EVO secure messaging: AES with 128/192/256 bit keys.
   Data must already be a multiple of AES_BLOCK_SIZE (callers apply the 0x80 padding). */
#[must_use]
pub(crate) fn aes_cbc_nopad(data: &[u8], key: &[u8], iv: &[u8; AES_BLOCK_SIZE], mode: i32) -> Vec<u8> {
    assert!(data.len().is_multiple_of(AES_BLOCK_SIZE));
    assert!([16, 24, 32].contains(&key.len()));
    let mut aes_key = AES_KEY::default();
    let mut ivec = *iv;
    let mut output = vec![0_u8; data.len()];
    let bits = 8 * i32::try_from(key.len()).unwrap_or(0);
    unsafe {
        let res = if mode == Encrypt { AES_set_encrypt_key(key.as_ptr(), bits, &raw mut aes_key) }
                  else               { AES_set_decrypt_key(key.as_ptr(), bits, &raw mut aes_key) };
        assert_eq!(0, res);
        AES_cbc_encrypt(data.as_ptr(), output.as_mut_ptr(), data.len(), &raw const aes_key, ivec.as_mut_ptr(), mode);
    }
    output
}

/* Shift a 16 byte block left by one bit, then xor Rb (0x87) into the last byte if the msb was set. */
fn cmac_subkey_double(block: &[u8; AES_BLOCK_SIZE]) -> [u8; AES_BLOCK_SIZE] {
    let mut out = [0_u8; AES_BLOCK_SIZE];
    for i in 0..AES_BLOCK_SIZE {
        out[i] = (block[i] << 1) | if i + 1 < AES_BLOCK_SIZE { block[i + 1] >> 7 } else { 0 };
    }
    if block[0] & 0x80 != 0 { out[AES_BLOCK_SIZE - 1] ^= 0x87; }
    out
}

/* AES-CMAC (NIST SP 800-38B), full 16 byte tag */
#[must_use]
pub(crate) fn aes_cmac(data: &[u8], key: &[u8]) -> [u8; AES_BLOCK_SIZE] {
    assert!([16, 24, 32].contains(&key.len()));
    let mut aes_key = AES_KEY::default();
    let bits = 8 * i32::try_from(key.len()).unwrap_or(0);
    let mut l = [0_u8; AES_BLOCK_SIZE];
    unsafe {
        assert_eq!(0, AES_set_encrypt_key(key.as_ptr(), bits, &raw mut aes_key));
        AES_ecb_encrypt([0_u8; AES_BLOCK_SIZE].as_ptr(), l.as_mut_ptr(), &raw const aes_key, Encrypt);
    }
    let k1 = cmac_subkey_double(&l);
    let k2 = cmac_subkey_double(&k1);

    let complete = !data.is_empty() && data.len().is_multiple_of(AES_BLOCK_SIZE);
    let mut msg = data.to_vec();
    if !complete {
        msg.push(0x80);
        while !msg.len().is_multiple_of(AES_BLOCK_SIZE) { msg.push(0); }
    }
    let n = msg.len() / AES_BLOCK_SIZE;
    let subkey = if complete { k1 } else { k2 };
    for (i, b) in msg[(n - 1) * AES_BLOCK_SIZE..].iter_mut().enumerate() { *b ^= subkey[i]; }

    let mut x = [0_u8; AES_BLOCK_SIZE];
    for chunk in msg.chunks_exact(AES_BLOCK_SIZE) {
        let mut y = [0_u8; AES_BLOCK_SIZE];
        for i in 0..AES_BLOCK_SIZE { y[i] = x[i] ^ chunk[i]; }
        unsafe { AES_ecb_encrypt(y.as_ptr(), x.as_mut_ptr(), &raw const aes_key, Encrypt); }
    }
    x
}

/* NIST SP 800-108 counter mode KDF with AES-CMAC as PRF. Block i (1 byte, from 1) is
   CMAC(kmc, i || label || 00 || context || L), L = out_len in bits (2 bytes, big-endian). */
#[must_use]
pub(crate) fn kbkdf_cmac(kmc: &[u8], label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    #[expect(clippy::expect_used, reason = "callers ask for one key, far below 8 KB")]
    let bits = u16::try_from(out_len * 8).expect("KDF output too long");
    let mut fixed = label.to_vec();
    fixed.push(0);
    fixed.extend_from_slice(context);
    fixed.extend_from_slice(&bits.to_be_bytes());
    let mut out = Vec::with_capacity(out_len + AES_BLOCK_SIZE);
    let mut counter = 1_u8;
    while out.len() < out_len {
        let mut block = vec![counter];
        block.extend_from_slice(&fixed);
        out.extend_from_slice(&aes_cmac(&block, kmc));
        counter += 1;
    }
    out.truncate(out_len);
    out
}

#[cfg(test)]
mod tests_evo_aes {
    use super::{aes_cbc_nopad, aes_cmac, kbkdf_cmac, Encrypt, Decrypt};

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
    }

    #[test]
    fn cmac_sp800_38b_aes192() {
        // NIST SP 800-38B, D.2 (AES-192)
        let key = hex("8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b");
        assert_eq!(aes_cmac(&[], &key).to_vec(), hex("d1 7d df 46 ad aa cd e5 31 ca c4 83 de 7a 93 67"));
        let m = hex("6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a");
        assert_eq!(aes_cmac(&m, &key).to_vec(), hex("9e 99 a7 bf 31 e7 10 90 06 62 f6 5e 61 7c 51 84"));
        let m40 = hex("6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a ae 2d 8a 57 1e 03 ac 9c 9e b7 6f ac 45 af 8e 51 30 c8 1c 46 a3 5c e4 11");
        assert_eq!(aes_cmac(&m40, &key).to_vec(), hex("8a 1d e5 be 2e b3 1a ad 08 9a 82 e6 ee 90 8b 0e"));
    }

    #[test]
    fn kbkdf_cmac_vector() {
        let kmc: Vec<u8> = (0..32).collect();
        let serial = hex("60 20 60 A1 C4 65 0A 00");
        assert_eq!(kbkdf_cmac(&kmc, b"ACOS5-EVO SM", &serial, 24),
                   hex("37 9a f8 cb e5 d9 10 d3 69 3c 63 b4 e8 82 e9 2a 3d bc bf 99 a1 0b f7 80"));
        assert_eq!(kbkdf_cmac(&kmc, b"ACOS5-EVO AUTH", &serial, 24),
                   hex("d6 ca ad d8 07 a4 c2 2a 4a a0 93 81 d2 a1 de 1c 15 7f 1c f8 23 58 24 c5"));
    }

    #[test]
    fn cbc_roundtrip() {
        let key = [7_u8; 24];
        let iv = [9_u8; 16];
        let data = [0x5A_u8; 32];
        let enc = aes_cbc_nopad(&data, &key, &iv, Encrypt);
        assert_ne!(enc.as_slice(), data.as_slice());
        assert_eq!(aes_cbc_nopad(&enc, &key, &iv, Decrypt).as_slice(), data.as_slice());
    }
}

#[repr(C)] struct EC_GROUP { _p: [u8; 0] }
#[repr(C)] struct EC_POINT { _p: [u8; 0] }
#[repr(C)] struct BN_CTX   { _p: [u8; 0] }

unsafe extern "C" {
    fn EC_GROUP_new_by_curve_name(nid: c_int) -> *mut EC_GROUP;
    fn EC_GROUP_free(group: *mut EC_GROUP);
    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_free(point: *mut EC_POINT);
    fn EC_POINT_oct2point(group: *const EC_GROUP, p: *mut EC_POINT, buf: *const u8, len: usize, ctx: *mut BN_CTX) -> c_int;
    fn EC_POINT_point2oct(group: *const EC_GROUP, p: *const EC_POINT, form: c_int, buf: *mut u8, len: usize, ctx: *mut BN_CTX) -> usize;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
}

/* ACOS5-EVO curve indicator (1..4: P-224, P-256, P-384, P-521) -> OpenSSL NID */
fn evo_curve_nid(curve_indicator: u8) -> Option<c_int> {
    match curve_indicator { 1 => Some(713), 2 => Some(415), 3 => Some(715), 4 => Some(716), _ => None }
}

/* The ACOS5-EVO stores generated EC public keys as compressed points (02|03 || X); OpenSC accepts only
   uncompressed points. Returns 04 || X || Y, or None if the point is not valid on the curve. */
#[must_use]
pub(crate) fn ec_point_uncompress(curve_indicator: u8, point: &[u8]) -> Option<Vec<u8>> {
    let nid = evo_curve_nid(curve_indicator)?;
    unsafe {
        let group = EC_GROUP_new_by_curve_name(nid);
        if group.is_null() { return None; }
        let p = EC_POINT_new(group);
        let bn_ctx = BN_CTX_new();
        let mut result = None;
        if !p.is_null() && !bn_ctx.is_null() && EC_POINT_oct2point(group, p, point.as_ptr(), point.len(), bn_ctx) == 1 {
            let mut out = vec![0_u8; 1 + 2 * 66];
            let n = EC_POINT_point2oct(group, p, 4 /* POINT_CONVERSION_UNCOMPRESSED */, out.as_mut_ptr(), out.len(), bn_ctx);
            if n > 0 { out.truncate(n); result = Some(out); }
        }
        BN_CTX_free(bn_ctx);
        EC_POINT_free(p);
        EC_GROUP_free(group);
        result
    }
}

#[cfg(test)]
mod tests_ec_point {
    use super::ec_point_uncompress;

    #[test]
    fn p256_generator() {
        // P-256 base point G, compressed: 03 || Gx (Gy is odd)
        let gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        let gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        let h = |s: &str| (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i+2).unwrap(), 16).unwrap()).collect::<Vec<u8>>();
        let mut comp = vec![3_u8]; comp.extend(h(gx));
        let mut unc = vec![4_u8]; unc.extend(h(gx)); unc.extend(h(gy));
        assert_eq!(Some(unc), ec_point_uncompress(2, &comp));
        let mut bad = vec![2_u8]; bad.extend([0xFF_u8; 32]);  // X >= field prime: invalid
        assert_eq!(None, ec_point_uncompress(2, &bad));
    }
}

fn der_len(len: usize) -> Vec<u8> {
    match len {
        0..=0x7F   => vec![u8::try_from(len).unwrap_or(0)],
        0x80..=0xFF => vec![0x81, u8::try_from(len).unwrap_or(0)],
        _          => vec![0x82, u8::try_from(len >> 8).unwrap_or(0), u8::try_from(len & 0xFF).unwrap_or(0)],
    }
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(der_len(value.len()));
    v.extend_from_slice(value);
    v
}

/* SubjectPublicKeyInfo for an EC public key (uncompressed point) on an ACOS5-EVO curve.
   OpenSC (with pkcs15-ec-card-read-spki.patch) takes the curve parameters from it. */
#[must_use]
pub(crate) fn ec_spki_der(curve_indicator: u8, point: &[u8]) -> Option<Vec<u8>> {
    let curve_oid: &[u8] = match curve_indicator {
        1 => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21],                   // secp224r1
        2 => &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], // prime256v1
        3 => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],                   // secp384r1
        4 => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23],                   // secp521r1
        _ => return None,
    };
    let mut alg = vec![0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; // id-ecPublicKey
    alg.extend_from_slice(curve_oid);
    let mut bits = vec![0_u8];
    bits.extend_from_slice(point);
    let mut body = der_tlv(0x30, &alg);
    body.extend(der_tlv(0x03, &bits));
    Some(der_tlv(0x30, &body))
}

#[cfg(test)]
mod tests_ec_spki {
    use super::ec_spki_der;

    #[test]
    fn p256_and_p521_lengths() {
        let p256 = ec_spki_der(2, &[4_u8; 65]).unwrap();
        assert_eq!(&p256[..4], &[0x30, 0x59, 0x30, 0x13]);
        assert_eq!(0x5B, p256.len());
        let p521 = ec_spki_der(4, &[4_u8; 133]).unwrap();
        assert_eq!(&p521[..3], &[0x30, 0x81, 0x9B]); // long form length
        assert_eq!(3 + 0x9B, p521.len());
    }
}
