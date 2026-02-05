pub mod bindings{
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::ffi::c_ulonglong;
use std::ptr::addr_of_mut;
pub use bindings::{
    CRYPTO_SECRETKEYBYTES,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_BYTES,
    CRYPTO_SEEDBYTES,
};
pub const CRYPTO_ALGNAME:&str = match match core::ffi::c_str::CStr::from_bytes_with_nul(bindings::CRYPTO_ALGNAME) {
    Ok(alg) => alg.to_str(),
    Err(_) => core::panic!("Unable to convert the CRYPTO_ALGNAME to a c_str"),
} {
    Ok(alg) => alg,
    Err(_) => core::panic!("Unable to convert the CRYPTO_ALGNAME to a string"),
};

/**
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
pub fn crypto_sign_seed_keypair(seed: &[u8; CRYPTO_SEEDBYTES as usize]) -> Result<([u8; CRYPTO_PUBLICKEYBYTES as usize], [u8; CRYPTO_SECRETKEYBYTES as usize]),::std::os::raw::c_int> {
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES as usize];
    let ret = unsafe { bindings::crypto_sign_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
    if ret != 0 { Err(ret)} else {Ok((pk, sk))}
}

/**
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
pub fn crypto_sign_keypair() -> Result<([u8; CRYPTO_PUBLICKEYBYTES as usize], [u8; CRYPTO_SECRETKEYBYTES as usize]),::std::os::raw::c_int> {
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES as usize];
    let ret = unsafe { bindings::crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if ret != 0 { Err(ret)} else {Ok((pk, sk))}
}

#[doc = "Returns an array containing a detached signature."]
pub fn crypto_sign_signature(
    message: &[u8],
    sk: &[u8;CRYPTO_SECRETKEYBYTES as usize],
) -> Result<[u8; CRYPTO_BYTES as usize], ::std::os::raw::c_int> {
    let mut sig = [0u8; CRYPTO_BYTES as usize];
    let mut sig_len = CRYPTO_BYTES as usize;
    let res = unsafe { bindings::crypto_sign_signature(sig.as_mut_ptr(), addr_of_mut!(sig_len), message.as_ptr(), message.len(), sk.as_ptr()) };

    if res != 0 {
        Err(res)
    } else {
        Ok(sig)
    }
}

#[doc = "Verifies a detached signature and message under a given public key."]
pub fn crypto_sign_verify(
    sig: &[u8],
    m: &[u8],
    pk: &[u8; CRYPTO_PUBLICKEYBYTES as usize],
) -> ::std::os::raw::c_int {
    unsafe {
        bindings::crypto_sign_verify(sig.as_ptr(), sig.len(), m.as_ptr(), m.len(), pk.as_ptr())
    }
}

#[doc = "Returns an array containing the signature followed by the message."]
pub fn crypto_sign(
    m: &[u8],
    sk: &[u8; CRYPTO_SECRETKEYBYTES as usize],
) -> Result<Vec<u8>, ::std::os::raw::c_int> {
    let mut sm = Vec::<u8>::with_capacity(CRYPTO_BYTES as usize + m.len());
    let mut sm_len = 0;
    let m_len = match c_ulonglong::try_from(m.len()) {
        Ok(len) => len,
        Err(_) => return Err(1),
    };
    unsafe {
        let ret = bindings::crypto_sign(sm.as_mut_ptr(), &mut sm_len, m.as_ptr(), m_len, sk.as_ptr());
        if ret != 0 { return Err(ret); }
        match usize::try_from(sm_len) {
            Ok(v) => sm.set_len(v),
            Err(_) => return Err(1),
        }
    };
    Ok(sm)
}

#[doc = "Verifies a given signature-message pair under a given public key."]
pub fn crypto_sign_open(
    m: &mut Vec<u8>,
    sm: &[u8],
    pk: &[u8; CRYPTO_PUBLICKEYBYTES as usize],
) -> ::std::os::raw::c_int {
    let mut len = match c_ulonglong::try_from(m.len()) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    unsafe {
        let ret = bindings::crypto_sign_open(m.as_mut_ptr(), &mut len, sm.as_ptr(), sm.len() as c_ulonglong, pk.as_ptr());
        match usize::try_from(len) {
            Ok(v) => m.set_len(v),
            Err(_) => return -1,
        }
        ret
    }
}
