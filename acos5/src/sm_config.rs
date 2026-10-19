/*
 * sm_config.rs: Driver 'acos5' - secure messaging settings for the ACOS5-EVO
 */
/*
The card_driver block names one SM block with `secure_messaging = <name>`:

    secure_messaging <name> {
        mode = none;                # none | acl | transmit, default none
        kmc = "<64 hex digits>";    # optional master secret, AES-256
        session_keys = no;
        card <16 hex digits serial> {
            mode = ...; kmc = ...; session_keys = ...;
            keyset_<AID hex>_02_enc = "<48 hex digits>";   # key 82, SM
            keyset_<AID hex>_02_mac = "<48 hex digits>";   # key 81, host authentication
        }
    }

Each setting resolves from the card sub-block, then the block, then the default. Keys resolve from the
card's keysets, then from the kmc in effect (card, then block). Without a named block, the old keyset
entries in the card_driver block still apply, with mode acl.
*/

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr::{null, null_mut};

use libc::free;
use opensc_sys::opensc::{sc_card, sc_context};
use opensc_sys::errors::{SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_INVALID_DATA, SC_ERROR_NOT_SUPPORTED};
use opensc_sys::scconf::{scconf_block, scconf_find_blocks, scconf_get_str};

use crate::cmd_card_info::serial_no;
use crate::constants_types::{CARD_DRV_SHORT_NAME, DataPrivate};
use crate::crypto::kbkdf_cmac;
use crate::sm::sm_ensure_current_aid;
use crate::wrappers::{wr_do_log, wr_do_log_t, wr_do_log_tuv, wr_do_log_rv_ret};

const KEY_LEN: usize = 24;
const KMC_LEN: usize = 32;
const LABEL_SM: &[u8] = b"ACOS5-EVO SM";
const LABEL_AUTH: &[u8] = b"ACOS5-EVO AUTH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SmMode { None, Acl, Transmit }

impl SmMode {
    fn name(self) -> &'static CStr {
        match self { Self::None => c"none", Self::Acl => c"acl", Self::Transmit => c"transmit" }
    }
}

/// Where the keys of an `EvoSmConfig` come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeySource { CardKeyset, CardKmc, BlockKmc, Legacy, None }

impl KeySource {
    pub(crate) fn name(self) -> &'static CStr {
        match self {
            Self::CardKeyset => c"card keyset",
            Self::CardKmc    => c"card kmc",
            Self::BlockKmc   => c"block kmc",
            Self::Legacy     => c"legacy",
            Self::None       => c"none",
        }
    }
}

/* overwrite in a way the compiler cannot drop as a dead store */
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

fn wipe_string(s: String) {
    let mut v = s.into_bytes();
    wipe(&mut v);
}

/// The static SM keys of a card: `sm` = key 82, `auth` = key 81 (both AES-192).
#[derive(Clone)]
pub(crate) struct EvoSmKeys {
    pub(crate) sm: [u8; KEY_LEN],
    pub(crate) auth: [u8; KEY_LEN],
}

impl Drop for EvoSmKeys {
    fn drop(&mut self) {
        wipe(&mut self.sm);
        wipe(&mut self.auth);
    }
}

impl std::fmt::Debug for EvoSmKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EvoSmKeys { .. }")
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EvoSmConfig {
    pub(crate) mode: SmMode,
    #[allow(dead_code)] // Task 7 reads it in the SM command paths
    pub(crate) keys: Option<EvoSmKeys>,
    #[allow(dead_code)] // Task 7 reads it in the SM command paths
    pub(crate) session_keys: bool,
    pub(crate) key_source: KeySource,
    pub(crate) serial: [u8; 8],
}

impl EvoSmConfig {
    /// The card serial as the name of its `card` sub-block: 16 upper-case hex digits.
    pub(crate) fn serial_hex(&self) -> String { serial_hex(&self.serial) }
}

fn serial_hex(serial: &[u8]) -> String {
    serial.iter().map(|b| format!("{b:02X}")).collect()
}

fn parse_mode(value: &str) -> Result<SmMode, i32> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none"     => Ok(SmMode::None),
        "acl"      => Ok(SmMode::Acl),
        "transmit" => Ok(SmMode::Transmit),
        _          => Err(SC_ERROR_INVALID_ARGUMENTS),
    }
}

fn parse_bool(value: &str) -> Result<bool, i32> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Ok(true),
        "no" | "false" | "off" | "0" => Ok(false),
        _ => Err(SC_ERROR_INVALID_ARGUMENTS),
    }
}

/* hex digits, optionally separated by ':' or white space (as sc_hex_to_bin accepts them) */
fn parse_hex(value: &str) -> Result<Vec<u8>, i32> {
    let mut digits: Vec<u8> = value.bytes().filter(|c| *c != b':' && !c.is_ascii_whitespace()).collect();
    let result = if digits.len() % 2 == 0 && digits.iter().all(u8::is_ascii_hexdigit) {
        Ok(digits.chunks_exact(2).map(|p| {
            let hi = char::from(p[0]).to_digit(16).unwrap_or(0);
            let lo = char::from(p[1]).to_digit(16).unwrap_or(0);
            u8::try_from(hi << 4 | lo).unwrap_or(0)
        }).collect())
    }
    else { Err(SC_ERROR_INVALID_DATA) };
    wipe(&mut digits);
    result
}

/* one 24-byte key: hex, or for legacy entries also the old 24-character raw form */
fn parse_key(value: String, allow_raw: bool) -> Result<[u8; KEY_LEN], i32> {
    let mut bytes = if allow_raw && value.len() == KEY_LEN { Ok(value.as_bytes().to_vec()) }
                    else { parse_hex(&value) };
    wipe_string(value);
    let mut key = [0_u8; KEY_LEN];
    let result = match bytes {
        Ok(ref b) if b.len() == KEY_LEN => { key.copy_from_slice(b); Ok(key) },
        Ok(_) => Err(SC_ERROR_INVALID_DATA),
        Err(e) => Err(e),
    };
    if let Ok(ref mut b) = bytes { wipe(b); }
    wipe(&mut key);
    result
}

/* the keyset pair enc (key 82) and mac (key 81); none: Ok(None), only one of them: error */
fn keyset(get: &dyn Fn(&str) -> Option<String>, aid: &[u8], allow_raw: bool) -> Result<Option<EvoSmKeys>, i32> {
    let aid_hex = serial_hex(aid);
    let enc = get(&format!("keyset_{aid_hex}_02_enc"));
    let mac = get(&format!("keyset_{aid_hex}_02_mac"));
    match (enc, mac) {
        (None, None) => Ok(None),
        (Some(enc), Some(mac)) => {
            match (parse_key(enc, allow_raw), parse_key(mac, allow_raw)) {
                (Ok(sm), Ok(auth)) => Ok(Some(EvoSmKeys { sm, auth })),
                (Ok(mut key), Err(e)) | (Err(e), Ok(mut key)) => { wipe(&mut key); Err(e) },
                (Err(e), Err(_)) => Err(e),
            }
        },
        (enc, mac) => {
            if let Some(s) = enc { wipe_string(s); }
            if let Some(s) = mac { wipe_string(s); }
            Err(SC_ERROR_INVALID_DATA)
        },
    }
}

fn keys_from_kmc(value: String, serial: &[u8; 8]) -> Result<EvoSmKeys, i32> {
    let mut kmc = parse_hex(&value);
    wipe_string(value);
    let result = match kmc {
        Ok(ref k) if k.len() == KMC_LEN => {
            let mut keys = EvoSmKeys { sm: [0; KEY_LEN], auth: [0; KEY_LEN] };
            let mut sm = kbkdf_cmac(k, LABEL_SM, serial, KEY_LEN);
            let mut auth = kbkdf_cmac(k, LABEL_AUTH, serial, KEY_LEN);
            keys.sm.copy_from_slice(&sm);
            keys.auth.copy_from_slice(&auth);
            wipe(&mut sm);
            wipe(&mut auth);
            Ok(keys)
        },
        Ok(_) => Err(SC_ERROR_INVALID_DATA),
        Err(e) => Err(e),
    };
    if let Ok(ref mut k) = kmc { wipe(k); }
    result
}

/// Resolve the SM settings of one card.
///
/// `lookup(Some(serial_hex), key)` reads from the card's sub-block, `lookup(None, key)` from the block level.
/// `legacy(key)` reads the old keyset entries of the `card_driver` block; they apply only when the keys do
/// not resolve otherwise, and then the mode defaults to `acl`.
///
/// # Errors
/// `SC_ERROR_INVALID_ARGUMENTS` for an unknown `mode` or `session_keys` value, `SC_ERROR_INVALID_DATA`
/// for a keyset or `kmc` that is not hex of the right length, or a keyset without its partner.
/// No keys is not an error: `keys` is `None` then.
pub(crate) fn resolve(lookup: &dyn Fn(Option<&str>, &str) -> Option<String>, serial: &[u8; 8], aid: &[u8],
                      legacy: &dyn Fn(&str) -> Option<String>) -> Result<EvoSmConfig, i32>
{
    let serial_hex = serial_hex(serial);
    let card = |key: &str| lookup(Some(&serial_hex), key);
    let setting = |key: &str| card(key).or_else(|| lookup(None, key));

    let mode = setting("mode").map(|v| parse_mode(&v)).transpose()?;
    let session_keys = setting("session_keys").map(|v| parse_bool(&v)).transpose()?.unwrap_or(false);

    let (keys, key_source) =
        if let Some(keys) = keyset(&card, aid, false)? { (Some(keys), KeySource::CardKeyset) }
        else if let Some(kmc) = card("kmc") { (Some(keys_from_kmc(kmc, serial)?), KeySource::CardKmc) }
        else if let Some(kmc) = lookup(None, "kmc") { (Some(keys_from_kmc(kmc, serial)?), KeySource::BlockKmc) }
        else if let Some(keys) = keyset(legacy, aid, true)? { (Some(keys), KeySource::Legacy) }
        else { (None, KeySource::None) };

    let mode = mode.unwrap_or(if key_source == KeySource::Legacy { SmMode::Acl } else { SmMode::None });
    Ok(EvoSmConfig { mode, keys, session_keys, key_source, serial: *serial })
}

/* first block named `name` of type `item` within the application blocks of opensc.conf */
fn find_block(ctx: &sc_context, item: &CStr, name: *const c_char) -> *mut scconf_block {
    for elem in &ctx.conf_blocks {
        if elem.is_null() { break; }
        let blocks = unsafe { scconf_find_blocks(ctx.conf, *elem, item.as_ptr(), name) };
        if blocks.is_null() { continue; }
        let block = unsafe { *blocks };
        unsafe { free(blocks.cast::<c_void>()) };
        if !block.is_null() { return block; }
    }
    null_mut()
}

fn get_str(block: *const scconf_block, key: &str) -> Option<String> {
    if block.is_null() { return None; }
    let key = CString::new(key).ok()?;
    let value = unsafe { scconf_get_str(block, key.as_ptr(), null::<c_char>()) };
    if value.is_null() { None } else { Some(unsafe { CStr::from_ptr(value) }.to_string_lossy().into_owned()) }
}

/// Free the configuration cached in `DataPrivate::sm_config` (called when the card handle is released).
pub(crate) fn evo_sm_config_free(p: *mut c_void) {
    if !p.is_null() { drop(unsafe { Box::from_raw(p.cast::<EvoSmConfig>()) }); }
}

/// Read the SM settings of `card` from opensc.conf: the block that `secure_messaging` in
/// `card_driver acos5_external` names, its `card <serial>` sub-block, or the old keyset entries.
/// The result is cached for the lifetime of the card handle.
///
/// # Errors
/// As `resolve`; also if the serial cannot be read, the card is not an EVO (serial not 8 bytes) or the named
/// block does not exist.
#[allow(dead_code)] // Task 7 wires this into the SM command paths
pub(crate) fn evo_sm_config(card: &mut sc_card) -> Result<EvoSmConfig, i32> {
    if card.ctx.is_null() || card.drv_data.is_null() { return Err(SC_ERROR_INVALID_ARGUMENTS); }
    {
        let dp = unsafe { &*card.drv_data.cast::<DataPrivate>() };
        if !dp.sm_config.is_null() {
            return Ok(unsafe { &*dp.sm_config.cast::<EvoSmConfig>() }.clone());
        }
    }
    let ctx = unsafe { &mut *card.ctx };
    let f = c"evo_sm_config";

    let serialnr = serial_no(card).map_err(|e| log3ifr_ret!(ctx,f,line!(), e))?;
    let serial: [u8; 8] = serialnr.value.get(..serialnr.len).and_then(|s| s.try_into().ok())
        .ok_or_else(|| log3ifr_ret!(ctx,f,line!(), SC_ERROR_NOT_SUPPORTED))?;
    sm_ensure_current_aid(card).map_err(|e| log3ifr_ret!(ctx,f,line!(), e))?;
    let aid = card.sm_ctx.info.current_aid;
    let aid = &aid.value[..aid.len];

    let drv_block = find_block(ctx, c"card_driver", CARD_DRV_SHORT_NAME.as_ptr());
    let sm_name = get_str(drv_block, "secure_messaging");
    let (sm_block, card_block) = match sm_name {
        None => (null_mut(), null_mut()),
        Some(ref name) => {
            let name_c = CString::new(name.as_str()).map_err(|_e| SC_ERROR_INVALID_ARGUMENTS)?;
            let sm_block = find_block(ctx, c"secure_messaging", name_c.as_ptr());
            if sm_block.is_null() {
                log3if!(ctx,f,line!(), c"secure_messaging: no block named %s", name_c.as_ptr());
                return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_ARGUMENTS));
            }
            let serial_c = CString::new(serial_hex(&serial)).map_err(|_e| SC_ERROR_INVALID_ARGUMENTS)?;
            let blocks = unsafe { scconf_find_blocks(ctx.conf, sm_block, c"card".as_ptr(), serial_c.as_ptr()) };
            let card_block = if blocks.is_null() { null_mut() }
                             else { let b = unsafe { *blocks }; unsafe { free(blocks.cast::<c_void>()) }; b };
            (sm_block, card_block)
        },
    };
    let lookup = |serial: Option<&str>, key: &str| get_str(if serial.is_some() { card_block } else { sm_block }, key);
    let legacy = |key: &str| if sm_name.is_none() { get_str(drv_block, key) } else { None };

    let config = resolve(&lookup, &serial, aid, &legacy).map_err(|e| {
        let serial_c = CString::new(serial_hex(&serial)).unwrap_or_default();
        log3if!(ctx,f,line!(), c"secure_messaging: invalid setting for card %s", serial_c.as_ptr());
        log3ifr_ret!(ctx,f,line!(), e)
    })?;

    let serial_c = CString::new(config.serial_hex()).unwrap_or_default();
    log3if!(ctx,f,line!(), c"secure_messaging: card %s, mode %s, keys from %s", serial_c.as_ptr(),
        config.mode.name().as_ptr(), config.key_source.name().as_ptr());
    if config.key_source == KeySource::Legacy {
        log3if!(ctx,f,line!(), c"secure_messaging: deprecated keyset entries in card_driver; move them into a secure_messaging block");
    }

    let dp = unsafe { &mut *card.drv_data.cast::<DataPrivate>() };
    dp.sm_config = Box::into_raw(Box::new(config.clone())).cast::<c_void>();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use opensc_sys::errors::{SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_INVALID_DATA};
    use super::{resolve, EvoSmConfig, KeySource, SmMode};

    const SERIAL: [u8; 8] = [0x60, 0x20, 0x60, 0xA1, 0xC4, 0x65, 0x0A, 0x00];
    const SERIAL_HEX: &str = "602060A1C4650A00";
    const AID: &[u8] = b"ACOSPKCS-15v1.00";
    const ENC: &str = "keyset_41434F53504B43532D313576312E3030_02_enc";
    const MAC: &str = "keyset_41434F53504B43532D313576312E3030_02_mac";
    const KMC_VECTOR: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SM_VECTOR: [u8; 24] = [0x37, 0x9a, 0xf8, 0xcb, 0xe5, 0xd9, 0x10, 0xd3, 0x69, 0x3c, 0x63, 0xb4,
                                 0xe8, 0x82, 0xe9, 0x2a, 0x3d, 0xbc, 0xbf, 0x99, 0xa1, 0x0b, 0xf7, 0x80];
    const AUTH_VECTOR: [u8; 24] = [0xd6, 0xca, 0xad, 0xd8, 0x07, 0xa4, 0xc2, 0x2a, 0x4a, 0xa0, 0x93, 0x81,
                                   0xd2, 0xa1, 0xde, 0x1c, 0x15, 0x7f, 0x1c, 0xf8, 0x23, 0x58, 0x24, 0xc5];

    /* block entries: (None, key); card entries: (Some(serial), key) */
    struct Conf {
        main: HashMap<(Option<String>, String), String>,
        legacy: HashMap<String, String>,
    }

    impl Conf {
        fn new() -> Self { Self { main: HashMap::new(), legacy: HashMap::new() } }
        fn block(mut self, key: &str, value: &str) -> Self {
            let _unused = self.main.insert((None, key.into()), value.into());
            self
        }
        fn card(mut self, key: &str, value: &str) -> Self {
            let _unused = self.main.insert((Some(SERIAL_HEX.into()), key.into()), value.into());
            self
        }
        fn legacy(mut self, key: &str, value: &str) -> Self {
            let _unused = self.legacy.insert(key.into(), value.into());
            self
        }
        fn resolve(&self) -> Result<EvoSmConfig, i32> {
            let lookup = |serial: Option<&str>, key: &str| self.main.get(&(serial.map(String::from), key.into())).cloned();
            let legacy = |key: &str| self.legacy.get(key).cloned();
            resolve(&lookup, &SERIAL, AID, &legacy)
        }
    }

    fn hex24(b: u8) -> String { format!("{b:02x}").repeat(24) }

    #[test]
    fn mode_default_is_none() {
        let c = Conf::new().resolve().unwrap();
        assert_eq!(c.mode, SmMode::None);
        assert!(c.keys.is_none());
        assert_eq!(c.key_source, KeySource::None);
        assert!(!c.session_keys);
    }

    #[test]
    fn card_overrides_block() {
        let c = Conf::new().block("mode", "acl").card("mode", "transmit").resolve().unwrap();
        assert_eq!(c.mode, SmMode::Transmit);
    }

    #[test]
    fn mode_parse_trims_and_ignores_case() {
        assert_eq!(Conf::new().block("mode", " Transmit ").resolve().unwrap().mode, SmMode::Transmit);
        assert_eq!(Conf::new().block("mode", "plain").resolve().err(), Some(SC_ERROR_INVALID_ARGUMENTS));
    }

    #[test]
    fn card_keyset_beats_kmc() {
        let c = Conf::new().block("kmc", KMC_VECTOR).card("kmc", KMC_VECTOR)
            .card(ENC, &hex24(0x11)).card(MAC, &hex24(0x22)).resolve().unwrap();
        let keys = c.keys.as_ref().unwrap();
        assert_eq!(keys.sm, [0x11; 24]);
        assert_eq!(keys.auth, [0x22; 24]);
        assert_eq!(c.key_source, KeySource::CardKeyset);
    }

    #[test]
    fn card_kmc_beats_block_kmc() {
        let c = Conf::new().block("kmc", &"ff".repeat(32)).card("kmc", KMC_VECTOR).resolve().unwrap();
        let keys = c.keys.as_ref().unwrap();
        assert_eq!(keys.sm, SM_VECTOR);
        assert_eq!(keys.auth, AUTH_VECTOR);
        assert_eq!(c.key_source, KeySource::CardKmc);
    }

    #[test]
    fn block_kmc_vector() {
        let c = Conf::new().block("kmc", KMC_VECTOR).resolve().unwrap();
        let keys = c.keys.as_ref().unwrap();
        assert_eq!(keys.sm, SM_VECTOR);
        assert_eq!(keys.auth, AUTH_VECTOR);
        assert_eq!(c.key_source, KeySource::BlockKmc);
    }

    #[test]
    fn resolve_rejects_short_keyset() {
        let r = Conf::new().card(ENC, &"11".repeat(23)).card(MAC, &hex24(0x22)).resolve();
        assert_eq!(r.err(), Some(SC_ERROR_INVALID_DATA));
    }

    #[test]
    fn resolve_rejects_short_kmc() {
        let r = Conf::new().block("kmc", &"11".repeat(16)).resolve();
        assert_eq!(r.err(), Some(SC_ERROR_INVALID_DATA));
    }

    #[test]
    fn resolve_no_keys_is_error_not_panic() {
        let c = Conf::new().block("mode", "acl").resolve().unwrap();
        assert_eq!(c.mode, SmMode::Acl);
        assert!(c.keys.is_none());
        assert_eq!(c.key_source, KeySource::None);
    }

    #[test]
    fn legacy_keyset_used_without_block() {
        let raw_mac = "0123456789abcdefghijklmn"; // the old 24-character raw form
        let c = Conf::new().legacy(ENC, &hex24(0x33)).legacy(MAC, raw_mac).resolve().unwrap();
        assert_eq!(c.mode, SmMode::Acl);
        let keys = c.keys.as_ref().unwrap();
        assert_eq!(keys.sm, [0x33; 24]);
        assert_eq!(&keys.auth, raw_mac.as_bytes());
        assert_eq!(c.key_source, KeySource::Legacy);
    }
}
