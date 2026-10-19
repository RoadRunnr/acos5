/*
 * sm.rs: Driver 'acos5' - Secure Messaging file
 *
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
/*
Secure Messaging is handled transparently towards OpenSC, meaning, it's done when necessary, but not communicated
towards OpenSC (OpenSC wouldn't help anyway but just confuse if setting SC_AC_PRO is used)
*/

/*
TODO There is a lot of code duplication here: Abstract as much as possible for the 4 APDU cases, but first test
  thoroughly that all is working as expected
*/

//#![expect(clippy::module_name_repetitions, reason = "..")]

use libc::{free, strlen};

use std::os::raw::{c_char, c_ulong, c_void};
use std::ffi::CString;
use std::ptr::{null, null_mut};
use std::slice::from_raw_parts;
use std::time::Instant;
use std::cmp::min;
use function_name::named;
use opensc_sys::opensc::{sc_context, sc_card, sc_hex_to_bin, sc_transmit_apdu,
                         sc_check_sw, sc_pin_cmd_data, SC_PIN_STATE_LOGGED_IN, SC_PIN_STATE_LOGGED_OUT,
                         SC_PIN_CMD_VERIFY, SC_PIN_CMD_CHANGE, SC_PIN_CMD_UNBLOCK, SC_PIN_CMD_GET_INFO,
                         SC_PIN_CMD_NEED_PADDING, sc_pin_cmd_pin, sc_build_pin};
#[cfg(not(target_os = "windows"))]
use opensc_sys::opensc::sc_select_file;
use opensc_sys::types::{SC_APDU_CASE_4_SHORT, sc_aid, sc_path};
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_SM_KEYSET_NOT_FOUND, SC_ERROR_UNKNOWN_DATA_RECEIVED, SC_ERROR_INVALID_DATA,
                         SC_ERROR_SM_IFD_DATA_MISSING, SC_ERROR_SM_AUTHENTICATION_FAILED,
                         SC_ERROR_SM_NOT_INITIALIZED, SC_ERROR_SM, SC_ERROR_PIN_CODE_INCORRECT, SC_ERROR_AUTH_METHOD_BLOCKED,
                         SC_ERROR_KEYPAD_MSG_TOO_LONG, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED,
                         SC_ERROR_CARD_CMD_FAILED, SC_ERROR_NO_CARD_SUPPORT, SC_ERROR_INVALID_ARGUMENTS};
    /*, SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_NOT_SUPPORTED*/
use opensc_sys::sm::{sm_info, SM_SMALL_CHALLENGE_LEN, SM_CMD_FILE_READ, SM_CMD_FILE_UPDATE, SM_CMD_PIN};
    /*, sm_cwa_session, SM_CMD_PIN_VERIFY, SM_CMD_FILE_CREATE, SM_CMD_FILE_DELETE, SM_CMD_FILE,*/
use opensc_sys::log::sc_dump_hex; /*, SC_LOG_DEBUG_NORMAL, SC_LOG_DEBUG_SM*/
use opensc_sys::scconf::{scconf_block, scconf_find_blocks, scconf_get_str};

use crate::constants_types::{ACOS5_OBJECT_REF_LOCAL, ACOS5_OBJECT_REF_MAX, CARD_DRV_SHORT_NAME, DataPrivate, build_apdu,
                             /*p_void,*/ SC_CARD_TYPE_ACOS5_EVO_V4, FDB_RSA_KEY_EF, FDB_ECC_KEY_EF, safe_int_try_from};
use crate::crypto::{DES_KEY_SZ, DES_KEY_SZ_u8, des_ecb3_unpadded_8, des_ede3_cbc_pad_80_mac, des_ede3_cbc_pad_80,
                    DES_set_odd_parity, DES_cblock, Encrypt, Decrypt};
use crate::no_cdecl::{authenticate_external, authenticate_internal};
use crate::wrappers::{wr_do_log, wr_do_log_t, wr_do_log_tttt, wr_do_log_tu,
                      wr_do_log_tuvw, wr_do_log_rv_ret, wr_do_log_sds_ret, wr_do_log_rv};
use crate::tasn1_pkcs15_util::analyze_PKCS15_DIRRecord_2F00;
use crate::sm_config::{evo_sm_config, evo_sm_find_aid, wipe, EvoSmConfig, SmMode};

#[expect(clippy::as_conversions, reason = "..")]
#[expect(clippy::cast_possible_truncation, reason = "we know, what we are doing here !")]
#[expect(non_upper_case_globals, reason = "..")]
pub(crate) const SM_SMALL_CHALLENGE_LEN_u8 : u8 = SM_SMALL_CHALLENGE_LEN as u8;

fn get_ck_enc_card(card: &sc_card) -> [u8; 3*DES_KEY_SZ] { // get_cwa_keyset_enc_card
    let mut result = [0; 3*DES_KEY_SZ];
    result[..2*DES_KEY_SZ].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.cwa_keyset.enc });
    result[2*DES_KEY_SZ..].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.icc.k[..DES_KEY_SZ] });
    result
}

fn get_ck_mac_host(card: &sc_card) -> [u8; 3*DES_KEY_SZ] { // get_cwa_keyset_mac_host
    let mut result = [0; 3*DES_KEY_SZ];
    result[..2*DES_KEY_SZ].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.cwa_keyset.mac });
    result[2*DES_KEY_SZ..].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.ifd.k[..DES_KEY_SZ] });
    result
}
//
fn get_cs_enc(card: &sc_card/*cwa: &sm_cwa_session*/) -> [u8; 3*DES_KEY_SZ] { // get_cwa_session_enc
    let mut result = [0; 3*DES_KEY_SZ];
    result[..2*DES_KEY_SZ].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.session_enc });
    result[2*DES_KEY_SZ..].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.icc.k[DES_KEY_SZ..2*DES_KEY_SZ] });
    result
}

fn get_cs_mac(card: &sc_card/*cwa: &sm_cwa_session*/) -> [u8; 3*DES_KEY_SZ] { // get_cwa_session_mac
    let mut result = [0; 3*DES_KEY_SZ];
    result[..2*DES_KEY_SZ].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.session_mac });
    result[2*DES_KEY_SZ..].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.ifd.k[DES_KEY_SZ..2*DES_KEY_SZ] });
    result
}

fn sm_incr_ssc(card: &mut sc_card) {
    let ssc = unsafe { card.sm_ctx.info.session.cwa.ssc };
    let mut x = u16::from_be_bytes([ssc[6], ssc[7]]);
    x = x.wrapping_add(1);
    unsafe { card.sm_ctx.info.session.cwa.ssc[6..8].copy_from_slice(&x.to_be_bytes()) };
}


#[named]
fn sm_cwa_config_get_keyset(ctx: &mut sc_context, sm_info: &mut sm_info) -> Result<(), i32>
{
    // libc doesn't provide snprintf for windows
    fn sprintf_ref(ref_: u8, qualifier: &str) -> CString {
        let mut vec : Vec<u8> = Vec::with_capacity(14);
        vec.extend_from_slice(b"keyset_");
        vec.extend_from_slice(format!("{ref_:02}").as_bytes());
        vec.push(b'_');
        vec.extend_from_slice(qualifier.as_bytes());
        unsafe { CString::from_vec_unchecked(vec) }
    }

    fn sprintf_aid_ref(aid: &sc_aid, ref_: u8, qualifier: &str) -> CString {
        let mut vec : Vec<u8> = Vec::with_capacity(80);
        vec.extend_from_slice(b"keyset_");
        vec.extend_from_slice(format!("{:X?}", &aid.value[..aid.len]).as_bytes());
        vec.retain(|&x| x != b'[' && x != b',' && x != b' ' && x != b']');
        vec.push(b'_');
        vec.extend_from_slice(format!("{ref_:02}").as_bytes());
        vec.push(b'_');
        vec.extend_from_slice(qualifier.as_bytes());
        unsafe { CString::from_vec_unchecked(vec) }
    }

    let cwa_session = unsafe { &mut sm_info.session.cwa };
    let cwa_keyset = &mut cwa_session.cwa_keyset;
    let mut sm_conf_block = null_mut::<scconf_block>();
    let crt_at = &cwa_session.params.crt_at;

    let mut name : CString; // [c_char; 128] = [0; 128];
    let mut hex  : [u8; 48]      = [0; 48];
    let mut hex_len;
    let mut rv : i32;
    let ref_ = ACOS5_OBJECT_REF_MAX & safe_int_try_from::<u32,u8>(crt_at.refs[0]);

    let f_cstr = CString::new(function_name!()).map_err(|_x| -1)?;
    let f = f_cstr.as_c_str();

    /* look for sc block in opensc.conf */
    for elem in &ctx.conf_blocks {
        if (*elem).is_null() { break; }
        let blocks_ptr = unsafe { scconf_find_blocks(ctx.conf, *elem,
            /*b"secure_messaging\0"*/ c"card_driver".as_ptr(),
        /*sm_info.config_section.as_ptr()*/ CARD_DRV_SHORT_NAME.as_ptr()) };
        if blocks_ptr.is_null() { continue; }
        sm_conf_block = unsafe { *blocks_ptr }; // blocks[0];

        unsafe { free(blocks_ptr.cast::<c_void>()) };
        if !sm_conf_block.is_null() { break; }
    }

    /*
        for (ii = 0; ctx->conf_blocks[ii]; ii++) {
            blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[ii], "secure_messaging", sm_info->config_section);
            if (blocks) {
                sm_conf_block = blocks[0];
                free(blocks);
            }

            if (sm_conf_block)
                break;
        }
    */
    log3if!(ctx,f,line!(), c"CRT(algo:%X,ref:%X)", crt_at.algo, crt_at.refs[0]);
    /*  FIXME strange behavior on Windows : line 290 will never be logged, thus the driver seems to starve in between, maybe some privilege issue accessing opensc.conf ?
    P:9344; T:9348 2020-11-07 03:36:27.174 [opensc-tool] acos5:263:sm_cwa_config_get_keyset: CRT(algo:0,ref:82)
    P:4268; T:4384 2020-11-07 03:36:37.559 [opensc-notify] reader-pcsc.c:1707:pcsc_wait_for_event: returning with: -1112 (Timeout while waiting for event from card reader)
    */

    /* Keyset ENC */
    if sm_info.current_aid.len>0 && (safe_int_try_from::<u32,u8>(crt_at.refs[0]) & ACOS5_OBJECT_REF_LOCAL) >0 {
        // unsafe { snprintf(name.as_mut_ptr(), name.len(), c"keyset_%s_%02i_enc".as_ptr(),
        //                   sc_dump_hex(sm_info.current_aid.value.as_ptr(), sm_info.current_aid.len), ref_) };
        name = sprintf_aid_ref(&sm_info.current_aid, ref_, "enc");
    }
    else {
        // unsafe { snprintf(name.as_mut_ptr(), name.len(), c"keyset_%02i_enc".as_ptr(), ref_) };
        name = sprintf_ref(ref_, "enc");
    }
    let mut value = unsafe { scconf_get_str(sm_conf_block, name.as_ptr(), null::<c_char>()) };

    if value.is_null() {
////                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "No %s value in OpenSC config", name);
        log3if!(ctx,f,line!(), c"No %s value in OpenSC config", name.as_ptr());
        return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_KEYSET_NOT_FOUND));
    }

    log3if!(ctx,f,line!(), c"%s: value of %zu characters", name.as_ptr(), unsafe { strlen(value) });
    if unsafe { strlen(value) } == 3*DES_KEY_SZ {
        cwa_keyset.enc.copy_from_slice(unsafe { from_raw_parts(value.cast::<u8>(), 2*DES_KEY_SZ) });
        cwa_session.icc.k[..DES_KEY_SZ].copy_from_slice(unsafe { from_raw_parts(
            value.add(2*DES_KEY_SZ).cast::<u8>(), DES_KEY_SZ) });
    }
    else {
        hex_len = hex.len();
        rv = unsafe { sc_hex_to_bin(value, hex.as_mut_ptr(), &raw mut hex_len) };
        if rv != SC_SUCCESS {
            log3if!(ctx,f,line!(), c"SM get %s: hextobin failed; error %i", name.as_ptr(), rv);
            return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_UNKNOWN_DATA_RECEIVED));
        }

        log3if!(ctx,f,line!(), c"%s: %zu bytes after hex decoding", name.as_ptr(), hex_len);
        if hex_len != 3*DES_KEY_SZ {
            return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_DATA));
        }
        cwa_keyset.enc.copy_from_slice(&hex[..2*DES_KEY_SZ]);
        cwa_session.icc.k[..DES_KEY_SZ].copy_from_slice(&hex[2*DES_KEY_SZ..3*DES_KEY_SZ]);
    }
    log3if!(ctx,f,line!(), c"%s: key of %zu bytes set", name.as_ptr(), 3*DES_KEY_SZ);

    /* Keyset MAC */
    if sm_info.current_aid.len>0 && (safe_int_try_from::<u32,u8>(crt_at.refs[0]) & ACOS5_OBJECT_REF_LOCAL) >0 {
        // unsafe { snprintf(name.as_mut_ptr(), name.len(), c"keyset_%s_%02i_mac".as_ptr(),
        //                   sc_dump_hex(sm_info.current_aid.value.as_ptr(), sm_info.current_aid.len), ref_) };
        name = sprintf_aid_ref(&sm_info.current_aid, ref_, "mac");
    }
    else {
//                snprintf(name, sizeof(name), "keyset_%02i_mac", ref);
//         unsafe { snprintf(name.as_mut_ptr(), name.len(), c"keyset_%02i_mac".as_ptr(), ref_) };
        name = sprintf_ref(ref_, "mac");
    }
    value = unsafe { scconf_get_str(sm_conf_block, name.as_ptr(), null::<c_char>()) };

    if value.is_null() {
////                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "No %s value in OpenSC config", name);
        log3if!(ctx,f,line!(), c"No %s value in OpenSC config", name.as_ptr());
        return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_KEYSET_NOT_FOUND));
    }

    log3if!(ctx,f,line!(), c"%s: value of %zu characters", name.as_ptr(), unsafe { strlen(value) });
    if unsafe { strlen(value) } == 3*DES_KEY_SZ {
        cwa_keyset.mac.copy_from_slice(unsafe { from_raw_parts(value.cast::<u8>(), 2*DES_KEY_SZ) });
        cwa_session.ifd.k[..DES_KEY_SZ].copy_from_slice(unsafe {
            from_raw_parts(value.add(2*DES_KEY_SZ).cast::<u8>(), DES_KEY_SZ) });
    }
    else   {
        hex_len = hex.len();
        rv = unsafe { sc_hex_to_bin(value, hex.as_mut_ptr(), &raw mut hex_len) };
        if rv != SC_SUCCESS {
            log3if!(ctx,f,line!(), c"SM get %s: hextobin failed; error %i", name.as_ptr(), rv);
            return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_UNKNOWN_DATA_RECEIVED));
        }

        log3if!(ctx,f,line!(), c"%s: %zu bytes after hex decoding", name.as_ptr(), hex_len);
        if hex_len != 3*DES_KEY_SZ {
            return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_DATA));
        }

        cwa_keyset.mac.copy_from_slice(&hex[..2*DES_KEY_SZ]);
        cwa_session.ifd.k[..DES_KEY_SZ].copy_from_slice(&hex[2*DES_KEY_SZ..3*DES_KEY_SZ]);
    }
    log3if!(ctx,f,line!(), c"%s: key of %zu bytes set", name.as_ptr(), 3*DES_KEY_SZ);

    cwa_keyset.sdo_reference = crt_at.refs[0];


    /* IFD parameters */
    //memset(cwa_session, 0, sizeof(struct sm_cwa_session));
//            value = scconf_get_str(sm_conf_block, "ifd_serial", NULL);
    value = unsafe { scconf_get_str(sm_conf_block, c"ifd_serial".as_ptr(), null::<c_char>()) };
    if value.is_null() {
        return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_IFD_DATA_MISSING));
    }
    hex_len = hex.len();
    rv = unsafe { sc_hex_to_bin(value, hex.as_mut_ptr(), &raw mut hex_len) };
    if rv != SC_SUCCESS   {
//sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "SM get 'ifd_serial': hex to bin failed for '%s'; error %i", value, rv);
        log3if!(ctx,f,line!(), c"SM get 'ifd_serial': hex to bin failed for '%s'; error %i", value, rv);
        return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_UNKNOWN_DATA_RECEIVED));
    }

    if hex_len != cwa_session.ifd.sn.len() {
//                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE,
//                        "SM get 'ifd_serial': invalid IFD serial length: %"SC_FORMAT_LEN_SIZE_T"u",
//                        hex_len);
        log3if!(ctx,f,line!(), c"SM get 'ifd_serial': invalid IFD serial length: %zu", hex_len);
        return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_UNKNOWN_DATA_RECEIVED));
    }

//            memcpy(cwa_session->ifd.sn, hex, hex_len);
    cwa_session.ifd.sn.copy_from_slice(&hex[..hex_len]);
// println!("cwa_session.ifd.sn: {:X?}", cwa_session.ifd.sn);
// println!("sm_info.serialnr:   {:X?}", sm_info.serialnr);
    if cwa_session.ifd.sn != sm_info.serialnr.value[..sm_info.serialnr.len] {
        return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM));
    }

    /*
                rv = RAND_bytes(cwa_session->ifd.rnd, DES_KEY_SZ_u8 as i32);
                if (!rv)   {
                    sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Generate random error: %i", rv);
                    return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_RAND_FAILED);
                }
    */
    /*
                rv = RAND_bytes(cwa_session->ifd.k, 32);
                if (!rv)   {
                    sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Generate random error: %i", rv);
                    return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_RAND_FAILED);
                }
    */
    /*
sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "IFD.Serial: %s", sc_dump_hex(cwa_session->ifd.sn, sizeof(cwa_session->ifd.sn)));
sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "IFD.Rnd: %s", sc_dump_hex(cwa_session->ifd.rnd, sizeof(cwa_session->ifd.rnd)));
sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "IFD.K: %s", sc_dump_hex(cwa_session->ifd.k, sizeof(cwa_session->ifd.k)));
    */
    log3ifr!(ctx,f,line!(), SC_SUCCESS);
    Ok(())
}

fn sm_cwa_initialize(card: &mut sc_card/*, sm_info: &mut sm_info, _rdata: &mut sc_remote_data*/) -> i32
{
    /*
    ck_mac_host: [F1, E0, D0, C1, B0, A1, 89, 8, 7, 16, 45, 4, 13, 2, 1, F1, 89, FE, B3, C8, 37, 45, 16, 94] corresponds to key_reference 0x81 (external auth. key terminal/host in DF 0x4100) kh, that will be authenticated
    ck_enc_card: [F1, 1, 2, 13, 4, 85, 16, 7, 8, 49, A1, B0, C1, D0, E0, F1, 45, 89, B3, 16, FE, 94, 37, C8] corresponds to key_reference 0x82 (internal auth. key card          in DF 0x4100) kc

    keyset_41434F53504B43532D313576312E3030_02_mac = "F1:E0:D0:C1:B0:A1:89:08:07:16:45:04:13:02:01:F1:89:FE:B3:C8:37:45:16:94"; # corresponds to key_reference 0x81 (external auth. key terminal/host in DF 0x4100) kh, that will be authenticated
    keyset_41434F53504B43532D313576312E3030_02_enc = "F1:01:02:13:04:85:16:07:08:49:A1:B0:C1:D0:E0:F1:45:89:B3:16:FE:94:37:C8"; # corresponds to key_reference 0x82 (internal auth. key card          in DF 0x4100) kc
    */
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = c"sm_cwa_initialize";
    log3ifc!(ctx,f,line!());
    /* Mutual Authentication Procedure with 2 different keys, (key card) kc and (key terminal/host) kh */
    match authenticate_external(card, 0x81, &get_ck_mac_host(card)) {
        Ok(val) => if !val { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_AUTHENTICATION_FAILED); },
        Err(_e) => { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_AUTHENTICATION_FAILED); },
    }
    unsafe { card.sm_ctx.info.session.cwa.ssc = card.sm_ctx.info.session.cwa.card_challenge };
    match authenticate_internal(card, 0x82, &get_ck_enc_card(card)) {
        Ok(val) => if !val { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_AUTHENTICATION_FAILED); },
        Err(_e) => { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_AUTHENTICATION_FAILED); },
    }
    /* session key(s) generation. acos5 does it internally automatically and we must do the same here */
    /* EVO: allows TDES and AES; for TDES the ref. manual is inconsistent: 32 byte deriv data for a max 24 byte session key ? */
    /* TODO : for EVO, switch to AES/256 */
    let mut deriv_data = Vec::with_capacity(3 * DES_KEY_SZ);
    unsafe {
        deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.card_challenge[4..8]);
        deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.host_challenge[0..4]);
        deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.card_challenge[0..4]);
        deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.host_challenge[4..8]);
        if card.type_ == SC_CARD_TYPE_ACOS5_EVO_V4 {
            deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.card_challenge[0..4]);
            deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.host_challenge[4..8]);
        }
        else {
            deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.host_challenge[0..4]);
            deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.card_challenge[4..8]);
        }
        card.sm_ctx.info.session.cwa.card_challenge.copy_from_slice(&[0; 8]);
        card.sm_ctx.info.session.cwa.host_challenge.copy_from_slice(&[0; 8]);
    }
//        writefln("deriv_data_plain:     0x [ %(%x %) ]", deriv_data);

    let mut sess_enc_buf = des_ecb3_unpadded_8(&deriv_data, &get_ck_enc_card(card), Encrypt);
    let mut sess_mac_buf = des_ecb3_unpadded_8(&deriv_data, &get_ck_mac_host(card), Encrypt);
    assert_eq!(3 * DES_KEY_SZ, sess_enc_buf.len());
    assert_eq!(3 * DES_KEY_SZ, sess_mac_buf.len());
    for i in 0..3 {
        unsafe {
            DES_set_odd_parity(sess_enc_buf.as_mut_ptr().add(i*8).cast::<DES_cblock>());
            DES_set_odd_parity(sess_mac_buf.as_mut_ptr().add(i*8).cast::<DES_cblock>());
        }
    }
    unsafe {
        card.sm_ctx.info.session.cwa.session_enc.copy_from_slice(&sess_enc_buf[..2*DES_KEY_SZ]);
        card.sm_ctx.info.session.cwa.icc.k[DES_KEY_SZ..2*DES_KEY_SZ].copy_from_slice(&sess_enc_buf[2*DES_KEY_SZ..]);
        card.sm_ctx.info.session.cwa.session_mac.copy_from_slice(&sess_mac_buf[..2*DES_KEY_SZ]);
        card.sm_ctx.info.session.cwa.ifd.k[DES_KEY_SZ..2*DES_KEY_SZ].copy_from_slice(&sess_mac_buf[2*DES_KEY_SZ..]);
    }
//println!("is_key_authenticated(card, 0x81): {}", get_is_key_authenticated(card, 0x81).unwrap()); // : true
//println!("is_key_authenticated(card, 0x82): {}", get_is_key_authenticated(card, 0x82).unwrap()); // : false
    SC_SUCCESS
}

fn sm_dur(cmd: u32) -> u128
{
    match cmd {
        SM_CMD_FILE_READ | SM_CMD_FILE_UPDATE => 300,
        SM_CMD_PIN  => 200,
        _           => 150,
    }
}

/// Set `card.sm_ctx.info.current_aid` from EF.DIR if it is not yet known; the current path stays selected.
#[named]
fn sm_ensure_current_aid(card: &mut sc_card) -> Result<(), i32>
{
    if card.ctx.is_null() { return Err(-1) }
    #[cfg(not(target_os = "windows"))]
    if card.sm_ctx.info.current_aid.len == 0 {
        let ctx = unsafe { &mut *card.ctx };
        let f_cstr = CString::new(function_name!()).map_err(|_x| -1)?;
        let f = f_cstr.as_c_str();
        let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        if dp.pkcs15_definitions.is_null() { let _unused = Box::leak(dp); return Err(-1) }
        let curr_path : sc_path = cfg_select! {
            any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0, v0_25_0, v0_25_1, v0_26_0, v0_26_1) =>
                 { card.cache.current_path }
            _ => { dp.card_cache.current_path }
        };
        let _unused = Box::leak(dp);

        let mut aid = sc_aid::default();
        let res = analyze_PKCS15_DIRRecord_2F00(card, &mut aid);
        if !res.unwrap_or(false) {
            return Err(log3ifr_ret!(ctx,f,line!(), -1));
        }
        //println!("AID: {:X?}", &aid.value[..aid.len]);
        card.sm_ctx.info.current_aid = aid;
        let rv = unsafe { sc_select_file(card, &raw const curr_path, null_mut()) };
        if rv != SC_SUCCESS {
            return Err(log3ifr_ret!(ctx,f,line!(), rv));
        }
    }
    Ok(())
}

#[named]
fn sm_manage_keyset(card: &mut sc_card) -> Result<(), i32>
{
    if card.ctx.is_null() { return Err(-1) }
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).map_err(|_x| -1)?;
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    if unsafe { card.sm_ctx.info.session.cwa.session_mac.ne(&[0; 16]) } {
        log3ifr!(ctx,f,line!(), SC_SUCCESS);
        Ok(())
    }
    else {
        sm_ensure_current_aid(card)?;
        log3if!(ctx,f,line!(), c"Current AID: %s",
            unsafe { sc_dump_hex(card.sm_ctx.info.current_aid.value.as_ptr(), card.sm_ctx.info.current_aid.len) });

//        case SM_TYPE_CWA14890:
        if let Err(e) = sm_cwa_config_get_keyset(ctx, &mut card.sm_ctx.info) {
            return Err(log3ifr_ret!(ctx,f,line!(), c"SM acos5 configuration error. Returning with", e));
        }
        log3ifr!(ctx,f,line!(), SC_SUCCESS);
        Ok(())
    }
}

/*
try to pass repetitive commands through the same SM session, but open a new session for new commands.
Also, some commands like verify always get a new session
repetitive commands: e.g. read_binary with large count will be chunk'ed to max. 240 bytes : same session

*: an SM command x or y is requested
timeline:                   *x                *x                *y                *x                *
         <- unknown cmd ? -> <- curr cmd: x -> <- curr cmd: x -> <- curr cmd: y -> <- curr cmd: x ->
                             <- last cmd: ? -> <- last cmd: x -> <- last cmd: x -> <- last cmd: y -> <- last cmd: x ->
                            =new_session      =dep on timing    =new_session      =new_session
*/
#[named]
fn sm_manage_initialize(card: &mut sc_card) -> Result<(), i32>
{
    if card.ctx.is_null() { return Err(-1) }
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).map_err(|_x| -1)?;
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());

    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let last_sm_cmd = dp.sm_cmd;
    dp.sm_cmd = card.sm_ctx.info.cmd;
    let last_time_stamp = dp.time_stamp;
    dp.time_stamp = Instant::now();
    card.drv_data = Box::into_raw(dp).cast::<c_void>();

//println!("elapsed ms: {}, last_sm_cmd: {:X}, this_sm_cmd: {:X}", last_time_stamp.elapsed().as_millis(), last_sm_cmd, card.sm_ctx.info.cmd);
    if  last_sm_cmd==0 || last_sm_cmd!=card.sm_ctx.info.cmd ||
        last_time_stamp.elapsed().as_millis() > sm_dur(last_sm_cmd) ||
        ![SM_CMD_FILE_READ, SM_CMD_FILE_UPDATE].contains(&card.sm_ctx.info.cmd)
    {
        let rv = sm_cwa_initialize(card/*, sm_info, rdata*/);
        if rv != SC_SUCCESS {
            log3if!(ctx,f,line!(),c"Error: #################### SM initializing failed ####################");
        }

        let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        dp.time_stamp = Instant::now();
        card.drv_data = Box::into_raw(dp).cast::<c_void>();
        Err(log3ifr_ret!(ctx,f,line!(), rv))
    }
    else {
        log3ifr!(ctx,f,line!(), SC_SUCCESS);
        Ok(())
    }
}

/* Naming
hdr:     bytes for mac_cmd/mac_resp generation, starting with 0x89, 0x04, cla, ins, p1, p2 and possibly more bytes; encapsulates the variability of cla, ins
hdr_vec: bytes for mac_cmd/mac_resp generation, if assembling bytes is more complex than just using fixed hdr

data: either plain or encrypted; input, the command data to be used in cmd/cmd_vec and mac_cmd
data_encrypted

resp: either plain or encrypted, output, command's response data to be used for Decrypting them first if applicable and mac_resp
resp_decrypted

cmd:     bytes for the APDU
cmd_vec: bytes for the APDU, if assembling bytes is more complex than just using fixed cmd

mac_cmd:
mac_resp:

*/

// TODO all code below assumes block_size is 8, i.e. using exclusively TDES for SM, which is not true anymore for ACOS5-EVO

// original APDU type (without SM): SC_APDU_CASE_2_SHORT: no command data, but expects response data (with SM, there are command data: the tagged le)
pub(crate) fn sm_common_read(card: &mut sc_card,
                      idx: u16,
                      buf: &mut [u8],
//                      count: usize,
                      flags: c_ulong,
                      bin: bool,
                      has_ct: bool,
                      fdb: u8) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = if bin {c"sm_read_binary"} else {c"sm_read_record"};
    log3if!(ctx,f,line!(), c"called with flags %zu", flags);
    if card.type_ == SC_CARD_TYPE_ACOS5_EVO_V4 {
        return evo_sm_common_read(card, idx, buf, bin, fdb);
    }

    if sm_manage_keyset(card).is_err() || sm_manage_initialize(card).is_err() {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_NOT_INITIALIZED);
    }

    /* sc_read_binary has a loop to chunk input into max. sc_get_max_recv_size(card) bytes,
       i.e. count<=255; it's okay to read less*/

//println!("sm_common_read          get_cs_mac:  {:X?}\n", get_cs_mac(card));
    assert!(buf.len()<256);
    let count = min(buf.len(), 255);
    let len_read : u8 = min(if has_ct {239} else {240}, safe_int_try_from(count));
////println!("len_read : {}", len_read);
    let len_read2 : u8 = len_read.next_multiple_of(DES_KEY_SZ_u8);// padding added if required
////println!("len_read2: {}", len_read2);
    debug_assert!(len_read2.is_multiple_of(DES_KEY_SZ_u8));
    assert!(len_read2 <= 240);
    let pos : usize = if has_ct {13} else {12};
    let len_resp = safe_int_try_from::<usize,u8>(pos) +
        if has_ct { len_read2 + if len_read.is_multiple_of(DES_KEY_SZ_u8) {DES_KEY_SZ_u8} else {0} } else { len_read };
////println!("len_resp: {}", len_resp);
    /* cmd without SM: SC_APDU_CASE_2_SHORT; with SM: SC_APDU_CASE_4_SHORT */
/*
    let hdr;
    if bin {
        hdr = [0x89u8,4, if fdb!=9 {0x0C} else {0x8C},
                         if fdb!=9 {0xB0} else {0xCA}, idx_arr[0],idx_arr[1],  0x97,1,len_read];
    }
    else {
        assert!(idx<32);
        hdr = [0x89u8,4, 0x0C, 0xB2, idx as u8,4,  0x97,1,len_read]; // there is no separate command for read sym. key record
    }
*/
    let hdr =
        if bin {
            let idx_arr : [u8; 2] = idx.to_be_bytes();
            [0x89_u8,4, if fdb==9 {0x8C} else {0x0C}, if fdb==9 {0xCA} else {0xB0}, idx_arr[0],idx_arr[1], 0x97,1,len_read]
        }
        else {
            assert!(idx<32);
            [0x89_u8,4, 0x0C, 0xB2, safe_int_try_from(idx),4,  0x97,1,len_read]
        };

////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr, &get_cs_mac(card), &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let cmd  = [hdr[2],hdr[3],hdr[4],hdr[5], 9,  hdr[6],hdr[7],hdr[8],
        0x8E,4, mac_cmd[0],mac_cmd[1],mac_cmd[2],mac_cmd[3], len_resp /*>0, otherwise arbitrary*/];
    let mut rbuf = vec![0_u8; usize::from(len_resp)];
    let mut apdu = build_apdu(ctx, &cmd, SC_APDU_CASE_4_SHORT, &mut rbuf);
    assert_eq!(apdu.le, rbuf.len());

    let mut rv = unsafe { sc_transmit_apdu(card, &raw mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), rv);
    }
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f, line!(), rv);
    }

    /* verify mac_resp */
    let mut mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    if has_ct { mac_resp_in.extend_from_slice(&[0x87_u8, len_resp - safe_int_try_from::<usize,u8>(pos-1), rbuf[pos-1]]); }
    else      { mac_resp_in.extend_from_slice(&[0x81_u8, len_read]); }
    mac_resp_in.extend_from_slice(&rbuf[pos..]);

    sm_incr_ssc(card);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), c"mac_resp verification: [%02X %02X %02X %02X]",
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] != mac_resp[..4] {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM);
    }

    if has_ct {
        ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
        let resp_decrypted = des_ede3_cbc_pad_80(&rbuf[pos..pos+usize::from(len_read2)],
                                          &get_cs_enc(card), &mut ivec, Decrypt, rbuf[pos-1]);
        assert_eq!(usize::from(len_read), resp_decrypted.len());
        assert!(resp_decrypted.len() <= count);
        buf[..usize::from(len_read)].copy_from_slice(&resp_decrypted);
    }
    else {
        buf[..usize::from(len_read)].copy_from_slice(&rbuf[pos..pos+usize::from(len_read)]);
    }

    log3ifr_ret!(ctx,f,line!(), i32::from(len_read))
}


// original APDU type (without SM): SC_APDU_CASE_3_SHORT: yes command data, but doesn't expect response data (with SM, there are response data)
pub(crate) fn sm_common_update(card: &mut sc_card,
                        idx: u16,
                        buf: &[u8],
//                        count: usize,
                        flags: c_ulong,
                        bin: bool,
                        has_ct: bool,
                        _fdb: u8) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = if bin {c"sm_update_binary"} else {c"sm_update_record"};
    log3if!(ctx,f,line!(), c"called with flags %zu", flags);
    if card.type_ == SC_CARD_TYPE_ACOS5_EVO_V4 {
        return evo_sm_common_update(card, idx, buf, flags, bin, has_ct);
    }

    if sm_manage_keyset(card).is_err() || sm_manage_initialize(card).is_err() {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_NOT_INITIALIZED);
    }

    /* sc_update_binary has a loop to chunk input into max. sc_get_max_recv_size(card) bytes, i.e. count<=255; it's okay to update less*/
//println!("sm_common_update        get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_common_update        get_cs_mac:  {:X?}\n", get_cs_mac(card));
    assert!(buf.len()<256);
    let count = min(buf.len(), 255);
    let len_update = min(if has_ct {232_u8} else {240_u8/*checked*/},safe_int_try_from(count));
////println!("len_update : {}", len_update);
    let len_update2 = len_update.next_multiple_of(DES_KEY_SZ_u8); // padding added if required
////println!("len_update2: {}", len_update2);
    debug_assert!(len_update2.is_multiple_of(DES_KEY_SZ_u8));
    assert!(len_update2 <= 240);
    let pi = u8::from(has_ct && ! len_update.is_multiple_of(DES_KEY_SZ_u8));
////println!("pi: {}", pi);
    /* cmd without SM: SC_APDU_CASE_3_SHORT; with SM: SC_APDU_CASE_4_SHORT */
    let hdr =
        if bin {
            let idx_arr : [u8; 2] = idx.to_be_bytes();
            [0x89_u8,4, 0x0C, // if fdb!=9 {0x0C} else {0x0C/ *0x8C* /}
                        0xD6, // if fdb!=9 {0xD6} else {0xD6/ *0xDA* /}
                idx_arr[0], idx_arr[1] ]
        }
        else {
            assert!(idx<32);
            [0x89_u8,4, 0x0C, if idx==0 && flags==0 {0xE2} else {0xDC},
                safe_int_try_from(idx),        if idx==0 && flags==0 {0}    else {4} ]
        };

////println!("sm_common_update ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
////println!("sm_common_update ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let data_encrypted = des_ede3_cbc_pad_80(&buf[..usize::from(len_update)],
          &get_cs_enc(card), &mut ivec, Encrypt, 0);
////println!("data_encrypted.len(): {}, data_encrypted: {:X?}", data_encrypted.len(), data_encrypted);
    assert_eq!(data_encrypted.len(), usize::from(len_update2));

    let mut hdr_vec : Vec<u8> = Vec::with_capacity(hdr.len()+ 3+ usize::from(len_update2));
    hdr_vec.extend_from_slice(&hdr);
    if has_ct {
        hdr_vec.extend_from_slice(& [0x87, 1+ len_update2, pi] );
        hdr_vec.extend_from_slice(&data_encrypted);
    }
    else {
        hdr_vec.extend_from_slice(& [0x81,    len_update] );
        hdr_vec.extend_from_slice(&buf[..usize::from(len_update)]);
    }
////println!("hdr_vec: {:X?}", hdr_vec);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac = des_ede3_cbc_pad_80_mac(&hdr_vec, &get_cs_mac(card), &mut ivec);
////println!("mac:                 {:X?}", mac);
    let mut cmd_vec : Vec<u8> = Vec::with_capacity(hdr.len()-2 +4 +usize::from(len_update2) +6 +1);
    cmd_vec.extend_from_slice(&hdr[2..]);
    if has_ct {
        cmd_vec.extend_from_slice(& [9 +len_update2, 0x87, 1 +len_update2, pi] );
        cmd_vec.extend_from_slice(&data_encrypted);
    }
    else {
        cmd_vec.extend_from_slice(& [8 +len_update,  0x81,    len_update] );
        cmd_vec.extend_from_slice(&buf[..usize::from(len_update)]);
    }
    cmd_vec.extend_from_slice(&[0x8E, 4]);
    cmd_vec.extend_from_slice(&mac[0..4]);
    cmd_vec.push(10);
////println!("cmd_vec:                 {:X?}", cmd_vec);
    let mut rbuf = vec![0_u8; 10];
    let mut apdu = build_apdu(ctx, &cmd_vec, SC_APDU_CASE_4_SHORT, &mut rbuf);
    assert_eq!(apdu.le, rbuf.len());

    let mut rv = unsafe { sc_transmit_apdu(card, &raw mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), rv);
    }

    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), rv);
    }

    /* verify mac_resp */
    let mac_resp_in = [hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(card);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), c"mac_resp verification: [%02X %02X %02X %02X]",
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] != mac_resp[..4] {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM);
    }
    log3ifr_ret!(ctx,f,line!(), i32::from(len_update))
} // sm_common_update


// original APDU type (without SM): SC_APDU_CASE_3_SHORT:
// no command data, but expects response data (with SM, there are command data: the tagged le)
pub(crate) fn sm_erase_binary(card: &mut sc_card, idx: u16, count: u16, flags: c_ulong, has_ct: bool) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = c"sm_erase_binary";
    log3if!(ctx,f,line!(), c"called with flags %zu", flags);

    if sm_manage_keyset(card).is_err() || sm_manage_initialize(card).is_err() {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_NOT_INITIALIZED);
    }

//println!("sm_erase_binary         get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_erase_binary         get_cs_mac:  {:X?}\n", get_cs_mac(card));
    /* cmd without SM: SC_APDU_CASE_2_SHORT; with SM: SC_APDU_CASE_4_SHORT */
    let idx_arr : [u8; 2] = idx.to_be_bytes();
    let hdr = [0x89_u8,4, 0x0C, 0x0E, idx_arr[0],idx_arr[1] /*,  0x97,1,len_read*/];
////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
    let mut ivec = unsafe { card.sm_ctx.info.session.cwa.ssc };
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let data_encrypted = des_ede3_cbc_pad_80(&(idx + count).to_be_bytes(),
        &get_cs_enc(card), &mut ivec, Encrypt, 0);
////println!("data_encrypted.len(): {}, data_encrypted: {:X?}", data_encrypted.len(), data_encrypted);
    assert_eq!(DES_KEY_SZ, data_encrypted.len());

    let mut hdr_vec : Vec<u8> = Vec::with_capacity(hdr.len()+ 11);
    hdr_vec.extend_from_slice(&hdr);
    if has_ct {
        hdr_vec.extend_from_slice(& [0x87, 9, 1] );
        hdr_vec.extend_from_slice(&data_encrypted);
    }
    else {
        hdr_vec.extend_from_slice(& [0x81,    2] );
        hdr_vec.extend_from_slice(& (idx + count).to_be_bytes() );
    }
////println!("hdr_vec: {:X?}", hdr_vec);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr_vec, &get_cs_mac(card), &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let mut cmd_vec : Vec<u8> = Vec::with_capacity(hdr.len()-2 +4 +8 +6 +1);
    cmd_vec.extend_from_slice(&hdr[2..]);
    if has_ct {
        cmd_vec.extend_from_slice(&[17, 0x87, 9, 1]);
        cmd_vec.extend_from_slice(&data_encrypted);
    }
    else {
        cmd_vec.extend_from_slice(&[10, 0x81, 2]);
        cmd_vec.extend_from_slice(& (idx + count).to_be_bytes() );
    }
    cmd_vec.extend_from_slice(&[0x8E, 4]);
    cmd_vec.extend_from_slice(&mac_cmd[0..4]);
    cmd_vec.push(10);
////println!("cmd_vec:                 {:X?}", cmd_vec);
    let mut rbuf = [0; 10];
    let mut apdu = build_apdu(ctx, &cmd_vec, SC_APDU_CASE_4_SHORT, &mut rbuf);
    debug_assert_eq!(apdu.le, rbuf.len());
    let mut rv = unsafe { sc_transmit_apdu(card, &raw mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), rv);
    }
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), rv);
    }

    /* verify mac_resp */
    let /*mut*/ mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(card);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), c"mac_resp verification: [%02X %02X %02X %02X]",
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] != mac_resp[..4] {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM);
    }
    rv = i32::from(count);
    log3ifr_ret!(ctx,f,line!(), rv)
} // sm_erase_binary


// original APDU type (without SM): SC_APDU_CASE_1 or SC_APDU_CASE_3_SHORT:
// Doesn't expect response data (with SM, )
pub(crate) fn sm_delete_file(card: &mut sc_card) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = c"sm_delete_file";
    log3ifc!(ctx,f,line!());

    if sm_manage_keyset(card).is_err() || sm_manage_initialize(card).is_err() {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_NOT_INITIALIZED);
    }
//println!("sm_delete_file          get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_delete_file          get_cs_mac:  {:X?}\n", get_cs_mac(card));
    /* cmd without SM: SC_APDU_CASE_1; with SM: SC_APDU_CASE_4_SHORT */
    let hdr = [0x89_u8,4, 0x0C, 0xE4, 0,0];
////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr, &get_cs_mac(card), &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let cmd  = [hdr[2],hdr[3],hdr[4],hdr[5], 6, 0x8E,4, mac_cmd[0],mac_cmd[1],mac_cmd[2],mac_cmd[3], 10];
    let mut rbuf = [0; 10];
    let mut apdu = build_apdu(ctx, &cmd, SC_APDU_CASE_4_SHORT, &mut rbuf);
    debug_assert_eq!(apdu.le, rbuf.len());
    let mut rv = unsafe { sc_transmit_apdu(card, &raw mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), rv);
    }
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), rv);
    }

    /* verify mac_resp */
    let mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(card);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), c"mac_resp verification: [%02X %02X %02X %02X]",
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] != mac_resp[..4] {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM);
    }
    log3ifr_ret!(ctx,f,line!(), rv)
} // sm_delete_file


//TODO this doesn't work for SM Confidentiality (has_ct==true)
#[expect(dead_code, reason = "no usage currently, but that will change")]
fn sm_create_file(card: &mut sc_card,
                  buf: &[u8], // starting with 0x62
                  has_ct: bool) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = c"sm_create_file";
    log3ifc!(ctx,f,line!());

    if sm_manage_keyset(card).is_err() || sm_manage_initialize(card).is_err() {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_NOT_INITIALIZED);
    }

//println!("sm_create_file          get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_create_file          get_cs_mac:  {:X?}\n", get_cs_mac(card));
//    let count = min(buf.len(), 255);
    let len_update : u8 = min(if has_ct {232_u8} else {240_u8}, safe_int_try_from(buf.len()));
    assert!(buf.len()<= usize::from(len_update));
////println!("len_update : {}", len_update);
    let len_update2 = len_update.next_multiple_of(DES_KEY_SZ_u8); // padding added if required
////println!("len_update2: {}", len_update2);
    debug_assert!(len_update2.is_multiple_of(DES_KEY_SZ_u8));
    assert!(len_update2 <= 240);
    let pi = u8::from(has_ct && ! len_update.is_multiple_of(DES_KEY_SZ_u8));
////println!("pi: {}", pi);
    /* cmd without SM: SC_APDU_CASE_3_SHORT; with SM: SC_APDU_CASE_4_SHORT */
    let hdr = [0x89_u8,4, 0x0C, 0xE0, 0, 0];
//println!("sm_common_update ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
//println!("sm_common_update ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let data_encrypted = des_ede3_cbc_pad_80(&buf[..usize::from(len_update)],
       &get_cs_enc(card), &mut ivec, Encrypt, 0);
////println!("data_encrypted.len(): {}, data_encrypted: {:X?}", data_encrypted.len(), data_encrypted);
    assert_eq!(data_encrypted.len(), usize::from(len_update2));

    let mut hdr_vec : Vec<u8> = Vec::with_capacity(hdr.len()+ 3+ usize::from(len_update2));
    hdr_vec.extend_from_slice(&hdr);
    if has_ct {
        hdr_vec.extend_from_slice(& [0x87, 1+ len_update2, pi] );
        hdr_vec.extend_from_slice(&data_encrypted);
    }
    else {
        hdr_vec.extend_from_slice(& [0x81,    len_update] );
        hdr_vec.extend_from_slice(&buf[..usize::from(len_update)]);
    }
////println!("hdr_vec: {:X?}", hdr_vec);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac = des_ede3_cbc_pad_80_mac(&hdr_vec, &get_cs_mac(card), &mut ivec);
////println!("mac:                 {:X?}", mac);
    let mut cmd_vec : Vec<u8> = Vec::with_capacity(hdr.len()-2 +4 +usize::from(len_update2) +6 +1);
    cmd_vec.extend_from_slice(&hdr[2..]);
    if has_ct {
        cmd_vec.extend_from_slice(& [9 +len_update2, 0x87, 1 +len_update2, pi] );
        cmd_vec.extend_from_slice(&data_encrypted);
    }
    else {
        cmd_vec.extend_from_slice(& [8 +len_update,  0x81,    len_update] );
        cmd_vec.extend_from_slice(&buf[..usize::from(len_update)]);
    }
    cmd_vec.extend_from_slice(&[0x8E, 4]);
    cmd_vec.extend_from_slice(&mac[0..4]);
    cmd_vec.push(10);
////println!("cmd_vec:                 {:X?}", cmd_vec);
    let mut rbuf = [0; 10];
    let mut apdu = build_apdu(ctx, &cmd_vec, SC_APDU_CASE_4_SHORT, &mut rbuf);
    assert_eq!(apdu.le, rbuf.len());
    let mut rv = unsafe { sc_transmit_apdu(card, &raw mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), rv);
    }

    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), rv);
    }

    /* verify mac_resp */
    let mac_resp_in = [hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(card);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in,
                            &get_cs_mac(card), &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    log3if!(ctx,f,line!(), c"mac_resp verification: [%02X %02X %02X %02X]",
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] != mac_resp[..4] {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM);
    }
    log3ifr_ret!(ctx,f,line!(), rv)
} // sm_create_file


#[expect(clippy::similar_names, reason = "..")]
pub(crate) fn sm_pin_cmd(card: &mut sc_card,
                  pin_cmd_data: &mut sc_pin_cmd_data,
                  tries_left: &mut i32,
                  has_ct: bool) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = c"sm_pin_cmd";
    log3if!(ctx,f,line!(), c"called for cmd: %u", pin_cmd_data.cmd);

    pin_cmd_data.pin1.tries_left = -1;
    *tries_left = pin_cmd_data.pin1.tries_left;

    if sm_manage_keyset(card).is_err() || sm_manage_initialize(card).is_err() {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_NOT_INITIALIZED);
    }

//println!("sm_pin_cmd  verify      get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_pin_cmd  verify      get_cs_mac:  {:X?}\n", get_cs_mac(card));
    let ins : u8 = match pin_cmd_data.cmd {
        SC_PIN_CMD_VERIFY  => 0x20,
        SC_PIN_CMD_CHANGE  => 0x24,
        SC_PIN_CMD_UNBLOCK => 0x2C,
        _ => unreachable!("unexpected pin command"),
    };
    let mut pin_data : Vec<u8> = Vec::with_capacity(16);
    pin_data.extend_from_slice(unsafe { from_raw_parts(pin_cmd_data.pin1.data,
        #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
            usize::try_from(pin_cmd_data.pin1.len).unwrap(),
        #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
            pin_cmd_data.pin1.len,
    ) });
    let mut len_pin : u8 = safe_int_try_from(pin_cmd_data.pin1.len);
    if ins == 0x24 || ins == 0x2C {
        len_pin *= 2;
        pin_data.extend_from_slice(unsafe { from_raw_parts(pin_cmd_data.pin2.data,
            #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                usize::try_from(pin_cmd_data.pin2.len).unwrap(),
            #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                pin_cmd_data.pin2.len,
        ) });
    }
////println!("len_pin : {}", len_pin);
    let len2_pin : u8 = len_pin.next_multiple_of(DES_KEY_SZ_u8); // padding added if required
////println!("len2_pin: {}", len2_pin);
    debug_assert!(len2_pin.is_multiple_of(DES_KEY_SZ_u8));
//    assert!(len2_pin <= DES_KEY_SZ_u8);
    let pi = u8::from(has_ct && ! len_pin.is_multiple_of(DES_KEY_SZ_u8));
////println!("pi: {}", pi);
    /* cmd without SM: SC_APDU_CASE_3_SHORT; with SM: SC_APDU_CASE_4_SHORT */
    let hdr = [0x89_u8,4, 0x0C, ins, 0, safe_int_try_from(pin_cmd_data.pin_reference)];
////println!("sm_pin_cmd ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
////println!("sm_pin_cmd ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe { card.sm_ctx.info.session.cwa.ssc };
    let data_encrypted = des_ede3_cbc_pad_80(&pin_data, &get_cs_enc(card), &mut ivec, Encrypt, 0);
////println!("data_encrypted.len(): {}, data_encrypted: {:X?}", data_encrypted.len(), data_encrypted);
    assert_eq!(data_encrypted.len(), usize::from(len2_pin));

    let mut hdr_vec : Vec<u8> = Vec::with_capacity(hdr.len()+ 3+ usize::from(len2_pin));
    hdr_vec.extend_from_slice(&hdr);
    if has_ct {
        hdr_vec.extend_from_slice(& [0x87, 1+ len2_pin, pi] );
        hdr_vec.extend_from_slice(&data_encrypted);
    }
    else {
        hdr_vec.extend_from_slice(& [0x81,    len_pin] );
        hdr_vec.extend_from_slice(&pin_data);
    }
////println!("hdr_vec: {:X?}", hdr_vec);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac = des_ede3_cbc_pad_80_mac(&hdr_vec, &get_cs_mac(card), &mut ivec);
////println!("mac:                 {:X?}", mac);
    let mut cmd_vec : Vec<u8> = Vec::with_capacity(hdr.len()-2 +4 +usize::from(len2_pin) +6 +1);
    cmd_vec.extend_from_slice(&hdr[2..]);
    if has_ct {
        cmd_vec.extend_from_slice(& [9 +len2_pin, 0x87, 1 +len2_pin, pi] );
        cmd_vec.extend_from_slice(&data_encrypted);
    }
    else {
        cmd_vec.extend_from_slice(& [8 +len_pin,  0x81,    len_pin] );
        cmd_vec.extend_from_slice(&pin_data);
    }
    cmd_vec.extend_from_slice(&[0x8E, 4]);
    cmd_vec.extend_from_slice(&mac[0..4]);
    cmd_vec.push(10);
////println!("cmd_vec:                 {:X?}", cmd_vec);
    let mut rbuf = [0; 10];
    let mut apdu = build_apdu(ctx, &cmd_vec, SC_APDU_CASE_4_SHORT, &mut rbuf);
    assert_eq!(apdu.le, rbuf.len());
    let mut rv = unsafe { sc_transmit_apdu(card, &raw mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), rv);
    }
    let mut cmd_failure = false;
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        cmd_failure = true;
        pin_cmd_data.pin1.logged_in = SC_PIN_STATE_LOGGED_OUT;
        if      rv==SC_ERROR_PIN_CODE_INCORRECT  { pin_cmd_data.pin1.tries_left = i32::from(rbuf[3]&0x0F);
                                                   *tries_left = pin_cmd_data.pin1.tries_left; }
        else if rv==SC_ERROR_AUTH_METHOD_BLOCKED { pin_cmd_data.pin1.tries_left = 0;
                                                   *tries_left = pin_cmd_data.pin1.tries_left; }
//        return log3ifr_ret!(ctx,f,line!(), rv);
    }

    /* verify mac_resp */
    let mac_resp_in = [hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, rbuf[2], rbuf[3]];
    sm_incr_ssc(card);
    ivec = unsafe { card.sm_ctx.info.session.cwa.ssc };
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
////println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), c"mac_resp verification: [%02X %02X %02X %02X]",
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if cmd_failure || rbuf[2]!=0x90 || rbuf[3]!=0 { return log3ifr_ret!(ctx,f,line!(),
        if rv == SC_SUCCESS {SC_ERROR_SM} else {rv}); }
    if rbuf[6..10] != mac_resp[..4] {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM);
    }
    pin_cmd_data.pin1.logged_in = SC_PIN_STATE_LOGGED_IN;

    log3ifr_ret!(ctx,f,line!(), rv)
}

#[named]
pub(crate) fn sm_pin_cmd_get_policy(card: &mut sc_card, ctx: &mut sc_context,
                             pin_cmd_data: &mut sc_pin_cmd_data/*, pin_reference: u8*/,
                             tries_left: &mut i32) -> Result<i32, i32>
{
    let f_cstr = CString::new(function_name!()).map_err(|_x| -1)?;
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());

    pin_cmd_data.pin1.tries_left = -1;
    *tries_left = pin_cmd_data.pin1.tries_left;

    if sm_manage_keyset(card).is_err() || sm_manage_initialize(card).is_err() {
        return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_NOT_INITIALIZED));
    }
//println!("sm_pin_cmd_get_policy   get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_pin_cmd_get_policy   get_cs_mac:  {:X?}\n", get_cs_mac(card));
    /* cmd without SM: SC_APDU_CASE_1; with SM: SC_APDU_CASE_4_SHORT */
    let hdr = [0x89_u8,4, 0x0C, 0x20, 0, safe_int_try_from(pin_cmd_data.pin_reference)];
////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
    let mut ivec = unsafe { card.sm_ctx.info.session.cwa.ssc };
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr, &get_cs_mac(card), &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let cmd  = [hdr[2],hdr[3],hdr[4],hdr[5], 6, 0x8E,4, mac_cmd[0],mac_cmd[1],mac_cmd[2],mac_cmd[3], 10];
    let mut rbuf = [0; 10];
    let mut apdu = build_apdu(ctx, &cmd, SC_APDU_CASE_4_SHORT, &mut rbuf);
    if apdu.le != rbuf.len() { return Err(log3ifr_ret!(ctx,f,line!(), -1)); }
    let mut rv = unsafe { sc_transmit_apdu(card, &raw mut apdu) };  if rv != SC_SUCCESS { return Err(log3ifr_ret!(ctx,f,line!(), rv)); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        return Err(log3ifr_ret!(ctx,f,line!(), rv));
    }

    if !(u32::from(rbuf[2]) == 0x63 && (u32::from(rbuf[3]) & 0xC0) == 0xC0) {
        log3if!(ctx,f,line!(), c"Error: 'Get remaining number of retries left for the PIN' failed");
        return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_KEYPAD_MSG_TOO_LONG));
    }


    /* verify mac_resp */
    let mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x63, rbuf[3]];
    sm_incr_ssc(card);
    ivec = unsafe { card.sm_ctx.info.session.cwa.ssc };
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
////println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), c"mac_resp verification: [%02X %02X %02X %02X]",
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] == mac_resp[..4] {
        pin_cmd_data.pin1.tries_left = i32::from(rbuf[3] & 0x0F); //  63 Cnh     n is remaining tries
        *tries_left = pin_cmd_data.pin1.tries_left;
    }
    else {
        rv = SC_ERROR_SM;
    }
    Ok(log3ifr_ret!(ctx,f,line!(), rv))
}


/*
ACOS5-EVO secure messaging, tested with a real ACOS5-EVO card.

The EVO does not use the V2/V3 3DES session key scheme; per command:
  * GET CHALLENGE (16 bytes) -> SSC; SSC+1 is the IV for command data, SSC+2 the IV for response data
  * MAC = first 4 bytes of AES-CMAC(key, pad(89 04 CLA' INS P1 P2) || pad(data objects))
    with CLA' = CLA ^ 0x0C and pad() = 0x80 00.. only if not already a multiple of 16
  * command data objects: 97 01 Le (expects response data), 81 L data (plain) or 87 L pi E(data)
  * response: [81 L data | 87 L pi E(data)] 99 02 SW1 SW2 8E 04 MAC, MAC over everything before 8E
The key is the static AES key referenced by the SE record's CCT/CT (key 82 from the card's SM configuration).
Note: the challenge is not part of the MAC, so MAC-only commands could be replayed (card design).
*/
use crate::crypto::{aes_cbc_nopad, aes_cmac, AES_BLOCK_SIZE};
use opensc_sys::types::SC_APDU_CASE_2_SHORT;

const EVO_SM_MAX_CHUNK: usize = 224; // keeps padded SM command/response data within short APDU limits

fn evo_pad(v: &mut Vec<u8>) {
    if !v.len().is_multiple_of(AES_BLOCK_SIZE) {
        v.push(0x80);
        while !v.len().is_multiple_of(AES_BLOCK_SIZE) { v.push(0); }
    }
}

fn evo_unpad(v: &[u8]) -> Option<&[u8]> {
    let end = v.iter().rposition(|&b| b != 0)?;
    if v[end] == 0x80 { Some(&v[..end]) } else { None }
}

fn evo_incr(b: &mut [u8; AES_BLOCK_SIZE]) {
    for byte in b.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 { break; }
    }
}

/// How an ACOS5-EVO command is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SmUse { Plain, Mac, MacEnc }

/// The ACOS5-EVO commands that can be sent under secure messaging. `PinStatus` is the retry counter query
/// (VERIFY without data): it sends no PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), expect(dead_code, reason = "the key and crypto commands are not sent under SM yet"))]
pub(crate) enum SmCmd { ReadFile, UpdateFile, Verify, ChangePin, Unblock, PutKey, GenerateKey, Sign, Decipher, GetKey,
                        PinStatus }

/// Decide whether a command is sent under SM, from the configured `mode`, the command's SCB and whether the
/// SE record the SCB references has a CT (`has_ct`).
///
/// SCB `4n` requires SM per SE record n; SCB `FF` (never) does not count as SM.
/// * `none`: never SM; an SCB that requires SM is an error.
/// * `acl`: SM only where the SCB requires it, encrypted if the SE record has a CT.
/// * `transmit` (strict): as `acl`, but a PIN or key command (VERIFY, CHANGE REFERENCE DATA, RESET RETRY
///   COUNTER, PUT KEY) is refused unless its SCB requires SM with an SE record that has a CT, so PINs and key
///   material never go in plain, neither as a plain APDU nor in a MAC-only `81` object. The card accepts only
///   the form its access condition dictates, so no command is forced into SM or into encryption.
///
/// # Errors
/// `SC_ERROR_SECURITY_STATUS_NOT_SATISFIED` for mode `none` with an SCB that requires SM, and for mode
/// `transmit` with a PIN or key command whose SCB does not require SM with encryption.
pub(crate) fn evo_sm_use(mode: SmMode, scb: u8, has_ct: bool, cmd: SmCmd) -> Result<SmUse, i32> {
    let required = scb != 0xFF && (scb & 0x40) == 0x40;
    let by_se = if has_ct { SmUse::MacEnc } else { SmUse::Mac };
    let secret = matches!(cmd, SmCmd::Verify | SmCmd::ChangePin | SmCmd::Unblock | SmCmd::PutKey);
    match mode {
        SmMode::None => if required { Err(SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) } else { Ok(SmUse::Plain) },
        SmMode::Acl => Ok(if required { by_se } else { SmUse::Plain }),
        SmMode::Transmit => if secret && !(required && has_ct) { Err(SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) }
                            else if required { Ok(by_se) }
                            else { Ok(SmUse::Plain) },
    }
}

/// `evo_sm_use` with the card's configured mode. When SM is required but not possible, logs one line naming
/// the card serial and the missing setting.
///
/// Mode and kmc resolve without the AID. On the first decision that is not plain while the AID is unknown
/// (the keyset entries are named after it), the AID is looked up (`evo_sm_find_aid`, SELECT only) and the
/// settings are resolved again, so the keys are final before the first SM command.
///
/// # Errors
/// As `evo_sm_config` and `evo_sm_use`; `SC_ERROR_SM_KEYSET_NOT_FOUND` if SM is to be used but no keys resolve.
pub(crate) fn evo_sm_decide(card: &mut sc_card, scb: u8, has_ct: bool, cmd: SmCmd) -> Result<SmUse, i32> {
    if card.ctx.is_null() { return Err(SC_ERROR_SM); }
    let ctx = unsafe { &mut *card.ctx };
    let f = c"evo_sm_decide";
    let mut config = evo_sm_config(card)?;
    /* SM, or mode none refusing an SM access condition (a legacy keyset found with the AID gives mode acl) */
    let needs_keys = |config: &EvoSmConfig| match evo_sm_use(config.mode, scb, has_ct, cmd) {
        Ok(SmUse::Plain) => false,
        Ok(_) => true,
        Err(_) => config.mode == SmMode::None,
    };
    if !config.aid_known && needs_keys(&config) && evo_sm_find_aid(card).map_err(|e| log3ifr_ret!(ctx,f,line!(), e))? {
        config = evo_sm_config(card)?;
    }
    let serial_c = CString::new(config.serial_hex()).unwrap_or_default();
    match evo_sm_use(config.mode, scb, has_ct, cmd) {
        Err(e) if config.mode == SmMode::Transmit => {
            log3if!(ctx,f,line!(), c"secure_messaging: card %s: mode transmit refused a PIN or key command without encryption",
                serial_c.as_ptr());
            Err(e)
        },
        Err(e) => {
            log3if!(ctx,f,line!(), c"secure_messaging: card %s: the access condition requires SM, but mode is none; set mode",
                serial_c.as_ptr());
            Err(e)
        },
        Ok(SmUse::Plain) => Ok(SmUse::Plain),
        Ok(_) if config.keys.is_none() => {
            log3if!(ctx,f,line!(), c"secure_messaging: card %s: SM is required, but no keys are set; set a keyset or kmc",
                serial_c.as_ptr());
            Err(SC_ERROR_SM_KEYSET_NOT_FOUND)
        },
        Ok(sm_use) => Ok(sm_use),
    }
}

/// The SM key (key 82, AES-192) from the card's configuration. The caller wipes it after use.
fn evo_sm_key(card: &mut sc_card) -> Result<[u8; 3*DES_KEY_SZ], i32> {
    let config = evo_sm_config(card)?;
    config.keys.as_ref().map(|keys| keys.sm).ok_or(SC_ERROR_SM_KEYSET_NOT_FOUND)
}

/// Send one command to an ACOS5-EVO under secure messaging.
/// `data`: command data (empty: the command expects `le` response bytes).
/// `encrypt`: command data as 87 (SE record has a CT) instead of plain 81.
/// Returns the number of plain response bytes written to `out`.
fn evo_sm_transmit(card: &mut sc_card, cmd: [u8; 4], data: &[u8], encrypt: bool, le: u8, out: &mut [u8])
    -> Result<usize, i32>
{
    let (len, sw) = evo_sm_transmit_sw(card, cmd, data, encrypt, le, out)?;
    let [sw1, sw2] = sw.to_be_bytes();
    let rv = unsafe { sc_check_sw(card, u32::from(sw1), u32::from(sw2)) };
    if rv != SC_SUCCESS {
        let ctx = unsafe { &mut *card.ctx };
        return Err(log3ifr_ret!(ctx, c"evo_sm_transmit", line!(), rv));
    }
    Ok(len)
}

/// As `evo_sm_transmit`, but returns the status word with the response length instead of checking it: the
/// inner SW from the 99 object, or the outer SW if the card answered without SM.
fn evo_sm_transmit_sw(card: &mut sc_card, cmd: [u8; 4], data: &[u8], encrypt: bool, le: u8, out: &mut [u8])
    -> Result<(usize, u16), i32>
{
    let mut key = evo_sm_key(card)?;
    let result = evo_sm_transmit_key(card, &key, cmd, data, encrypt, le, out);
    wipe(&mut key);
    result
}

fn evo_sm_transmit_key(card: &mut sc_card, key: &[u8; 3*DES_KEY_SZ], cmd: [u8; 4], data: &[u8], encrypt: bool, le: u8,
                       out: &mut [u8]) -> Result<(usize, u16), i32>
{
    if card.ctx.is_null() { return Err(SC_ERROR_SM); }
    let ctx = unsafe { &mut *card.ctx };
    let f = c"evo_sm_transmit";

    let mut ssc = [0_u8; AES_BLOCK_SIZE];
    let mut apdu = build_apdu(ctx, &[0, 0x84, 0, 0, 16], SC_APDU_CASE_2_SHORT, &mut ssc);
    let mut rv = unsafe { sc_transmit_apdu(card, &raw mut apdu) };  if rv != SC_SUCCESS { return Err(log3ifr_ret!(ctx,f,line!(), rv)); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen != AES_BLOCK_SIZE { return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM)); }
    evo_incr(&mut ssc);

    let cla = cmd[0] ^ 0x0C;
    let mut dos = Vec::with_capacity(data.len() + 20);
    if data.is_empty() {
        dos.extend_from_slice(&[0x97, 1, le]);
    }
    else if encrypt {
        let mut padded = data.to_vec();
        evo_pad(&mut padded);
        let pi = u8::from(padded.len() != data.len());
        let enc = aes_cbc_nopad(&padded, key, &ssc, Encrypt);
        dos.extend_from_slice(&[0x87, safe_int_try_from(enc.len() + 1), pi]);
        dos.extend_from_slice(&enc);
    }
    else {
        dos.extend_from_slice(&[0x81, safe_int_try_from(data.len())]);
        dos.extend_from_slice(data);
    }
    let mut mac_in = vec![0x89, 4, cla, cmd[1], cmd[2], cmd[3]];
    evo_pad(&mut mac_in);
    let mut dos_padded = dos.clone();
    evo_pad(&mut dos_padded);
    mac_in.extend_from_slice(&dos_padded);
    let mac = aes_cmac(&mac_in, key);

    let mut sm_cmd = vec![cla, cmd[1], cmd[2], cmd[3], safe_int_try_from(dos.len() + 6)];
    sm_cmd.extend_from_slice(&dos);
    sm_cmd.extend_from_slice(&[0x8E, 4, mac[0], mac[1], mac[2], mac[3], 0]);
    let mut rbuf = [0_u8; 256];
    let mut apdu = build_apdu(ctx, &sm_cmd, SC_APDU_CASE_4_SHORT, &mut rbuf);
    rv = unsafe { sc_transmit_apdu(card, &raw mut apdu) };  if rv != SC_SUCCESS { return Err(log3ifr_ret!(ctx,f,line!(), rv)); }
    if (apdu.sw1, apdu.sw2) != (0x90, 0) {
        return Ok((0, u16::from_be_bytes([safe_int_try_from(apdu.sw1), safe_int_try_from(apdu.sw2)])));
    }

    let resp = &rbuf[..apdu.resplen];
    if resp.len() < 10 || resp[resp.len()-6..resp.len()-4] != [0x8E, 4] {
        return Err(log3ifr_ret!(ctx,f,line!(), c"Error: SM response without MAC", SC_ERROR_SM));
    }
    let body = &resp[..resp.len()-6];
    let mut body_padded = body.to_vec();
    evo_pad(&mut body_padded);
    if aes_cmac(&body_padded, key)[..4] != resp[resp.len()-4..] {
        return Err(log3ifr_ret!(ctx,f,line!(), c"Error: SM response MAC mismatch", SC_ERROR_SM));
    }
    evo_incr(&mut ssc);

    let mut plain_len = 0_usize;
    let mut inner_sw: Option<(u8, u8)> = None;
    let mut i = 0_usize;
    while i + 2 <= body.len() {
        let (tag, len) = (body[i], usize::from(body[i+1]));
        if i + 2 + len > body.len() { return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM)); }
        let val = &body[i+2..i+2+len];
        match tag {
            0x81 => {
                if val.len() > out.len() { return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM)); }
                out[..val.len()].copy_from_slice(val);
                plain_len = val.len();
            },
            0x87 => {
                if val.is_empty() || !(val.len()-1).is_multiple_of(AES_BLOCK_SIZE) { return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM)); }
                let dec = aes_cbc_nopad(&val[1..], key, &ssc, Decrypt);
                let plain = if val[0] == 1 { evo_unpad(&dec).ok_or(SC_ERROR_SM)? } else { &dec[..] };
                if plain.len() > out.len() { return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM)); }
                out[..plain.len()].copy_from_slice(plain);
                plain_len = plain.len();
            },
            0x99 if len == 2 => inner_sw = Some((val[0], val[1])),
            _ => {},
        }
        i += 2 + len;
    }
    let Some((sw1, sw2)) = inner_sw else { return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM)); };
    Ok((plain_len, u16::from_be_bytes([sw1, sw2])))
}

/// Map the status word of a PIN command: `90 00` success, `63 Cx` wrong PIN with x tries left (also set in
/// `tries_left`), `69 83` blocked (`tries_left` 0). Any other SW gives `SC_ERROR_CARD_CMD_FAILED`.
fn map_inner_sw(sw: u16, tries_left: &mut i32) -> i32 {
    match sw {
        0x9000 => SC_SUCCESS,
        0x63C0..=0x63CF => { *tries_left = i32::from(sw & 0x0F); SC_ERROR_PIN_CODE_INCORRECT },
        0x6983 => { *tries_left = 0; SC_ERROR_AUTH_METHOD_BLOCKED },
        _ => SC_ERROR_CARD_CMD_FAILED,
    }
}

/// VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER or the retry counter query (VERIFY without data, sent
/// as `97 01 00`) on an ACOS5-EVO under SM. `encrypt`: PIN data as 87 (SE record has a CT) instead of 81.
/// Sets `tries_left` (and `pin1.tries_left`) from a `63 Cx` answer; for the query, `63 Cx` is success.
///
/// # Errors
/// As `evo_sm_transmit`; `SC_ERROR_PIN_CODE_INCORRECT`, `SC_ERROR_AUTH_METHOD_BLOCKED` or the mapped SW if
/// the card refuses the command.
pub(crate) fn evo_sm_pin_cmd(card: &mut sc_card, data: &mut sc_pin_cmd_data, tries_left: &mut i32, encrypt: bool)
    -> Result<i32, i32>
{
    if card.ctx.is_null() { return Err(SC_ERROR_SM); }
    let ctx = unsafe { &mut *card.ctx };
    let f = c"evo_sm_pin_cmd";
    log3if!(ctx,f,line!(), c"called for cmd: %u", data.cmd);
    let ins = match data.cmd {
        SC_PIN_CMD_GET_INFO | SC_PIN_CMD_VERIFY => 0x20,
        SC_PIN_CMD_CHANGE  => 0x24,
        SC_PIN_CMD_UNBLOCK => 0x2C,
        _ => return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT)),
    };
    /* PIN data encoded and padded as the plain ISO command would send it */
    let mut pin_data = [0_u8; 64];
    let mut pin_len = 0_usize;
    if data.cmd != SC_PIN_CMD_GET_INFO {
        let pad = i32::from((data.flags & SC_PIN_CMD_NEED_PADDING) != 0);
        let pins: &mut [&mut sc_pin_cmd_pin] = if ins == 0x20 { &mut [&mut data.pin1] }
                                               else { &mut [&mut data.pin1, &mut data.pin2] };
        for pin in pins {
            let buf = &mut pin_data[pin_len..];
            let rv = unsafe { sc_build_pin(buf.as_mut_ptr(), buf.len(), &raw mut **pin, pad) };
            if rv <= 0 {
                wipe(&mut pin_data);
                return Err(log3ifr_ret!(ctx,f,line!(), if rv < 0 { rv } else { SC_ERROR_INVALID_ARGUMENTS }));
            }
            pin_len += safe_int_try_from::<i32, usize>(rv);
        }
    }
    data.pin1.tries_left = -1;
    *tries_left = -1;
    let mut dummy = [0_u8; 0];
    let cmd = [0, ins, 0, safe_int_try_from(data.pin_reference)];
    let result = evo_sm_transmit_sw(card, cmd, &pin_data[..pin_len], encrypt, 0, &mut dummy);
    wipe(&mut pin_data);
    let (_, sw) = result.map_err(|e| log3ifr_ret!(ctx,f,line!(), e))?;
    let mut rv = map_inner_sw(sw, tries_left);
    data.pin1.tries_left = *tries_left;
    if rv == SC_ERROR_CARD_CMD_FAILED {
        let [sw1, sw2] = sw.to_be_bytes();
        rv = unsafe { sc_check_sw(card, u32::from(sw1), u32::from(sw2)) };
    }
    if data.cmd == SC_PIN_CMD_GET_INFO && rv == SC_ERROR_PIN_CODE_INCORRECT {
        data.pin1.logged_in = SC_PIN_STATE_LOGGED_OUT;
        rv = SC_SUCCESS;
    }
    else {
        data.pin1.logged_in = if rv == SC_SUCCESS { SC_PIN_STATE_LOGGED_IN } else { SC_PIN_STATE_LOGGED_OUT };
    }
    if rv == SC_SUCCESS { Ok(log3ifr_ret!(ctx,f,line!(), rv)) } else { Err(log3ifr_ret!(ctx,f,line!(), rv)) }
}

/* key EFs (FDB 09, 19) are read with GET KEY 80 CA, other files with READ BINARY / READ RECORD */
fn evo_sm_common_read(card: &mut sc_card, idx: u16, buf: &mut [u8], bin: bool, fdb: u8) -> i32 {
    if card.ctx.is_null() { return SC_ERROR_SM; }
    let ctx = unsafe { &mut *card.ctx };
    let key_ef = bin && [FDB_RSA_KEY_EF, FDB_ECC_KEY_EF].contains(&fdb);
    let f = if key_ef {c"evo_sm_get_key"} else if bin {c"evo_sm_read_binary"} else {c"evo_sm_read_record"};
    let count = min(buf.len(), EVO_SM_MAX_CHUNK);
    let cmd = if key_ef { let [hi, lo] = idx.to_be_bytes(); [0x80, 0xCA, hi, lo] }
              else if bin { let [hi, lo] = idx.to_be_bytes(); [0, 0xB0, hi, lo] }
              else   { [0, 0xB2, safe_int_try_from(idx), 4] };
    match evo_sm_transmit(card, cmd, &[], false, safe_int_try_from(count), &mut buf[..count]) {
        Ok(n)  => log3ifr_ret!(ctx,f,line!(), safe_int_try_from::<usize, i32>(n)),
        Err(e) => log3ifr_ret!(ctx,f,line!(), e),
    }
}

/* `encrypt`: the command data go as 87 (SmUse::MacEnc) */
fn evo_sm_common_update(card: &mut sc_card, idx: u16, buf: &[u8], flags: c_ulong, bin: bool, encrypt: bool) -> i32 {
    if card.ctx.is_null() { return SC_ERROR_SM; }
    let ctx = unsafe { &mut *card.ctx };
    let f = if bin {c"evo_sm_update_binary"} else {c"evo_sm_update_record"};
    let count = min(buf.len(), EVO_SM_MAX_CHUNK);
    let cmd = if bin { let [hi, lo] = idx.to_be_bytes(); [0, 0xD6, hi, lo] }
              else if idx == 0 && flags == 0 { [0, 0xE2, 0, 0] }
              else   { [0, 0xDC, safe_int_try_from(idx), 4] };
    let mut dummy = [0_u8; 0];
    match evo_sm_transmit(card, cmd, &buf[..count], encrypt, 0, &mut dummy) {
        Ok(_)  => log3ifr_ret!(ctx,f,line!(), safe_int_try_from::<usize, i32>(count)),
        Err(e) => log3ifr_ret!(ctx,f,line!(), e),
    }
}

#[cfg(test)]
mod tests_evo_sm {
    use opensc_sys::errors::SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
    use crate::sm_config::SmMode;
    use opensc_sys::errors::{SC_ERROR_AUTH_METHOD_BLOCKED, SC_ERROR_PIN_CODE_INCORRECT, SC_SUCCESS};
    use super::{evo_incr, evo_pad, evo_unpad, evo_sm_use, map_inner_sw, SmCmd, SmUse};

    #[test]
    fn pin_inner_sw_maps_tries_left() {
        let mut tries_left = -1;
        assert_eq!(SC_ERROR_PIN_CODE_INCORRECT, map_inner_sw(0x63C2, &mut tries_left));
        assert_eq!(2, tries_left);
        assert_eq!(SC_ERROR_AUTH_METHOD_BLOCKED, map_inner_sw(0x6983, &mut tries_left));
        assert_eq!(0, tries_left);
        tries_left = -1;
        assert_eq!(SC_SUCCESS, map_inner_sw(0x9000, &mut tries_left));
        assert_eq!(-1, tries_left);
    }

    #[test]
    fn evo_sm_use_table() {
        use SmUse::{Plain as P, Mac as M, MacEnc as E};
        const CMDS: [SmCmd; 11] = [SmCmd::ReadFile, SmCmd::UpdateFile, SmCmd::Verify, SmCmd::ChangePin, SmCmd::Unblock,
                                   SmCmd::PutKey, SmCmd::GenerateKey, SmCmd::Sign, SmCmd::Decipher, SmCmd::GetKey,
                                   SmCmd::PinStatus];
        const ERR: Result<SmUse, i32> = Err(SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
        /* SCB 45: SE record 5 (CCT only), SCB 46: SE record 6 (CCT and CT) */
        let rows: [(SmMode, u8, bool, [Result<SmUse, i32>; 11]); 12] = [
            //                           Read   Update Verify ChgPin Unblk  PutKey GenKey Sign   Decip  GetKey PinSt
            (SmMode::None,     0x00, false, [Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P)]),
            (SmMode::None,     0x01, false, [Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P)]),
            (SmMode::None,     0x45, false, [ERR,   ERR,   ERR,   ERR,   ERR,   ERR,   ERR,   ERR,   ERR,   ERR,   ERR  ]),
            (SmMode::None,     0x46, true,  [ERR,   ERR,   ERR,   ERR,   ERR,   ERR,   ERR,   ERR,   ERR,   ERR,   ERR  ]),
            (SmMode::Acl,      0x00, false, [Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P)]),
            (SmMode::Acl,      0x01, false, [Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P), Ok(P)]),
            (SmMode::Acl,      0x45, false, [Ok(M), Ok(M), Ok(M), Ok(M), Ok(M), Ok(M), Ok(M), Ok(M), Ok(M), Ok(M), Ok(M)]),
            (SmMode::Acl,      0x46, true,  [Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E)]),
            (SmMode::Transmit, 0x00, false, [Ok(P), Ok(P), ERR,   ERR,   ERR,   ERR,   Ok(P), Ok(P), Ok(P), Ok(P), Ok(P)]),
            (SmMode::Transmit, 0x01, false, [Ok(P), Ok(P), ERR,   ERR,   ERR,   ERR,   Ok(P), Ok(P), Ok(P), Ok(P), Ok(P)]),
            (SmMode::Transmit, 0x45, false, [Ok(M), Ok(M), ERR,   ERR,   ERR,   ERR,   Ok(M), Ok(M), Ok(M), Ok(M), Ok(M)]),
            (SmMode::Transmit, 0x46, true,  [Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E), Ok(E)]),
        ];
        for (mode, scb, has_ct, expected) in rows {
            for (cmd, want) in CMDS.into_iter().zip(expected) {
                assert_eq!(evo_sm_use(mode, scb, has_ct, cmd), want, "mode {mode:?}, SCB {scb:02X}, {cmd:?}");
            }
        }
        /* SCB FF is NEVER, not SM with SE record 0F: no SM decision error for it */
        assert_eq!(evo_sm_use(SmMode::None, 0xFF, false, SmCmd::ReadFile), Ok(P));
        assert_eq!(evo_sm_use(SmMode::Transmit, 0xFF, false, SmCmd::Verify), ERR);
    }

    #[test]
    fn transmit_pin_status_not_secret() {
        /* the retry counter query sends no PIN: allowed in plain and MAC-only in mode transmit */
        assert_eq!(evo_sm_use(SmMode::Transmit, 0x45, false, SmCmd::PinStatus), Ok(SmUse::Mac));
        assert_eq!(evo_sm_use(SmMode::Transmit, 0x01, false, SmCmd::PinStatus), Ok(SmUse::Plain));
        assert_eq!(evo_sm_use(SmMode::Transmit, 0x46, true, SmCmd::PinStatus), Ok(SmUse::MacEnc));
        /* VERIFY with the same MAC-only SE record is refused */
        assert_eq!(evo_sm_use(SmMode::Transmit, 0x45, false, SmCmd::Verify), Err(SC_ERROR_SECURITY_STATUS_NOT_SATISFIED));
    }

    #[test]
    fn padding_and_ssc() {
        let mut v = vec![1_u8; 14];
        evo_pad(&mut v);
        assert_eq!(16, v.len());
        assert_eq!(&[1_u8; 14][..], evo_unpad(&v).unwrap());
        let mut w = vec![1_u8; 16];
        evo_pad(&mut w);
        assert_eq!(16, w.len()); // no padding block for complete blocks
        let mut ssc = [0_u8; 16];
        ssc[15] = 0xFF;
        evo_incr(&mut ssc);
        assert_eq!([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0], ssc);
    }
}
