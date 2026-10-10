//! TOTP (RFC 6238) — the first approver factor for human approvals
//! (roadmap S6.3).
//!
//! HMAC-SHA1, 6 digits, 30-second steps: what every authenticator app
//! does by default with an `otpauth://totp/…` URI that names nothing else.
//! A code is accepted for the current step and one step either side
//! (clock skew); the caller makes it single-use by refusing any step at
//! or below the last one accepted (`crate::approvers`).

use hmac::{Hmac, Mac};
use sha1::Sha1;

/// Seconds per step.
pub const STEP_SECS: u64 = 30;
/// Digits per code.
pub const DIGITS: u32 = 6;
/// Steps accepted either side of the current one.
pub const SKEW_STEPS: u64 = 1;
/// Length of a minted secret, in bytes (RFC 4226 recommends 160 bits).
pub const SECRET_LEN: usize = 20;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, no padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// RFC 4648 base32, case-insensitive, padding and spaces ignored (as
/// authenticator apps show secrets in groups).
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !matches!(c, ' ' | '=' | '-')) {
        let v = B32
            .iter()
            .position(|&x| x as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// HOTP (RFC 4226) value for `counter`, `DIGITS` long.
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(DIGITS)
}

/// The step containing unix time `now`.
pub fn step_at(now: u64) -> u64 {
    now / STEP_SECS
}

/// The code for `now`, zero-padded — for tests and scripts.
pub fn code_at(secret: &[u8], now: u64) -> String {
    format!(
        "{:0width$}",
        hotp(secret, step_at(now)),
        width = DIGITS as usize
    )
}

/// The step `code` is valid for at `now` (current ± [`SKEW_STEPS`]), if
/// any. Every candidate is computed and compared in constant time, so
/// the time taken doesn't say which step (if any) matched.
pub fn matching_step(secret: &[u8], code: &str, now: u64) -> Option<u64> {
    use subtle::ConstantTimeEq;
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now_step = step_at(now);
    let mut found = None;
    for step in now_step.saturating_sub(SKEW_STEPS)..=now_step + SKEW_STEPS {
        let want = format!("{:0width$}", hotp(secret, step), width = DIGITS as usize);
        if bool::from(want.as_bytes().ct_eq(code.as_bytes())) && found.is_none() {
            found = Some(step);
        }
    }
    found
}

/// A fresh random secret.
pub fn mint_secret() -> anyhow::Result<Vec<u8>> {
    let mut s = vec![0u8; SECRET_LEN];
    getrandom::fill(&mut s).map_err(|e| anyhow::anyhow!("OS random source failed: {e}"))?;
    Ok(s)
}

/// The `otpauth://` URI an authenticator app enrolls from.
pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        enc(issuer),
        enc(account),
        base32_encode(secret),
        enc(issuer)
    )
}

/// `uri` as a QR code drawn with Unicode half blocks, for a terminal.
pub fn qr_terminal(uri: &str) -> Option<String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(uri.as_bytes()).ok()?;
    Some(
        code.render::<Dense1x2>()
            .dark_color(Dense1x2::Light)
            .light_color(Dense1x2::Dark)
            .quiet_zone(true)
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B, SHA1 rows (8-digit values; the 6-digit code
    /// is the last six digits).
    #[test]
    fn rfc6238_vectors() {
        let secret = b"12345678901234567890";
        for (t, eight) in [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(code_at(secret, t), eight[2..], "t={t}");
        }
    }

    #[test]
    fn base32_round_trips_and_matches_rfc4648() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_decode("mzxw 6ytb oi==").unwrap(), b"foobar");
        assert_eq!(base32_decode("MZXW6YTBO1"), None); // '1' isn't base32
        let s = mint_secret().unwrap();
        assert_eq!(base32_decode(&base32_encode(&s)).unwrap(), s);
    }

    #[test]
    fn window_is_one_step_either_side() {
        let secret = b"12345678901234567890";
        let now = 1_000_000_000;
        let step = step_at(now);
        for (d, ok) in [(-2i64, false), (-1, true), (0, true), (1, true), (2, false)] {
            let code = code_at(secret, (now as i64 + d * STEP_SECS as i64) as u64);
            let got = matching_step(secret, &code, now);
            if ok {
                assert_eq!(got, Some((step as i64 + d) as u64), "offset {d}");
            } else {
                assert_eq!(got, None, "offset {d}");
            }
        }
        assert_eq!(matching_step(secret, "12345", now), None);
        assert_eq!(matching_step(secret, "abcdef", now), None);
    }

    #[test]
    fn uri_carries_the_secret_and_defaults() {
        let uri = otpauth_uri("prompto sbx", "nico@x", b"foobar");
        assert_eq!(
            uri,
            "otpauth://totp/prompto%20sbx:nico%40x?secret=MZXW6YTBOI&issuer=prompto%20sbx\
             &algorithm=SHA1&digits=6&period=30"
        );
        assert!(qr_terminal(&uri).is_some());
    }
}
