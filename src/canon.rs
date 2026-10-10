//! Canonical JSON (RFC 8785, "JCS") and the arguments digest a ticket is
//! bound to (roadmap S6.1).
//!
//! A ticket says "this exact call": prompto hashes the call's arguments
//! when it mints the ticket and again when the call arrives, and the two
//! must agree although the client (the Claude Code mod, a script, `jq`)
//! may have re-serialized the object in between. So the hash is taken
//! over a canonical form that any client can reproduce with an
//! off-the-shelf RFC 8785 library:
//!
//! - objects: members sorted by key, compared as UTF-16 code units; no
//!   whitespace anywhere;
//! - strings: `"` and `\` escaped, U+0008/0009/000A/000C/000D as
//!   `\b \t \n \f \r`, every other control character below U+0020 as
//!   `\u00xx` (lowercase hex); everything else (non-ASCII, U+2028, DEL)
//!   as literal UTF-8;
//! - numbers: as ECMAScript's `Number.prototype.toString` prints the
//!   IEEE-754 double (`1`, `4.5`, `1e+21`, `1e-7`, `-0` → `0`). Integers
//!   beyond 2^53 lose precision exactly as they would in JavaScript;
//! - `true`, `false`, `null` as such.
//!
//! [`args_sha256`] is SHA-256 over the canonical form of the arguments
//! object **without its top-level `ticket` member** (a ticket can't hash
//! itself), lowercase hex. Absent arguments hash as `{}`, so a hostless
//! tool called with `null` or `{}` gets the same digest.

use serde_json::Value;
use std::fmt::Write;

/// The RFC 8785 canonical form of `v`.
pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, v);
    out
}

/// SHA-256 (hex) of the canonical arguments, minus a top-level `ticket`.
pub fn args_sha256(args: &Value) -> String {
    let stripped = without_ticket(args);
    crate::agent::hex(&crate::agent::sha256(canonical(&stripped).as_bytes()))
}

/// `args` without its top-level `ticket` member; `null` becomes `{}`.
pub fn without_ticket(args: &Value) -> Value {
    match args {
        Value::Null => Value::Object(Default::default()),
        Value::Object(m) => {
            let mut m = m.clone();
            m.remove("ticket");
            Value::Object(m)
        }
        other => other.clone(),
    }
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, x);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<(&String, Vec<u16>)> =
                m.keys().map(|k| (k, k.encode_utf16().collect())).collect();
            keys.sort_by(|a, b| a.1.cmp(&b.1));
            out.push('{');
            for (i, (k, _)) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, &m[k.as_str()]);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(out: &mut String, n: &serde_json::Number) {
    // Every JSON number is an IEEE-754 double to JCS. serde_json never
    // holds NaN or infinity.
    let f = n.as_f64().unwrap_or(0.0);
    out.push_str(&es_number(f));
}

/// ECMAScript `Number::toString(x)` for a finite double.
fn es_number(x: f64) -> String {
    if x == 0.0 {
        return "0".into(); // also -0
    }
    let sign = if x < 0.0 { "-" } else { "" };
    // `{:e}` prints the shortest digits that round-trip, as ES requires:
    // `d[.ddd]e<exp>`.
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e').expect("{:e} has an exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    // x = 0.d1d2…dk × 10^n
    let n = exp.parse::<i32>().expect("{:e} exponent") + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let e = if e >= 0 {
            format!("+{e}")
        } else {
            e.to_string()
        };
        if k == 1 {
            format!("{digits}e{e}")
        } else {
            format!("{}.{}e{e}", &digits[..1], &digits[1..])
        }
    };
    format!("{sign}{body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// RFC 8785 §3.2.3: key order by UTF-16 code units, which puts the
    /// emoji (a surrogate pair, 0xD83D…) before U+FB33 although its code
    /// point is larger. Plain byte or `char` order would not.
    #[test]
    fn keys_sort_by_utf16_code_units() {
        let v: Value = serde_json::from_str(
            r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#,
        )
        .unwrap();
        let keys: Vec<String> = {
            let c = canonical(&v);
            let back: serde_json::Map<String, Value> = serde_json::from_str(&c).unwrap();
            back.keys().cloned().collect()
        };
        assert_eq!(
            keys,
            [
                "\r",
                "1",
                "\u{80}",
                "\u{f6}",
                "\u{20ac}",
                "\u{1f600}",
                "\u{fb33}"
            ]
        );
    }

    /// RFC 8785 Appendix B number samples (and a few more).
    #[test]
    fn numbers_print_like_ecmascript() {
        for (bits, want) in [
            (0x0000000000000000u64, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x4630000000000000, "1.2676506002282294e+30"),
        ] {
            assert_eq!(es_number(f64::from_bits(bits)), want, "{bits:#x}");
        }
        assert_eq!(es_number(4.5), "4.5");
        assert_eq!(es_number(0.002), "0.002");
        assert_eq!(es_number(1e-7), "1e-7");
        assert_eq!(es_number(123e18), "123000000000000000000");
        assert_eq!(es_number(-30.0), "-30");
    }

    #[test]
    fn strings_escape_only_what_jcs_escapes() {
        let v = json!("a\"b\\c\u{8}\t\n\u{c}\r\u{1f}\u{7f}é\u{2028}/");
        assert_eq!(
            canonical(&v),
            "\"a\\\"b\\\\c\\b\\t\\n\\f\\r\\u001f\u{7f}é\u{2028}/\""
        );
    }

    /// RFC 8785 §3.2.4 example, end to end.
    #[test]
    fn rfc8785_sample() {
        let v: Value = serde_json::from_str(
            r#"{
              "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
              "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
              "literals": [null, true, false]
            }"#,
        )
        .unwrap();
        assert_eq!(
            canonical(&v),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
    }

    #[test]
    fn digest_ignores_ticket_order_and_whitespace() {
        let a: Value =
            serde_json::from_str(r#"{"host":"t1","cmd":"id","timeout_secs":5}"#).unwrap();
        let b: Value = serde_json::from_str(
            r#"{ "timeout_secs" : 5.0, "ticket": "pt1.x", "cmd": "id", "host": "t1" }"#,
        )
        .unwrap();
        assert_eq!(args_sha256(&a), args_sha256(&b));
        // Any other change is a different call.
        let c = json!({ "host": "t1", "cmd": "id ", "timeout_secs": 5 });
        assert_ne!(args_sha256(&a), args_sha256(&c));
        // A `ticket` nested deeper is an argument like any other.
        let d = json!({ "host": "t1", "cmd": "id", "timeout_secs": 5, "x": { "ticket": 1 } });
        assert_ne!(args_sha256(&a), args_sha256(&d));
        assert_eq!(args_sha256(&Value::Null), args_sha256(&json!({})));
        assert_eq!(
            args_sha256(&json!({ "ticket": "t" })),
            args_sha256(&json!({}))
        );
    }

    /// A known digest, so a client implementation can check itself
    /// against this one (also quoted in the README).
    #[test]
    fn digest_test_vector() {
        let args = json!({ "host": "sbx-t2", "cmd": "id -u", "ticket": "ignored" });
        assert_eq!(
            canonical(&without_ticket(&args)),
            r#"{"cmd":"id -u","host":"sbx-t2"}"#
        );
        assert_eq!(
            args_sha256(&args),
            crate::agent::hex(&crate::agent::sha256(br#"{"cmd":"id -u","host":"sbx-t2"}"#))
        );
    }
}
