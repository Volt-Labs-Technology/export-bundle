//! Canonical JSON, and the hash taken over it.
//!
//! Two documents that say the same thing must hash the same, and two that
//! differ anywhere must not. Serialisers are free to order keys and space
//! things as they like, so a hash is only meaningful over one agreed
//! spelling. This module is that spelling, and everything in it is a
//! calculation: text in, text out, no clock and no disk.
//!
//! The rules, in full:
//!
//! * Object keys are sorted, at every depth.
//! * No whitespace anywhere outside a string.
//! * Array order is content and is left alone.
//! * An integer is written without a point; a float is written with one, in
//!   Rust's shortest round-tripping form. `1` and `1.0` are therefore
//!   different documents, which is the honest answer: a count and a measured
//!   quantity are not the same fact.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Number, Value};
use sha2::{Digest as _, Sha256};

/// One document, one spelling. **Calculation.**
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

/// The SHA-256 of some bytes, lowercase hex. **Calculation.**
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut hex, byte| {
            // `write!` to a String cannot fail; the fold keeps the one
            // allocation rather than growing a Vec of two-character strings.
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// The SHA-256 of a document's canonical form. **Calculation.**
#[must_use]
pub fn digest(value: &Value) -> String {
    sha256_hex(canonical_json(value).as_bytes())
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(yes) => out.push_str(if *yes { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&write_number(number)),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => write_array(out, items),
        Value::Object(members) => write_object(out, members),
    }
}

fn write_array(out: &mut String, items: &[Value]) {
    out.push('[');
    for (position, item) in items.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        write_value(out, item);
    }
    out.push(']');
}

fn write_object(out: &mut String, members: &serde_json::Map<String, Value>) {
    let sorted: BTreeMap<&str, &Value> = members
        .iter()
        .map(|(key, value)| (key.as_str(), value))
        .collect();
    out.push('{');
    for (position, (key, value)) in sorted.into_iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        write_string(out, key);
        out.push(':');
        write_value(out, value);
    }
    out.push('}');
}

/// A string, escaped as JSON escapes one.
///
/// `Display` for a JSON string is that escaping rule itself; a hand-rolled
/// one here would be a second, worse copy of it.
fn write_string(out: &mut String, text: &str) {
    out.push_str(&Value::String(text.to_owned()).to_string());
}

/// A number in its one canonical spelling. **Calculation.**
///
/// A float that is not finite cannot be JSON at all — `serde_json` refuses to
/// build one — so the fallback is unreachable through any document this crate
/// can produce, and says `null` rather than inventing a number.
fn write_number(number: &Number) -> String {
    if let Some(whole) = number.as_i64() {
        return whole.to_string();
    }
    if let Some(whole) = number.as_u64() {
        return whole.to_string();
    }
    number.as_f64().map_or_else(
        || "null".to_owned(),
        |float| {
            let text = format!("{float:?}");
            if text.contains(['.', 'e', 'E']) {
                text
            } else {
                format!("{text}.0")
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(text: &str) -> Value {
        serde_json::from_str(text).expect("the test document is JSON")
    }

    #[test]
    fn keys_are_sorted_at_every_depth_and_nothing_is_spaced() {
        let document = parse(r#"{"b": {"z": 1, "a": 2}, "a": [3, 4]}"#);

        assert_eq!(
            canonical_json(&document),
            r#"{"a":[3,4],"b":{"a":2,"z":1}}"#
        );
    }

    #[test]
    fn the_same_map_written_two_ways_hashes_the_same() {
        let one = parse(r#"{"bill": 1.5, "label": "a run", "late": 2}"#);
        let other = parse(r#"{"late": 2, "label": "a run", "bill": 1.5}"#);

        assert_eq!(digest(&one), digest(&other));
    }

    #[test]
    fn changing_one_float_changes_the_hash() {
        let before = json!({ "bill": 44_028.42 });
        let after = json!({ "bill": 44_028.43 });

        assert_ne!(digest(&before), digest(&after));
    }

    #[test]
    fn array_order_is_content_and_is_not_sorted() {
        assert_ne!(digest(&json!([1, 2])), digest(&json!([2, 1])));
    }

    #[test]
    fn a_count_and_a_measured_quantity_are_different_documents() {
        assert_eq!(canonical_json(&json!({ "n": 1 })), r#"{"n":1}"#);
        assert_eq!(canonical_json(&json!({ "n": 1.0 })), r#"{"n":1.0}"#);
    }

    #[test]
    fn strings_keep_the_escaping_json_requires() {
        let document = json!({ "note": "a \"quoted\" line\n" });

        assert_eq!(
            canonical_json(&document),
            r#"{"note":"a \"quoted\" line\n"}"#
        );
    }

    #[test]
    fn a_key_that_needs_escaping_is_escaped_too() {
        let document = parse(r#"{"a\"b": 1}"#);

        assert_eq!(canonical_json(&document), r#"{"a\"b":1}"#);
    }

    #[test]
    fn null_and_the_two_booleans_are_written_as_json_spells_them() {
        assert_eq!(
            canonical_json(&json!({ "a": null, "b": true, "c": false })),
            r#"{"a":null,"b":true,"c":false}"#
        );
    }

    /// FIPS 180-2 vector for SHA-256 of `"abc"`.
    #[test]
    fn sha256_of_abc_is_the_published_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_of_nothing_is_the_published_empty_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
