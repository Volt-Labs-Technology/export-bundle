//! `manifest.json`: what a bundle contains, so it can be checked later.
//!
//! A bundle is a directory of CSV files beside a manifest, and the manifest
//! is how anyone downstream answers two questions without the exporter's
//! help: which files were in it, and are these still those bytes. So every
//! entry carries a name, a SHA-256 and a row count.
//!
//! The document is written as *canonical* JSON: object keys sorted at every
//! depth, no whitespace outside a string. Two spellings of one document
//! would hash differently, so the manifest fixes one spelling for itself.
//!
//! `created_at` is the one wall-clock value, and it is the caller's to
//! supply: this crate never reads a clock. [`Manifest`] ignores it when
//! compared, so two bundles of the same bytes made a month apart are equal —
//! equality means "these files", never "this afternoon".
//!
//! The manifest also records, per file, which columns the allow-list left
//! behind. The recipient can then see for themselves that the export was
//! wider than the bundle, and by exactly which columns.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// One file in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// The name the file has inside the bundle.
    pub name: String,
    /// SHA-256 of its bytes, lowercase hex.
    pub sha256: String,
    /// Data rows, header excluded.
    pub rows: usize,
    /// Columns the allow-list dropped, in the header's own order.
    ///
    /// Reported rather than silently removed: a file that carried more than
    /// its allow-list is something the recipient should see.
    #[serde(default)]
    pub dropped: Vec<String>,
}

/// What one bundle contains.
///
/// The whole document is a calculation over values the caller already has,
/// so two bundles of the same files compare equal whoever ran them. Only
/// `created_at` is left out of the comparison: it says when, not what.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// One entry per bundled file, in the order the bundle wrote them.
    pub files: Vec<FileEntry>,
    /// When the bundle was made, as the caller supplied it.
    ///
    /// The only wall-clock value in a bundle, and the only field that
    /// comparison ignores.
    pub created_at: String,
    /// The version of the tool that wrote it.
    pub tool_version: String,
    /// Free-form facts the caller attached: a window, a label, anything.
    pub meta: BTreeMap<String, String>,
    /// Columns left behind, per file, for files that carried extras.
    #[serde(default)]
    pub dropped: BTreeMap<String, Vec<String>>,
}

impl PartialEq for Manifest {
    fn eq(&self, other: &Self) -> bool {
        self.files == other.files
            && self.tool_version == other.tool_version
            && self.meta == other.meta
            && self.dropped == other.dropped
    }
}

impl Eq for Manifest {}

impl Manifest {
    /// The manifest as one file's worth of canonical JSON. **Calculation.**
    ///
    /// # Errors
    /// A [`serde_json::Error`] if the document cannot be encoded, which
    /// cannot happen for a manifest built from ordinary strings.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        Ok(canonical_json(&serde_json::to_value(self)?))
    }

    /// A manifest read back off disk. **Calculation.**
    ///
    /// # Errors
    /// A [`serde_json::Error`] when the text is not a manifest this build
    /// knows.
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

/// The SHA-256 of some bytes, lowercase hex. **Calculation.**
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// One document, one spelling: object keys sorted at every depth, no
/// whitespace outside a string, array order left alone. **Calculation.**
pub(crate) fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(yes) => out.push_str(if *yes { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(members) => {
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
    }
}

/// A string, escaped as JSON escapes one.
fn write_string(out: &mut String, text: &str) {
    out.push_str(&Value::String(text.to_owned()).to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn keys_are_sorted_at_every_depth_and_nothing_is_spaced() {
        let document: Value =
            serde_json::from_str(r#"{"b": {"z": 1, "a": 2}, "a": [3, 4]}"#).unwrap();

        assert_eq!(
            canonical_json(&document),
            r#"{"a":[3,4],"b":{"a":2,"z":1}}"#
        );
    }

    #[test]
    fn strings_keep_the_escaping_json_requires() {
        let document: Value = serde_json::from_str(r#"{"note": "a \"quoted\" line\n"}"#).unwrap();

        assert_eq!(
            canonical_json(&document),
            r#"{"note":"a \"quoted\" line\n"}"#
        );
    }

    #[test]
    fn array_order_is_content_and_is_not_sorted() {
        let one: Value = serde_json::from_str("[1, 2]").unwrap();
        let other: Value = serde_json::from_str("[2, 1]").unwrap();

        assert_ne!(canonical_json(&one), canonical_json(&other));
    }

    #[test]
    fn a_manifest_is_written_canonical_with_keys_sorted() {
        let manifest = Manifest {
            files: vec![FileEntry {
                name: "id.csv".to_owned(),
                sha256: sha256_hex(b"abc"),
                rows: 1,
                dropped: vec!["email".to_owned()],
            }],
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            tool_version: "0.1.0".to_owned(),
            meta: BTreeMap::from([("window".to_owned(), "24h".to_owned())]),
            dropped: BTreeMap::from([("id.csv".to_owned(), vec!["email".to_owned()])]),
        };

        let text = manifest.to_json().unwrap();

        assert_eq!(
            text,
            concat!(
                r#"{"created_at":"2026-01-01T00:00:00Z","#,
                r#""dropped":{"id.csv":["email"]},"#,
                r#""files":[{"dropped":["email"],"name":"id.csv","rows":1,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}],"#,
                r#""meta":{"window":"24h"},"#,
                r#""tool_version":"0.1.0"}"#,
            )
        );
    }
}
