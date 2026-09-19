//! `manifest.json`: what a bundle contains, so it can be checked later.
//!
//! A bundle is the only thing that leaves a site, and the manifest is how
//! anyone downstream answers two questions without the site's help: which
//! files were in it, and are these still those bytes. So every entry carries a
//! name, a SHA-256 and a row count, and the whole document is a calculation
//! over values the caller already has — nothing here opens a file or reads a
//! clock.
//!
//! `created_at` is the one wall-clock value, and it is the caller's to supply.
//! [`Manifest::digest`] leaves it out, so two bundles of the same bytes made a
//! month apart fingerprint the same and a fingerprint means "these files",
//! never "this afternoon".
//!
//! The `map_err`s below attach *which* document failed, as `run`'s do: that is
//! context a `serde_json::Error` does not carry and a blanket `From` impl could
//! not know.

use loadshift_domain::SiteAlias;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canon;
use crate::error::ReportError;

/// The version of this document's shape. A reader that does not know this
/// number should refuse the file rather than guess at it.
pub const SCHEMA: u32 = 1;

const DOCUMENT: &str = "manifest";

/// One file in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// The name the file has inside the bundle.
    pub name: String,
    /// SHA-256 of its bytes, lowercase hex.
    pub sha256: String,
    /// Data rows, header excluded — `None` for a file that has no rows.
    ///
    /// A JSON nameplate or a tariff sheet is not tabular. Saying so is
    /// honester than counting its lines and calling them rows.
    pub rows: Option<usize>,
}

/// The price series a bundle carries: where it starts, and how long it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    /// The `timestamp_iso` of hour 0, when the series carries one.
    pub t0: Option<String>,
    /// Hours in the series.
    pub hours: usize,
}

/// What wrote a bundle, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// The version of the tool that wrote it.
    pub tool_version: String,
    /// When it was written, UTC. The only wall-clock value in a bundle.
    pub created_at: String,
}

/// What one bundle contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Named `manifest_schema` in the file, as `loadshift_run` names its own:
    /// a document says which shape it is in its own terms, and the field is
    /// `schema` here because it is already inside a [`Manifest`].
    #[serde(rename = "manifest_schema")]
    schema: u32,
    site_alias: String,
    /// The calendar anchor of the price series, when it carries one.
    t0: Option<String>,
    /// Hours in the price series.
    hours: usize,
    files: Vec<FileEntry>,
    tool_version: String,
    created_at: String,
}

impl Manifest {
    /// The manifest for one bundle. **Calculation.**
    ///
    /// The alias arrives as a [`SiteAlias`] rather than a string so that a
    /// company name cannot reach this document: the only way to build one is
    /// to have parsed an alias at the edge.
    #[must_use]
    pub fn new(site: &SiteAlias, window: Window, files: Vec<FileEntry>, written: Written) -> Self {
        Self {
            schema: SCHEMA,
            site_alias: site.get().to_owned(),
            t0: window.t0,
            hours: window.hours,
            files,
            tool_version: written.tool_version,
            created_at: written.created_at,
        }
    }

    /// The files the bundle claims to hold, in the order it wrote them.
    #[must_use]
    pub fn files(&self) -> &[FileEntry] {
        &self.files
    }

    /// The alias the bundle was made for, as the document carries it.
    #[must_use]
    pub fn site_alias(&self) -> &str {
        &self.site_alias
    }

    /// Hours in the bundled price series.
    #[must_use]
    pub const fn hours(&self) -> usize {
        self.hours
    }

    /// The document as a file's worth of text. **Calculation.**
    ///
    /// # Errors
    /// [`ReportError::Encode`] if the document cannot be encoded.
    pub fn to_json(&self) -> Result<String, ReportError> {
        let body = serde_json::to_string_pretty(self).map_err(|source| ReportError::Encode {
            document: DOCUMENT,
            source,
        })?;
        Ok(format!("{body}\n"))
    }

    /// A manifest read back off disk. **Calculation.**
    ///
    /// # Errors
    /// [`ReportError::Decode`] when the text is not this document, or
    /// [`ReportError::UnknownSchema`] when it is a shape this build does not
    /// know — which is refused rather than read as if it were shape 1.
    pub fn from_json(text: &str) -> Result<Self, ReportError> {
        let manifest: Self = serde_json::from_str(text).map_err(|source| ReportError::Decode {
            document: DOCUMENT,
            source,
        })?;
        if manifest.schema == SCHEMA {
            Ok(manifest)
        } else {
            Err(ReportError::UnknownSchema {
                document: DOCUMENT,
                schema: manifest.schema,
            })
        }
    }

    /// What the bundle is, as one hash: the document without `created_at`.
    /// **Calculation.**
    ///
    /// Two bundles of the same files under the same alias fingerprint the
    /// same, however far apart they were made, which is what makes this
    /// quotable in a run document or an audit line.
    ///
    /// # Errors
    /// [`ReportError::Encode`] if the document cannot be encoded.
    pub fn digest(&self) -> Result<String, ReportError> {
        let mut value: Value =
            serde_json::to_value(self).map_err(|source| ReportError::Encode {
                document: DOCUMENT,
                source,
            })?;
        if let Some(members) = value.as_object_mut() {
            members.remove("created_at");
        }
        Ok(canon::digest(&value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias() -> SiteAlias {
        SiteAlias::parse("site-1").expect("site-1 is an alias")
    }

    fn entry(name: &str, rows: Option<usize>) -> FileEntry {
        FileEntry {
            name: name.to_owned(),
            sha256: canon::sha256_hex(name.as_bytes()),
            rows,
        }
    }

    fn window() -> Window {
        Window {
            t0: Some("2026-01-19T00:00:00-06:00".to_owned()),
            hours: 336,
        }
    }

    fn written(created_at: &str) -> Written {
        Written {
            tool_version: "0.1.0".to_owned(),
            created_at: created_at.to_owned(),
        }
    }

    fn manifest(created_at: &str) -> Manifest {
        Manifest::new(
            &alias(),
            window(),
            vec![entry("jobs.csv", Some(252)), entry("cap_h.json", None)],
            written(created_at),
        )
    }

    #[test]
    fn the_schema_version_is_the_documents_first_key() {
        let text = manifest("2026-09-19T11:00:00Z")
            .to_json()
            .expect("the document encodes");

        let first = text.lines().nth(1).expect("the document has a first key");
        assert_eq!(first.trim(), "\"manifest_schema\": 1,");
    }

    #[test]
    fn a_document_is_a_text_file_and_ends_in_a_newline() {
        let text = manifest("2026-09-19T11:00:00Z")
            .to_json()
            .expect("the document encodes");

        assert!(text.ends_with("}\n"), "got {text}");
    }

    #[test]
    fn a_file_with_no_rows_says_null_rather_than_zero() {
        let text = manifest("2026-09-19T11:00:00Z")
            .to_json()
            .expect("the document encodes");

        assert!(text.contains("\"rows\": null"), "got {text}");
    }

    #[test]
    fn two_bundles_of_the_same_bytes_fingerprint_the_same_whenever_they_were_made() {
        let morning = manifest("2026-09-19T08:00:00Z")
            .digest()
            .expect("the document encodes");
        let a_month_later = manifest("2026-10-19T23:59:59Z")
            .digest()
            .expect("the document encodes");

        assert_eq!(morning, a_month_later);
    }

    #[test]
    fn a_bundle_whose_file_changed_fingerprints_differently() {
        let before = manifest("2026-09-19T08:00:00Z")
            .digest()
            .expect("the document encodes");
        let after = Manifest::new(
            &alias(),
            window(),
            vec![entry("jobs.csv", Some(253)), entry("cap_h.json", None)],
            written("2026-09-19T08:00:00Z"),
        )
        .digest()
        .expect("the document encodes");

        assert_ne!(before, after);
    }

    #[test]
    fn a_manifest_survives_the_round_trip_to_text_and_back() {
        let written = manifest("2026-09-19T11:00:00Z");

        let read = Manifest::from_json(&written.to_json().expect("the document encodes"))
            .expect("what this crate wrote, it reads");

        assert_eq!(read, written);
        assert_eq!(read.site_alias(), "site-1");
        assert_eq!(read.hours(), 336);
        assert_eq!(read.files().len(), 2);
    }

    #[test]
    fn text_that_is_not_a_manifest_is_refused() {
        let error = Manifest::from_json("{}").expect_err("an empty object is not a manifest");

        assert!(matches!(error, ReportError::Decode { .. }), "got {error}");
    }

    #[test]
    fn a_manifest_from_a_shape_this_build_does_not_know_is_refused_by_number() {
        let text = r#"{"manifest_schema":2,"site_alias":"site-1","t0":null,"hours":0,
                       "files":[],"tool_version":"0.2.0","created_at":"2026-09-19T11:00:00Z"}"#;

        let error = Manifest::from_json(text).expect_err("shape 2 is not shape 1");

        assert!(
            matches!(error, ReportError::UnknownSchema { schema: 2, .. }),
            "got {error}"
        );
    }
}
