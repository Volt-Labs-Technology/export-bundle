//! Checking a bundle against its manifest.
//!
//! Verify is the recipient's half of the deal: read `manifest.json`, hash
//! every file it lists, count its rows, and compare. The first thing that
//! differs is named — a file the manifest lists but the bundle does not
//! hold, a hash that does not match, or a row count that does not — so a
//! tampered bundle is answered with the specific file, not a shrug.
//!
//! Everything here is a calculation over bytes already on disk: no network,
//! no clock, no second copy of any rule the manifest did not state.

use std::fs;
use std::io;
use std::path::Path;

use thiserror::Error;

use crate::bundle::MANIFEST;
use crate::manifest::{sha256_hex, Manifest};

/// Why a bundle did not verify.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The manifest could not be read, so there is nothing to check
    /// against.
    #[error("{file}: the manifest could not be read: {source}")]
    ManifestIo {
        /// Where the manifest was expected.
        file: std::path::PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The manifest text is not a manifest this build knows.
    #[error("{file}: the manifest could not be read: {source}")]
    ManifestDecode {
        /// Where the manifest was expected.
        file: std::path::PathBuf,
        /// The underlying error.
        source: serde_json::Error,
    },
    /// A file the manifest lists is not in the bundle.
    #[error("{file}: the manifest lists it, the bundle does not have it")]
    Missing {
        /// The listed file that is not there.
        file: String,
    },
    /// A bundled file's bytes differ from what the manifest recorded.
    #[error("{file}: sha256 is {found}, the manifest says {listed}")]
    Hash {
        /// The file whose bytes differ.
        file: String,
        /// The hash the bundle actually holds.
        found: String,
        /// The hash the manifest recorded.
        listed: String,
    },
    /// A bundled file's row count differs from what the manifest recorded.
    #[error("{file}: {found} data rows, the manifest says {listed}")]
    Rows {
        /// The file whose row count differs.
        file: String,
        /// Data rows the bundle actually holds.
        found: usize,
        /// Data rows the manifest recorded.
        listed: usize,
    },
}

/// Recompute a bundle against its manifest. **Action.**
///
/// Reads `manifest.json` from `dir`, then for every entry re-hashes the
/// file and recounts its rows. The first mismatch — a listed file that is
/// missing, a different hash, or a different row count — is named and the
/// check stops there.
///
/// # Errors
/// A [`VerifyError`] naming the first mismatch, or the manifest itself if
/// it cannot be read.
pub fn verify(dir: &Path) -> Result<(), VerifyError> {
    let path = dir.join(MANIFEST);
    let text = fs::read_to_string(&path).map_err(|source| VerifyError::ManifestIo {
        file: path.clone(),
        source,
    })?;
    let manifest = Manifest::from_json(&text)
        .map_err(|source| VerifyError::ManifestDecode { file: path, source })?;

    for entry in &manifest.files {
        fault(dir, entry)?;
    }
    Ok(())
}

/// What is wrong with one listed file, if anything. **Action.**
fn fault(dir: &Path, entry: &crate::manifest::FileEntry) -> Result<(), VerifyError> {
    let path = dir.join(&entry.name);
    let bytes = fs::read(&path).map_err(|_| VerifyError::Missing {
        file: entry.name.clone(),
    })?;

    let found = sha256_hex(&bytes);
    if found != entry.sha256 {
        return Err(VerifyError::Hash {
            file: entry.name.clone(),
            found,
            listed: entry.sha256.clone(),
        });
    }
    let counted = data_rows(&String::from_utf8_lossy(&bytes));
    if counted != entry.rows {
        return Err(VerifyError::Rows {
            file: entry.name.clone(),
            found: counted,
            listed: entry.rows,
        });
    }
    Ok(())
}

/// Data rows in a text file: every non-empty line after the header.
/// **Calculation.**
fn data_rows(text: &str) -> usize {
    text.lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .count()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn write_bundle(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("meters.csv"), "id,watts\n1,60\n").unwrap();
        let spec = crate::FileSpec {
            path: dir.join("meters.csv"),
            keep_columns: vec!["id".to_owned(), "watts".to_owned()],
        };
        crate::bundle(
            &[spec],
            dir,
            std::collections::BTreeMap::new(),
            "2026-01-01T00:00:00Z",
            &[],
        )
        .unwrap();
    }

    #[test]
    fn a_bundle_the_way_it_was_written_verifies() {
        let home = crate::bundle::unique_directory();

        write_bundle(&home);

        verify(&home).unwrap_or_else(|error| panic!("the bundle verifies: {error}"));
    }

    #[test]
    fn a_tampered_byte_makes_verify_fail_naming_that_file() {
        let home = crate::bundle::unique_directory();

        write_bundle(&home);
        let path = home.join("meters.csv");
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replace("60", "61")).unwrap();

        let error = verify(&home).expect_err("the file's bytes changed");

        assert!(
            matches!(error, VerifyError::Hash { ref file, .. } if file == "meters.csv"),
            "got {error}"
        );
        assert!(error.to_string().contains("meters.csv"), "got {error}");
    }

    #[test]
    fn a_file_the_manifest_lists_but_the_bundle_does_not_hold_is_named() {
        let home = crate::bundle::unique_directory();

        write_bundle(&home);
        fs::remove_file(home.join("meters.csv")).unwrap();

        let error = verify(&home).expect_err("the file is gone");

        assert!(
            matches!(error, VerifyError::Missing { ref file } if file == "meters.csv"),
            "got {error}"
        );
    }

    #[test]
    fn a_changed_row_count_is_named() {
        let home = crate::bundle::unique_directory();

        write_bundle(&home);
        // Keep only the header, then rewrite the manifest's hash to match
        // the shorter file, so the only remaining mismatch is the row count.
        let path = home.join("meters.csv");
        let header = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_owned();
        fs::write(&path, format!("{header}\n")).unwrap();
        let manifest_path = home.join("manifest.json");
        let manifest = fs::read_to_string(&manifest_path).unwrap();
        let listed = recorded_sha(&manifest);
        let found = crate::manifest::sha256_hex(&fs::read(&path).unwrap());
        fs::write(&manifest_path, manifest.replace(&listed, &found)).unwrap();

        let error = verify(&home).expect_err("the row count changed");

        assert!(
            matches!(error, VerifyError::Rows { ref file, found: 0, listed: 1 } if file == "meters.csv"),
            "got {error}"
        );
    }

    /// The one hash recorded in the test manifest.
    fn recorded_sha(manifest: &str) -> String {
        let start = manifest.find("\"sha256\":\"").unwrap() + "\"sha256\":\"".len();
        let end = manifest[start..].find('"').unwrap() + start;
        manifest[start..end].to_owned()
    }

    #[test]
    fn data_rows_do_not_count_the_header_or_a_trailing_blank_line() {
        assert_eq!(data_rows("id\n1\n2\n"), 2);
        assert_eq!(data_rows("id\n"), 0);
        assert_eq!(data_rows(""), 0);
    }

    #[test]
    fn text_that_is_not_a_manifest_is_refused() {
        let home = crate::bundle::unique_directory();
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("manifest.json"), "{}").unwrap();

        let error = verify(&home).expect_err("an empty object is not a manifest");

        assert!(
            matches!(error, VerifyError::ManifestDecode { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_missing_manifest_is_refused() {
        let home = crate::bundle::unique_directory();
        fs::create_dir_all(&home).unwrap();

        let error = verify(&home).expect_err("there is no manifest");

        assert!(
            matches!(error, VerifyError::ManifestIo { .. }),
            "got {error}"
        );
    }
}
