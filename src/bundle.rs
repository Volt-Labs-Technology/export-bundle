//! Making a bundle: the listed files, filtered, and nothing else.
//!
//! A bundle is a copy of the files the caller names — each rewritten with
//! only the columns its allow-list declares — under its own file name,
//! beside a manifest that says what is in it and what it hashed to.
//!
//! Three refusals hold the line, and each one refuses rather than repairs:
//!
//! * a column the allow-list does not declare is dropped, and reported on
//!   the manifest, so the recipient learns what the export carried;
//! * any input whose header contains a forbidden token — by default
//!   `user`, `name`, `hostname`, `node`, `email`, matched without regard to
//!   case — stops the whole call, naming the file and the column. The
//!   caller may add tokens, never remove them;
//! * a table file sitting in an input's own directory but not listed as an
//!   input is refused too. A directory that holds one identifying file
//!   holds identifying data, so nothing is copied out of it.
//!
//! `created_at` is supplied by the caller — this crate never reads a clock
//! — so the whole of the filtering, the tripwire and the row counting is a
//! calculation over text and can be tested without a disk.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::manifest::{canonical_json, sha256_hex, FileEntry, Manifest};

/// The manifest's name inside a bundle.
pub(crate) const MANIFEST: &str = "manifest.json";

/// Tokens that mean a column identifies a person or a machine. Matched
/// without regard to case, as a substring of the column name.
pub(crate) const FORBIDDEN: [&str; 5] = ["user", "name", "hostname", "node", "email"];

/// How one file goes into a bundle.
///
/// The allow-list is the caller's, not this crate's: the caller knows which
/// columns their data may carry and this crate must not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSpec {
    /// The file to read.
    pub path: PathBuf,
    /// The columns to keep, by exact name. Every other column is dropped
    /// and reported.
    pub keep_columns: Vec<String>,
}

/// Why a bundle call failed.
#[derive(Debug, Error)]
pub enum BundleError {
    /// A header column contained a forbidden token, so the call refused
    /// rather than copy it.
    #[error("{file}: the column {column} identifies a person or a machine, so nothing was copied")]
    ForbiddenColumn {
        /// The input file whose header carried the column.
        file: PathBuf,
        /// The column that carried a forbidden token.
        column: String,
    },
    /// A table file in an input's directory was not listed as an input, so
    /// the directory may hold identifying data and nothing was copied.
    #[error("{file}: a table in an input directory that was not listed as an input, so nothing was copied")]
    UnlistedFile {
        /// The unlisted file, named as the refusal promises.
        file: PathBuf,
    },
    /// Two inputs would be written under the same name.
    #[error("{name}: two inputs would be written under this name")]
    DuplicateFile {
        /// The name two inputs share.
        name: String,
    },
    /// A row's cell count does not match its header.
    #[error("{file}: line {line} has {found} cells, the header has {listed}")]
    RowWidth {
        /// The input file the row came from.
        file: PathBuf,
        /// The line number, header counted as line 1.
        line: usize,
        /// Cells in the header.
        listed: usize,
        /// Cells in this row.
        found: usize,
    },
    /// The file has no header row at all.
    #[error("{file}: the file has no header row")]
    NoHeader {
        /// The input file.
        file: PathBuf,
    },
    /// No column in the header belongs to the allow-list.
    #[error("{file}: no column in the header belongs to the allow-list")]
    NoAllowedColumn {
        /// The input file.
        file: PathBuf,
    },
    /// Reading or writing a file failed.
    #[error("{file}: {source}")]
    Io {
        /// The file that failed.
        file: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The manifest could not be encoded, which cannot happen for a
    /// manifest built from ordinary strings.
    #[error("the manifest could not be written: {source}")]
    Encode {
        /// The underlying error.
        source: serde_json::Error,
    },
}

/// Copy the listed files out, filtered, and write the manifest beside them.
/// **Action.**
///
/// Every input is rewritten with only the columns its [`FileSpec`] declares,
/// written under its own file name into `out`, and hashed. A file not on an
/// allow-list column is dropped and recorded on the manifest. The manifest
/// is written as canonical JSON and returned.
///
/// `created_at` is the caller's wall-clock value; this crate never reads a
/// clock. `extra_forbidden` is unioned with this crate's default forbidden
/// tokens; a caller may add tokens, never remove them.
///
/// # Errors
/// A [`BundleError`] naming the file, column or row that failed, when any
/// refusal applies. Nothing is written when the call fails.
///
/// # Errors
/// See [`BundleError`].
pub fn bundle(
    inputs: &[FileSpec],
    out: &Path,
    meta: BTreeMap<String, String>,
    created_at: &str,
    extra_forbidden: &[String],
) -> Result<Manifest, BundleError> {
    refuse_unlisted_tables(&inputs_by_directory(inputs))?;
    refuse_duplicate_names(inputs)?;

    let mut files = Vec::new();
    let mut dropped = BTreeMap::new();
    for spec in inputs {
        let bundled = bundle_one(spec, out, extra_forbidden)?;
        if !bundled.dropped.is_empty() {
            dropped.insert(bundled.entry.name.clone(), bundled.dropped.clone());
        }
        files.push(bundled.entry);
    }

    let manifest = Manifest {
        files,
        created_at: created_at.to_owned(),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        meta,
        dropped,
    };
    let text = canonical_json(
        &serde_json::to_value(&manifest).map_err(|source| BundleError::Encode { source })?,
    );
    write(&out.join(MANIFEST), &text)?;

    Ok(manifest)
}

/// Inputs grouped by the directory each one lives in. **Calculation.**
fn inputs_by_directory(inputs: &[FileSpec]) -> BTreeMap<PathBuf, Vec<&FileSpec>> {
    inputs.iter().fold(BTreeMap::new(), |mut groups, spec| {
        let directory = spec
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_owned();
        groups.entry(directory).or_default().push(spec);
        groups
    })
}

/// Refuse every directory an input lives in that holds a table this call
/// was not asked to copy. **Action.**
fn refuse_unlisted_tables(groups: &BTreeMap<PathBuf, Vec<&FileSpec>>) -> Result<(), BundleError> {
    for (directory, specs) in groups {
        let listed: BTreeSet<&str> = specs
            .iter()
            .filter_map(|spec| file_name(&spec.path))
            .collect();
        for path in tables_in(directory)? {
            let name = match file_name(&path) {
                Some(name) => name.to_owned(),
                None => continue,
            };
            if !listed.contains(name.as_str()) {
                return Err(BundleError::UnlistedFile { file: path });
            }
        }
    }
    Ok(())
}

/// Refuse two inputs that would land under one name. **Action.**
fn refuse_duplicate_names(inputs: &[FileSpec]) -> Result<(), BundleError> {
    let mut seen = BTreeSet::new();
    for spec in inputs {
        if let Some(name) = file_name(&spec.path) {
            if !seen.insert(name.to_owned()) {
                return Err(BundleError::DuplicateFile {
                    name: name.to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// One file as the bundle holds it.
struct Bundled {
    entry: FileEntry,
    dropped: Vec<String>,
}

/// Read one file, filter it to its allow-list, write it. **Action.**
fn bundle_one(
    spec: &FileSpec,
    out: &Path,
    extra_forbidden: &[String],
) -> Result<Bundled, BundleError> {
    let source = read(&spec.path)?;
    let filtered = filtered(&source, spec, extra_forbidden)?;
    let name = file_name(&spec.path).unwrap_or_default().to_owned();
    write(&out.join(&name), &filtered.text)?;
    Ok(Bundled {
        entry: FileEntry {
            name,
            sha256: sha256_hex(filtered.text.as_bytes()),
            rows: filtered.rows,
            dropped: filtered.dropped.clone(),
        },
        dropped: filtered.dropped,
    })
}

/// One file filtered to its allow-list.
#[derive(Debug, PartialEq, Eq)]
struct Filtered {
    text: String,
    dropped: Vec<String>,
    rows: usize,
}

/// Keep the columns the allow-list declares, in the file's own order.
/// **Calculation.**
///
/// The output is LF with a trailing newline whatever the input was, so a
/// bundle made on Windows and one made on Linux hash the same. Cells are
/// trimmed. A file whose header carries a forbidden token is refused before
/// any column is dropped: the refusal names the file and the column.
///
/// # Errors
/// A [`BundleError`] when the header is missing, carries a forbidden
/// token, matches nothing on the allow-list, or a row's width differs.
fn filtered(
    text: &str,
    spec: &FileSpec,
    extra_forbidden: &[String],
) -> Result<Filtered, BundleError> {
    let mut lines = text.lines();
    let header = lines.next().ok_or_else(|| BundleError::NoHeader {
        file: spec.path.clone(),
    })?;
    let columns: Vec<&str> = header.split(',').map(str::trim).collect();

    for column in &columns {
        if forbidden(column, extra_forbidden) {
            return Err(BundleError::ForbiddenColumn {
                file: spec.path.clone(),
                column: (*column).to_owned(),
            });
        }
    }

    let kept: Vec<usize> = columns
        .iter()
        .enumerate()
        .filter(|(_, column)| spec.keep_columns.iter().any(|keep| keep == *column))
        .map(|(at, _)| at)
        .collect();
    if kept.is_empty() {
        return Err(BundleError::NoAllowedColumn {
            file: spec.path.clone(),
        });
    }

    let rows: Vec<String> = lines
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(offset, line)| {
            kept_row(line, columns.len(), &kept).map_err(|found| BundleError::RowWidth {
                file: spec.path.clone(),
                line: offset + 2,
                listed: columns.len(),
                found,
            })
        })
        .collect::<Result<_, _>>()?;

    let counted = rows.len();
    let body = std::iter::once(pick(&columns, &kept))
        .chain(rows)
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Filtered {
        text: format!("{body}\n"),
        dropped: columns
            .iter()
            .enumerate()
            .filter(|(at, _)| !kept.contains(at))
            .map(|(_, column)| (*column).to_owned())
            .collect(),
        rows: counted,
    })
}

/// Whether a column name carries a forbidden token. **Calculation.**
///
/// Matched as a case-insensitive substring, so `NodeList` and `user_email`
/// are caught as surely as `user`.
fn forbidden(column: &str, extra: &[String]) -> bool {
    let lowered = column.to_ascii_lowercase();
    FORBIDDEN
        .iter()
        .copied()
        .chain(extra.iter().map(String::as_str))
        .any(|token| lowered.contains(token))
}

/// One data row, filtered to the kept columns, or the count that is wrong
/// with it. **Calculation.**
fn kept_row(line: &str, width: usize, kept: &[usize]) -> Result<String, usize> {
    let cells: Vec<&str> = line.split(',').map(str::trim).collect();
    if cells.len() == width {
        Ok(pick(&cells, kept))
    } else {
        Err(cells.len())
    }
}

/// The cells at those positions, comma-joined. **Calculation.**
fn pick(cells: &[&str], kept: &[usize]) -> String {
    kept.iter()
        .filter_map(|at| cells.get(*at))
        .copied()
        .collect::<Vec<_>>()
        .join(",")
}

/// Which tables in a directory, this crate reads a header out of. **Action.**
fn tables_in(directory: &Path) -> Result<Vec<PathBuf>, BundleError> {
    let mut found = Vec::new();
    let entries = fs::read_dir(directory).map_err(|source| BundleError::Io {
        file: directory.to_owned(),
        source,
    })?;
    for entry in entries {
        let path = entry
            .map_err(|source| BundleError::Io {
                file: directory.to_owned(),
                source,
            })?
            .path();
        if is_table(&path) {
            found.push(path);
        }
    }
    found.sort();
    Ok(found)
}

/// Whether a file is a table. **Calculation.**
fn is_table(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("csv") || extension.eq_ignore_ascii_case("tsv")
    })
}

/// A file's name, if it has one. **Calculation.**
fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

/// Read a file as text. **Action.**
fn read(path: &Path) -> Result<String, BundleError> {
    fs::read_to_string(path).map_err(|source| BundleError::Io {
        file: path.to_owned(),
        source,
    })
}

/// Write a file. **Action.**
pub(crate) fn write(path: &Path, text: &str) -> Result<(), BundleError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| BundleError::Io {
            file: parent.to_owned(),
            source,
        })?;
    }
    fs::write(path, text).map_err(|source| BundleError::Io {
        file: path.to_owned(),
        source,
    })
}

/// A directory that only this test can see.
#[cfg(test)]
pub(crate) fn unique_directory() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let at = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    std::env::temp_dir().join(format!("export-bundle-test-{}-{at}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(path: &str, keep: &[&str]) -> FileSpec {
        FileSpec {
            path: PathBuf::from(path),
            keep_columns: keep.iter().map(|column| (*column).to_owned()).collect(),
        }
    }

    fn filtered_of(text: &str, keep: &[&str]) -> Filtered {
        let spec = spec("meters.csv", keep);
        filtered(text, &spec, &[]).unwrap_or_else(|error| panic!("the fixture filters: {error}"))
    }

    #[test]
    fn a_column_the_allow_list_declares_survives_and_one_it_does_not_is_dropped_and_reported() {
        let filtered = filtered_of("id,watts,note\n1,60,bench\n", &["id", "watts"]);

        assert_eq!(filtered.text, "id,watts\n1,60\n");
        assert_eq!(filtered.dropped, vec!["note".to_owned()]);
        assert_eq!(filtered.rows, 1);
    }

    #[test]
    fn a_crlf_file_is_rewritten_as_lf_so_a_hash_does_not_depend_on_the_platform() {
        let filtered = filtered_of("id,watts\r\n1,60\r\n", &["id", "watts"]);

        assert!(!filtered.text.contains('\r'));
        assert!(filtered.text.ends_with("1,60\n"));
    }

    #[test]
    fn a_trailing_blank_line_is_not_a_row() {
        let filtered = filtered_of("id,watts\n1,60\n\n", &["id", "watts"]);

        assert_eq!(filtered.rows, 1);
        assert!(filtered.text.ends_with("1,60\n"));
    }

    #[test]
    fn a_row_with_the_wrong_number_of_cells_is_named_by_line_rather_than_re_columned() {
        let error = filtered(
            "id,watts\n1,60\n2\n",
            &spec("meters.csv", &["id", "watts"]),
            &[],
        )
        .expect_err("that row is not on the allow-list");

        assert!(
            matches!(error, BundleError::RowWidth { line: 3, .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_file_with_no_allowed_column_at_all_is_refused() {
        let error = filtered(
            "note,colour\nbench,red\n",
            &spec("meters.csv", &["id"]),
            &[],
        )
        .expect_err("nothing on the allow-list");

        assert!(matches!(error, BundleError::NoAllowedColumn { .. }));
    }

    #[test]
    fn an_empty_file_is_refused_rather_than_bundled_as_nothing() {
        let error = filtered("", &spec("meters.csv", &["id"]), &[])
            .expect_err("an empty file has no header");

        assert!(matches!(error, BundleError::NoHeader { .. }));
    }

    #[test]
    fn a_header_column_that_names_a_person_or_a_machine_refuses_the_call() {
        for header in [
            "id,user",
            "id,User",
            "id,email",
            "id,hostname",
            "id,node_list",
            "id,full_name",
        ] {
            let error = filtered(
                &format!("{header}\n1,x\n"),
                &spec("meters.csv", &["id"]),
                &[],
            )
            .expect_err("the header names a person or a machine");

            assert!(
                matches!(error, BundleError::ForbiddenColumn { .. }),
                "{header} was not refused: {error}"
            );
        }
    }

    #[test]
    fn the_refusal_names_the_file_and_the_column() {
        let error = filtered("id,user\n1,nobody\n", &spec("meters.csv", &["id"]), &[])
            .expect_err("the header names a person");

        assert_eq!(
            error.to_string(),
            "meters.csv: the column user identifies a person or a machine, so nothing was copied"
        );
    }

    #[test]
    fn an_extra_forbidden_token_from_the_caller_is_unioned_with_the_defaults() {
        let spec = spec("meters.csv", &["id"]);
        let error = filtered("id,region\n1,north\n", &spec, &[String::from("region")])
            .expect_err("the caller added a forbidden token");

        assert!(
            matches!(error, BundleError::ForbiddenColumn { ref column, .. } if column == "region"),
            "got {error}"
        );
    }

    #[test]
    fn the_default_tokens_apply_whenever_the_caller_adds_none() {
        let spec = spec("meters.csv", &["id"]);
        let error = filtered("id,user\n1,nobody\n", &spec, &[]).expect_err("default token");

        assert!(matches!(error, BundleError::ForbiddenColumn { .. }));
    }

    #[test]
    fn only_a_table_is_inspected_for_an_unlisted_file() {
        assert!(is_table(Path::new("users.csv")));
        assert!(is_table(Path::new("export.TSV")));
        assert!(!is_table(Path::new("notes.json")));
        assert!(!is_table(Path::new("notes")));
    }

    #[test]
    fn bundle_refuses_a_table_in_the_input_directory_that_was_not_listed() {
        let home = unique_directory();
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("meters.csv"), "id,watts\n1,60\n").unwrap();
        fs::write(home.join("users.csv"), "user\nnobody\n").unwrap();
        let out = home.join("bundle");

        let error = bundle(
            &[spec(
                home.join("meters.csv").to_str().unwrap(),
                &["id", "watts"],
            )],
            &out,
            BTreeMap::new(),
            "2026-01-01T00:00:00Z",
            &[],
        )
        .expect_err("users.csv sits in the same directory and is not listed");

        assert!(
            error.to_string().contains("users.csv"),
            "the refusal names the file: {error}"
        );
        assert!(!out.join("meters.csv").exists(), "nothing was copied");
    }

    #[test]
    fn bundle_writes_the_filtered_files_and_a_manifest_that_verifies() {
        let home = unique_directory();
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("meters.csv"), "id,watts,note\n1,60,bench\n").unwrap();
        let out = home.join("bundle");

        let manifest = bundle(
            &[spec(
                home.join("meters.csv").to_str().unwrap(),
                &["id", "watts"],
            )],
            &out,
            BTreeMap::from([("window".to_owned(), "24h".to_owned())]),
            "2026-01-01T00:00:00Z",
            &[],
        )
        .unwrap_or_else(|error| panic!("the bundle writes: {error}"));

        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].name, "meters.csv");
        assert_eq!(manifest.files[0].rows, 1);
        assert_eq!(manifest.files[0].dropped, vec!["note".to_owned()]);
        assert_eq!(manifest.dropped["meters.csv"], vec!["note".to_owned()]);
        assert_eq!(manifest.meta["window"], "24h");
        crate::verify(&out).unwrap_or_else(|error| panic!("the bundle verifies: {error}"));
    }

    #[test]
    fn two_bundles_of_the_same_bytes_are_equal_whenever_they_were_made() {
        let home = unique_directory();
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("meters.csv"), "id,watts\n1,60\n").unwrap();
        let spec = spec(home.join("meters.csv").to_str().unwrap(), &["id", "watts"]);

        let morning = bundle(
            std::slice::from_ref(&spec),
            &home.join("morning"),
            BTreeMap::new(),
            "2026-01-01T00:00:00Z",
            &[],
        )
        .unwrap();
        let a_month_later = bundle(
            &[spec],
            &home.join("later"),
            BTreeMap::new(),
            "2026-02-01T23:59:59Z",
            &[],
        )
        .unwrap();

        assert_eq!(morning, a_month_later);
    }

    #[test]
    fn a_bundle_whose_file_changed_is_not_equal_to_one_made_before_the_change() {
        let home = unique_directory();
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("meters.csv"), "id,watts\n1,60\n").unwrap();
        let spec = spec(home.join("meters.csv").to_str().unwrap(), &["id", "watts"]);

        let before = bundle(
            std::slice::from_ref(&spec),
            &home.join("before"),
            BTreeMap::new(),
            "x",
            &[],
        )
        .unwrap();
        fs::write(home.join("meters.csv"), "id,watts\n1,61\n").unwrap();
        let after = bundle(&[spec], &home.join("after"), BTreeMap::new(), "x", &[]).unwrap();

        assert_ne!(before, after);
    }

    #[test]
    fn two_inputs_from_one_directory_are_both_copied() {
        let home = unique_directory();
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("meters.csv"), "id,watts\n1,60\n").unwrap();
        fs::write(home.join("sites.csv"), "site,kw\nroof,4\n").unwrap();
        let out = home.join("bundle");

        let manifest = bundle(
            &[
                spec(home.join("meters.csv").to_str().unwrap(), &["id"]),
                spec(home.join("sites.csv").to_str().unwrap(), &["site"]),
            ],
            &out,
            BTreeMap::new(),
            "2026-01-01T00:00:00Z",
            &[],
        )
        .unwrap();

        let names: Vec<&str> = manifest
            .files
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["meters.csv", "sites.csv"]);
    }

    #[test]
    fn two_inputs_that_would_land_under_one_name_are_refused() {
        let home = unique_directory();
        fs::create_dir_all(home.join("one")).unwrap();
        fs::create_dir_all(home.join("two")).unwrap();
        fs::write(home.join("one/meters.csv"), "id\n1\n").unwrap();
        fs::write(home.join("two/meters.csv"), "id\n2\n").unwrap();
        let out = home.join("bundle");

        let error = bundle(
            &[
                spec(home.join("one/meters.csv").to_str().unwrap(), &["id"]),
                spec(home.join("two/meters.csv").to_str().unwrap(), &["id"]),
            ],
            &out,
            BTreeMap::new(),
            "2026-01-01T00:00:00Z",
            &[],
        )
        .expect_err("two files would share a name");

        assert!(
            matches!(error, BundleError::DuplicateFile { ref name } if name == "meters.csv"),
            "got {error}"
        );
    }
}
