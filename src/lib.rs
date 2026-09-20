//! Bundle CSV files under a manifest, and check a bundle later.
//!
//! A bundle is a directory of CSV files — each rewritten to only the
//! columns its caller-supplied allow-list declares — beside a
//! `manifest.json` that records a SHA-256 hash and a row count for every
//! file. A bundle made here can be checked later, by anyone, with
//! [`verify`]: re-hash each file, compare, and either every byte is still
//! what was exported or a specific file is named as different.
//!
//! The crate refuses rather than repairs. An input whose header names a
//! person or a machine stops the whole call. A column not on the
//! allow-list is dropped and recorded on the manifest, never silently
//! rewritten. Which columns are safe is the caller's decision, made in the
//! allow-list; this crate does not know anyone's schema.
//!
//! `created_at` is the one wall-clock value, and the caller supplies it:
//! this crate never reads a clock.
//!
//! ```no_run
//! use std::collections::BTreeMap;
//! use std::path::Path;
//!
//! use export_bundle::{bundle, verify, FileSpec};
//!
//! // Synthetic file and column names.
//! let spec = FileSpec {
//!     path: Path::new("meters.csv").to_owned(),
//!     keep_columns: vec!["id".to_owned(), "watts".to_owned()],
//! };
//! let manifest = bundle(
//!     &[spec],
//!     Path::new("bundle"),
//!     BTreeMap::new(),
//!     "2026-01-01T00:00:00Z",
//!     &[],
//! )
//! .expect("the bundle writes");
//! verify(Path::new("bundle")).expect("the bundle verifies");
//! let _ = manifest;
//! ```
//!
//! The `cli` feature builds a small `export-bundle` binary with the same
//! two operations, `bundle` and `verify`, using standard-library argument
//! parsing only.

#![deny(missing_docs)]

mod bundle;
mod manifest;
mod verify;

pub use bundle::{bundle, BundleError, FileSpec};
pub use manifest::{FileEntry, Manifest};
pub use verify::{verify, VerifyError};
