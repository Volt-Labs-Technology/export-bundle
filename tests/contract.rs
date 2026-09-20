//! Consumer contract for the public bundle/verify API.
//!
//! These tests name the promised types, fields, hashes, and refusals so a
//! rename or a loosened rule fails. Extra fields, extra output, extra
//! dependencies, and exact serialization are not the contract.
//!
//! File names and column names in these fixtures are synthetic.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use export_bundle::{bundle, verify, BundleError, FileEntry, FileSpec, Manifest, VerifyError};

const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn sha256_of_abc_is_the_published_vector() {
    let out = bundle_meters(&unique_directory());
    fs::write(out.join("meters.csv"), b"abc").expect("the overwrite writes");

    let error: VerifyError = verify(&out).expect_err("the bytes changed");

    assert!(
        error.to_string().contains(SHA256_ABC),
        "the hasher must report the published SHA-256 of abc, got {error}"
    );
}

#[test]
fn sha256_of_nothing_is_the_published_empty_vector() {
    let out = bundle_meters(&unique_directory());
    fs::write(out.join("meters.csv"), b"").expect("the overwrite writes");

    let error: VerifyError = verify(&out).expect_err("the bytes changed");

    assert!(
        error.to_string().contains(SHA256_EMPTY),
        "the hasher must report the published SHA-256 of nothing, got {error}"
    );
}

#[test]
fn bundle_keeps_allow_list_columns_and_reports_dropped() {
    let home = unique_directory();
    let input = write_csv(&home, "meters.csv", "id,watts,note\n1,60,bench\n");
    let out = home.join("bundle");

    let manifest: Manifest = bundle(
        &[spec(&input, &["id", "watts"])],
        &out,
        BTreeMap::new(),
        "2026-01-01T00:00:00Z",
        &[],
    )
    .expect("the synthetic bundle writes");

    let text = fs::read_to_string(out.join("meters.csv")).expect("the bundled file is readable");
    let header = header_columns(&text);
    assert_eq!(
        header.len(),
        2,
        "only the allow-list columns are kept: {header:?}"
    );
    assert!(header.contains(&"id".to_owned()), "got {header:?}");
    assert!(header.contains(&"watts".to_owned()), "got {header:?}");
    assert!(
        !header.contains(&"note".to_owned()),
        "note must be dropped: {header:?}"
    );

    let entry: &FileEntry = &manifest.files[0];
    assert_eq!(entry.name, "meters.csv");
    assert_eq!(entry.rows, 1);
    assert!(
        entry.dropped.iter().any(|column| column == "note"),
        "note is listed as dropped, got {:?}",
        entry.dropped
    );
    assert_eq!(entry.sha256.len(), 64);
    assert!(
        entry
            .sha256
            .chars()
            .all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "sha256 is lowercase hex, got {}",
        entry.sha256
    );
}

#[test]
fn forbidden_header_column_refuses_and_writes_nothing() {
    for column in ["user", "name", "hostname", "node", "email", "User"] {
        let home = unique_directory();
        let input = write_csv(&home, "meters.csv", &format!("id,{column}\n1,x\n"));
        let out = home.join("bundle");

        let error = bundle(
            &[spec(&input, &["id"])],
            &out,
            BTreeMap::new(),
            "2026-01-01T00:00:00Z",
            &[],
        )
        .expect_err("the header names a person or a machine");

        match error {
            BundleError::ForbiddenColumn {
                file,
                column: found,
                ..
            } => {
                assert!(
                    file.ends_with("meters.csv"),
                    "the refusal names the file, got {}",
                    file.display()
                );
                assert_eq!(found, column);
            }
            other => panic!("{column} was not ForbiddenColumn: {other}"),
        }
        assert!(!out.join("meters.csv").exists(), "nothing was copied");
        assert!(!out.join("manifest.json").exists(), "nothing was copied");
    }
}

#[test]
fn unlisted_users_csv_in_the_input_directory_is_refused() {
    let home = unique_directory();
    let input = write_csv(&home, "meters.csv", "id,watts\n1,60\n");
    write_csv(&home, "users.csv", "id\n1\n");
    let out = home.join("bundle");

    let error = bundle(
        &[spec(&input, &["id", "watts"])],
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
fn a_tampered_byte_makes_verify_fail_naming_that_file() {
    let out = bundle_meters(&unique_directory());
    let path = out.join("meters.csv");
    let text = fs::read_to_string(&path).expect("the bundled file is readable");
    fs::write(&path, text.replace("60", "61")).expect("the overwrite writes");

    let error: VerifyError = verify(&out).expect_err("the file's bytes changed");

    assert!(error.to_string().contains("meters.csv"), "got {error}");
}

#[test]
fn manifests_that_differ_only_in_created_at_compare_equal() {
    let home = unique_directory();
    let input = write_csv(&home, "meters.csv", "id,watts\n1,60\n");
    let spec = spec(&input, &["id", "watts"]);

    let morning: Manifest = bundle(
        std::slice::from_ref(&spec),
        &home.join("morning"),
        BTreeMap::new(),
        "2026-01-01T00:00:00Z",
        &[],
    )
    .expect("the synthetic bundle writes");
    let later: Manifest = bundle(
        &[spec],
        &home.join("later"),
        BTreeMap::new(),
        "2026-02-01T23:59:59Z",
        &[],
    )
    .expect("the synthetic bundle writes");

    let _: &FileEntry = &morning.files[0];
    assert_ne!(morning.created_at, later.created_at);
    assert_eq!(morning.tool_version, later.tool_version);
    assert_eq!(morning.meta, later.meta);
    assert_eq!(morning, later);
}

#[test]
fn caller_meta_and_created_at_appear_in_the_written_manifest() {
    let home = unique_directory();
    let input = write_csv(&home, "meters.csv", "id,watts\n1,60\n");
    let out = home.join("bundle");
    let meta = BTreeMap::from([("window".to_owned(), "24h".to_owned())]);

    let manifest: Manifest = bundle(
        &[spec(&input, &["id", "watts"])],
        &out,
        meta,
        "caller-supplied-stamp",
        &[],
    )
    .expect("the synthetic bundle writes");

    let text = fs::read_to_string(out.join("manifest.json")).expect("the manifest is readable");
    assert_eq!(manifest.created_at, "caller-supplied-stamp");
    assert_eq!(manifest.meta["window"], "24h");
    assert!(text.contains("caller-supplied-stamp"), "got {text}");
    assert!(text.contains("window"), "got {text}");
    assert!(text.contains("24h"), "got {text}");
}

#[test]
fn extra_forbidden_is_unioned_with_the_defaults() {
    let home = unique_directory();
    let user = write_csv(&home.join("user"), "meters.csv", "id,user_id\n1,u1\n");
    let account = write_csv(&home.join("account"), "meters.csv", "id,account_id\n1,a1\n");
    let allowed = write_csv(&home.join("allowed"), "meters.csv", "id,account_id\n1,a1\n");

    let user_error = bundle(
        &[spec(&user, &["id"])],
        &home.join("out-user"),
        BTreeMap::new(),
        "2026-01-01T00:00:00Z",
        &[],
    )
    .expect_err("user_id is a default forbidden token");
    assert!(
        matches!(
            user_error,
            BundleError::ForbiddenColumn { ref column, .. } if column == "user_id"
        ),
        "got {user_error}"
    );

    let extra_error = bundle(
        &[spec(&account, &["id"])],
        &home.join("out-account"),
        BTreeMap::new(),
        "2026-01-01T00:00:00Z",
        &[String::from("account")],
    )
    .expect_err("the caller added a forbidden token");
    assert!(
        matches!(
            extra_error,
            BundleError::ForbiddenColumn { ref column, .. } if column == "account_id"
        ),
        "got {extra_error}"
    );

    let manifest: Manifest = bundle(
        &[spec(&allowed, &["id"])],
        &home.join("out-allowed"),
        BTreeMap::new(),
        "2026-01-01T00:00:00Z",
        &[],
    )
    .expect("account_id is allowed until the caller forbids it");
    assert!(
        manifest.files[0]
            .dropped
            .iter()
            .any(|column| column == "account_id"),
        "got {:?}",
        manifest.files[0].dropped
    );
}

#[test]
fn direct_dependencies_include_the_named_crates_and_not_clap() {
    let toml = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("Cargo.toml is readable");
    let names = dependency_names(&toml);

    for required in ["serde", "serde_json", "sha2", "thiserror"] {
        assert!(
            names.iter().any(|name| name == required),
            "{required} must remain a direct dependency, got {names:?}"
        );
    }
    assert!(
        !names.iter().any(|name| name == "clap"),
        "clap must not be a direct dependency, got {names:?}"
    );
}

#[test]
fn library_sources_do_not_name_product_columns() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let forbidden = [
        "hour_index",
        "nameplate_gpus",
        "act_hours",
        "arrival_h",
        "id_map",
        concat!("Site", "Alias"),
    ];
    for path in rust_files(&src) {
        let text = fs::read_to_string(&path).expect("a source file is readable");
        let production = production_source(&text);
        for token in forbidden {
            assert!(
                !production.contains(token),
                "{} contains {token}",
                path.display()
            );
        }
    }
}

fn unique_directory() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let at = NEXT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "export-bundle-contract-{}-{at}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("the temp directory is created");
    dir
}

fn write_csv(dir: &Path, name: &str, text: &str) -> PathBuf {
    fs::create_dir_all(dir).expect("the fixture directory is created");
    let path = dir.join(name);
    fs::write(&path, text).expect("the synthetic csv writes");
    path
}

fn spec(path: &Path, keep: &[&str]) -> FileSpec {
    FileSpec {
        path: path.to_owned(),
        keep_columns: keep.iter().map(|column| (*column).to_owned()).collect(),
    }
}

fn bundle_meters(home: &Path) -> PathBuf {
    let input = write_csv(home, "meters.csv", "id,watts\n1,60\n");
    let out = home.join("bundle");
    bundle(
        &[spec(&input, &["id", "watts"])],
        &out,
        BTreeMap::new(),
        "2026-01-01T00:00:00Z",
        &[],
    )
    .expect("the synthetic bundle writes");
    out
}

fn header_columns(text: &str) -> Vec<String> {
    match text.lines().next() {
        Some(line) => line
            .split(',')
            .map(|column| column.trim().to_owned())
            .collect(),
        None => Vec::new(),
    }
}

fn dependency_names(toml: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_dependencies = false;
    for line in toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_dependencies = trimmed == "[dependencies]";
            continue;
        }
        if !in_dependencies || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(name) = trimmed.split([' ', '=', '.']).next() {
            if !name.is_empty() {
                names.push(name.to_owned());
            }
        }
    }
    names
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rs(dir, &mut files);
    files
}

fn collect_rs(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("src is readable") {
        let path = entry.expect("a directory entry is readable").path();
        if path.is_dir() {
            collect_rs(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn production_source(text: &str) -> &str {
    match text.find("#[cfg(test)]") {
        Some(at) => &text[..at],
        None => text,
    }
}
