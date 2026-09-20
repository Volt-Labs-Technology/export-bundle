# export-bundle

Copy CSV files while keeping only the columns a caller allows, refuse any
header that names a person or a machine, and write a manifest the recipient
can check later.

## What this is

A small Rust library and command-line tool that makes a *bundle*: a directory
of CSV files, each rewritten to only its allowed columns, beside a
`manifest.json` that records a SHA-256 hash and a row count for every file.
A second command re-checks a bundle against its manifest.

## Who it is for

Anyone who has to hand CSV files to a third party and wants a provable record
of exactly which bytes left — and a tool that refuses to copy identifying
columns rather than asking it to judge them.

## How to use it

Add the crate to a Rust project:

```sh
cargo add export-bundle
```

That writes this line into `Cargo.toml`:

```toml
export-bundle = "0.1.0"
```

Minimal example. The file names and column names below are synthetic.

```rust
use std::collections::BTreeMap;
use std::path::Path;

use export_bundle::{bundle, FileSpec};

let spec = FileSpec {
    path: Path::new("examples/usage/meters.csv").to_owned(),
    keep_columns: vec!["id".to_owned(), "watts".to_owned()],
};
let meta = BTreeMap::from([("window".to_owned(), "24h".to_owned())]);
let manifest = bundle(&[spec], Path::new("examples/usage/out"), meta, "2026-01-01T00:00:00Z", &[])
    .expect("the bundle writes");
export_bundle::verify(Path::new("examples/usage/out")).expect("the bundle verifies");
let _ = manifest;
```

A bundle is a copy of the listed files with every column not on the
allow-list dropped, so the manifest is what lets a recipient prove, later and
without your help, that the bundle is unchanged. Because `manifest.json`
carries a SHA-256 of every file, "this bundle is unchanged" becomes a
calculation anyone can run: re-hash each file, compare against the manifest,
and either every byte matches what you exported or a specific file and hash
is named as different. Nothing has to be trusted on either side — no
attestation, no signature infrastructure, just the hashes and the files
themselves.

The command-line tool does the same without writing Rust:

```sh
export-bundle bundle --out bundle-dir --keep id,watts meters.csv
export-bundle verify bundle-dir
```

## What it deliberately does not do

It does not encrypt, does not transmit, does not anonymise values inside a
column (it drops columns; it does not rewrite them), and does not decide
which columns are safe — allow-lists are supplied by the caller, because only
the caller knows their data.

Version 0.x: the API may change before 1.0.
