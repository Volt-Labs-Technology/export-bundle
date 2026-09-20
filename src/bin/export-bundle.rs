//! `export-bundle`: bundle CSV files, or verify a bundle later.
//!
//! Standard-library argument parsing only. The clock is read once, here at
//! the edge, and handed to the library as `created_at`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use export_bundle::{bundle, verify, FileSpec};

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("bundle") => run_bundle(&mut arguments),
        Some("verify") => run_verify(&mut arguments),
        Some(other) => {
            eprintln!("unknown command {other}: expected `bundle` or `verify`");
            usage();
            ExitCode::FAILURE
        }
        None => {
            usage();
            ExitCode::FAILURE
        }
    }
}

/// What `bundle` needs before it can run.
#[derive(Debug)]
struct Request {
    inputs: Vec<FileSpec>,
    out: PathBuf,
    meta: BTreeMap<String, String>,
    created_at: String,
    extra_forbidden: Vec<String>,
}

fn run_bundle(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let request = match parse_bundle(arguments) {
        Ok(request) => request,
        Err(message) => {
            eprintln!("{message}");
            usage();
            return ExitCode::FAILURE;
        }
    };

    match bundle(
        &request.inputs,
        &request.out,
        request.meta,
        &request.created_at,
        &request.extra_forbidden,
    ) {
        Ok(manifest) => {
            for entry in &manifest.files {
                if entry.dropped.is_empty() {
                    println!("{}", entry.name);
                } else {
                    println!("{} (dropped: {})", entry.name, entry.dropped.join(" "));
                }
            }
            println!(
                "wrote: {}",
                request.out.join("manifest.json").to_string_lossy()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run_verify(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(directory) = arguments.next() else {
        eprintln!("`verify` needs the bundle directory");
        usage();
        return ExitCode::FAILURE;
    };

    match verify(Path::new(&directory)) {
        Ok(()) => {
            println!("verified: {directory}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// argv as a bundle request.
fn parse_bundle(arguments: &mut impl Iterator<Item = String>) -> Result<Request, String> {
    let mut inputs = Vec::new();
    let mut out = None;
    let mut meta = BTreeMap::new();
    let mut created_at = None;
    let mut extra_forbidden = Vec::new();

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--out" => out = Some(next_value(arguments, "--out")?),
            "--created-at" => created_at = Some(next_value(arguments, "--created-at")?),
            "--forbid" => extra_forbidden.push(next_value(arguments, "--forbid")?),
            "--meta" => {
                let pair = next_value(arguments, "--meta")?;
                let (key, value) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("`--meta` wants KEY=VALUE, got {pair}"))?;
                meta.insert(key.to_owned(), value.to_owned());
            }
            _ => inputs.push(input_spec(&argument)?),
        }
    }

    Ok(Request {
        inputs,
        out: PathBuf::from(out.ok_or("`bundle` needs `--out DIR`")?),
        meta,
        created_at: created_at.unwrap_or_else(created_at_now),
        extra_forbidden,
    })
}

/// The value that follows a flag.
fn next_value(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{flag} needs a value"))
}

/// One input, written as `PATH:COL,COL`.
fn input_spec(argument: &str) -> Result<FileSpec, String> {
    let (path, columns) = argument
        .split_once(':')
        .ok_or_else(|| format!("an input is PATH:COL,COL, got {argument}"))?;
    Ok(FileSpec {
        path: PathBuf::from(path),
        keep_columns: columns.split(',').map(str::to_owned).collect(),
    })
}

/// The clock, read once, at the edge.
fn created_at_now() -> String {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is past the epoch");
    let secs = since.as_secs();
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let rest = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z",
        hour = rest / 3_600,
        minute = (rest % 3_600) / 60,
        second = rest % 60,
    )
}

/// Days since the epoch as a civil date.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_point = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_point + 2) / 5 + 1;
    let month = if month_point < 10 {
        month_point + 3
    } else {
        month_point - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn usage() {
    eprintln!(
        "usage: export-bundle bundle --out DIR [--created-at TS] [--forbid TOKEN] [--meta KEY=VALUE] INPUT:COL,COL ...\n       export-bundle verify DIR"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_becomes_a_request_with_the_flags_it_carries() {
        let arguments = [
            "--out".to_owned(),
            "bundle-dir".to_owned(),
            "--created-at".to_owned(),
            "2026-01-01T00:00:00Z".to_owned(),
            "--forbid".to_owned(),
            "region".to_owned(),
            "--meta".to_owned(),
            "window=24h".to_owned(),
            "meters.csv:id,watts".to_owned(),
        ];
        let mut argv = arguments.into_iter();

        let request = parse_bundle(&mut argv).expect("every flag is complete");

        assert_eq!(request.out, PathBuf::from("bundle-dir"));
        assert_eq!(request.created_at, "2026-01-01T00:00:00Z");
        assert_eq!(request.extra_forbidden, vec!["region".to_owned()]);
        assert_eq!(request.meta["window"], "24h");
        assert_eq!(request.inputs.len(), 1);
        assert_eq!(request.inputs[0].path, PathBuf::from("meters.csv"));
        assert_eq!(
            request.inputs[0].keep_columns,
            vec!["id".to_owned(), "watts".to_owned()]
        );
    }

    #[test]
    fn a_bundle_without_an_output_directory_is_refused() {
        let arguments = ["meters.csv:id".to_owned()];
        let mut argv = arguments.into_iter();

        let error = parse_bundle(&mut argv).expect_err("there is no --out");

        assert_eq!(error, "`bundle` needs `--out DIR`");
    }

    #[test]
    fn an_input_without_its_columns_is_refused() {
        let error = input_spec("meters.csv").expect_err("there are no columns");

        assert!(error.contains("PATH:COL,COL"), "got {error}");
    }

    #[test]
    fn the_epoch_is_midnight_on_the_first_of_january_nineteen_seventy() {
        assert_eq!(created_at_from(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn a_known_second_is_written_as_iso8601_in_utc() {
        assert_eq!(created_at_from(1_000_000_000), "2001-09-09T01:46:40Z");
    }

    fn created_at_from(secs: u64) -> String {
        let (year, month, day) = civil_from_days((secs / 86_400) as i64);
        let rest = secs % 86_400;
        format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z",
            hour = rest / 3_600,
            minute = (rest % 3_600) / 60,
            second = rest % 60,
        )
    }
}
