//! `loadshift bundle`: the contract files, and nothing else, leave the site.
//!
//! A pilot export carries user names, job names and node names. The diagnostic
//! needs none of them, and the pilot terms say what leaves is metadata only.
//! So a bundle is not a copy of a directory: it is a copy of the *contracts* —
//! each file rewritten with only the columns its contract declares, under a
//! canonical name, beside a manifest that says what is in it and what it
//! hashed to.
//!
//! Three refusals hold that line, and each one refuses rather than repairs:
//!
//! * a column the contract does not declare is dropped, and reported, so the
//!   operator learns what their export carried;
//! * a `.csv` or `.tsv` sitting in the same directory whose header names a
//!   user, a job name, a hostname or a node stops the whole bundle — that
//!   directory holds identifying data, and nothing is copied out of it;
//! * a row whose cell count does not match its header is named by line number
//!   rather than silently re-columned.
//!
//! Everything that decides anything is a calculation below — text in, values
//! out — so the whole of the filtering, the tripwire and the row counting is
//! tested without a disk. [`crate::files`] holds the actions.
//!
//! `id_map.csv`, the file that would turn an alias back into a person, is
//! dropped the way every other unnamed file is dropped: a bundle copies the
//! files the flags name and nothing it was not asked for.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use loadshift_domain::SiteAlias;
use loadshift_ingest::schema::prices;
use loadshift_report::canon::sha256_hex;
use loadshift_report::{FileEntry, Manifest, Window, Written};

use crate::cli::{Bundle, BundleCommands, extension};
use crate::clock;
use crate::error::CliError;
use crate::files;
use crate::summary::labelled;

/// The manifest's name inside a bundle.
const MANIFEST: &str = "manifest.json";

/// The tool that wrote the bundle, as the manifest records it.
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Column-name segments that mean a file identifies people or machines.
const IDENTIFYING: [&str; 4] = ["user", "name", "hostname", "node"];

/// The nameplate CSV contract, which no adapter declares yet.
const NAMEPLATE_COLUMNS: [&str; 2] = ["hour_index", "nameplate_gpus"];

/// Whether a column belongs to a contract. **Calculation.**
type Allows = fn(&str) -> bool;

/// How a file goes into a bundle.
#[derive(Debug)]
enum Content {
    /// A CSV, rewritten with the columns its contract declares.
    Table(Allows),
    /// A file copied as it is, because it has no columns: a JSON nameplate,
    /// a tariff sheet.
    Opaque,
}

/// One file on its way into a bundle.
#[derive(Debug)]
struct Member<'a> {
    source: &'a Path,
    /// What the bundle calls it. Canonical, because a partner's own file name
    /// can identify the partner.
    name: &'static str,
    content: Content,
}

/// One file as the bundle holds it.
#[derive(Debug)]
struct Bundled {
    entry: FileEntry,
    /// Columns the contract does not declare, which this file carried.
    dropped: Vec<String>,
    text: String,
}

/// A bundle invocation with every required flag present.
///
/// The parser cannot demand these — `bundle verify <dir>` is the same word
/// with none of them — so this is where argv becomes a request, and where the
/// site alias stops being a string.
#[derive(Debug)]
struct Request<'a> {
    jobs: &'a Path,
    prices: &'a Path,
    settlement: Option<&'a Path>,
    nameplate: &'a Path,
    tariff: Option<&'a Path>,
    site: SiteAlias,
    out: &'a Path,
}

/// Write a bundle, or verify one. **Action.**
///
/// # Errors
/// [`CliError`] naming the flag, file or mismatch that failed.
pub fn run(bundle: &Bundle) -> Result<String, CliError> {
    match &bundle.command {
        Some(BundleCommands::Verify(verify)) => verify_bundle(&verify.dir),
        None => write_bundle(&Request::parse(bundle)?),
    }
}

impl<'a> Request<'a> {
    /// argv as a request. **Calculation.**
    fn parse(bundle: &'a Bundle) -> Result<Self, CliError> {
        let site = bundle
            .site
            .as_deref()
            .ok_or(CliError::MissingFlag { flag: "--site" })?;
        Ok(Self {
            jobs: required(bundle.jobs.as_deref(), "--jobs")?,
            prices: required(bundle.prices.as_deref(), "--prices")?,
            settlement: bundle.settlement.as_deref(),
            nameplate: required(bundle.nameplate.as_deref(), "--nameplate")?,
            tariff: bundle.tariff.as_deref(),
            site: SiteAlias::parse(site)?,
            out: required(bundle.out.as_deref(), "--out")?,
        })
    }

    /// What the bundle will hold, in the order it writes it. **Calculation.**
    fn members(&self) -> Result<Vec<Member<'a>>, CliError> {
        let optional = |source: Option<&'a Path>, name, content| {
            source.map(|source| Member {
                source,
                name,
                content,
            })
        };
        Ok([
            Some(Member {
                source: self.jobs,
                name: "jobs.csv",
                content: Content::Table(jobs_column),
            }),
            Some(Member {
                source: self.prices,
                name: "prices.csv",
                content: Content::Table(prices_column),
            }),
            optional(
                self.settlement,
                "settlement.csv",
                Content::Table(prices_column),
            ),
            Some(nameplate_member(self.nameplate)?),
            optional(self.tariff, "tariff.json", Content::Opaque),
        ]
        .into_iter()
        .flatten()
        .collect())
    }
}

fn required<'a>(path: Option<&'a Path>, flag: &'static str) -> Result<&'a Path, CliError> {
    path.ok_or(CliError::MissingFlag { flag })
}

/// The nameplate's two shapes, told apart by extension as `replay` tells them
/// apart. **Calculation.**
fn nameplate_member(source: &Path) -> Result<Member<'_>, CliError> {
    match extension(source).as_str() {
        "csv" => Ok(Member {
            source,
            name: "nameplate.csv",
            content: Content::Table(nameplate_column),
        }),
        "json" => Ok(Member {
            source,
            name: "cap_h.json",
            content: Content::Opaque,
        }),
        _ => Err(CliError::NameplateShape {
            path: source.to_owned(),
        }),
    }
}

/// The jobs contract, as the ingest adapter's declared catalogue defines it.
/// **Calculation.**
///
/// By predicate rather than by list: the catalogue is already the single
/// source of truth for which columns a jobs file may carry, and a second list
/// here would be a second answer to the same question.
fn jobs_column(name: &str) -> bool {
    loadshift_ingest::schema::jobs_field(name).is_some()
}

/// The prices contract, which settlement shares. **Calculation.**
fn prices_column(name: &str) -> bool {
    [
        prices::HOUR_INDEX,
        prices::TIMESTAMP_ISO,
        prices::PRICE_USD_PER_MWH,
    ]
    .contains(&name)
}

/// The nameplate CSV contract. **Calculation.**
fn nameplate_column(name: &str) -> bool {
    NAMEPLATE_COLUMNS.contains(&name)
}

/// Copy the contracts out, then say what was written. **Action.**
fn write_bundle(request: &Request) -> Result<String, CliError> {
    let members = request.members()?;
    refuse_identifying_directories(&members)?;

    let bundled = members
        .iter()
        .map(|member| bundle_one(member, request.out))
        .collect::<Result<Vec<_>, _>>()?;

    let manifest = Manifest::new(
        &request.site,
        anchor(text_of(&bundled, "prices.csv")),
        bundled.iter().map(|one| one.entry.clone()).collect(),
        Written {
            tool_version: TOOL_VERSION.to_owned(),
            created_at: clock::created_at()?,
        },
    );
    let path = request.out.join(MANIFEST);
    files::write(&path, &manifest.to_json()?)?;

    Ok(written(&manifest, &bundled, &path))
}

/// Read one file, filter it to its contract, write it. **Action.**
///
/// The `map_err` gives the refusal the path it was reading, which is context
/// the calculation below cannot have: `strip` sees text, not a file name.
fn bundle_one(member: &Member, out: &Path) -> Result<Bundled, CliError> {
    let source = files::read_text(member.source)?;
    let (text, dropped, rows) = match member.content {
        Content::Table(allows) => {
            let stripped = strip(&source, allows).map_err(|detail| CliError::Contract {
                path: member.source.to_owned(),
                detail,
            })?;
            (stripped.text, stripped.dropped, Some(stripped.rows))
        }
        Content::Opaque => (source, Vec::new(), None),
    };
    files::write(&out.join(member.name), &text)?;
    Ok(Bundled {
        entry: FileEntry {
            name: member.name.to_owned(),
            sha256: sha256_hex(text.as_bytes()),
            rows,
        },
        dropped,
        text,
    })
}

/// Refuse every directory an input lives in that holds identifying data.
/// **Action.**
///
/// The inputs themselves are in those directories, so an export whose own
/// header names a user is refused too — which is the point. A column that
/// would have been dropped from one file is still identifying data sitting on
/// the operator's disk, and the answer to that is a conversation, not a
/// quieter copy.
fn refuse_identifying_directories(members: &[Member]) -> Result<(), CliError> {
    let directories: BTreeSet<PathBuf> = members
        .iter()
        .map(|member| member.source.parent().unwrap_or(Path::new(".")).to_owned())
        .collect();

    let found = directories
        .iter()
        .map(|directory| identifying_files(directory))
        .collect::<Result<Vec<_>, _>>()?
        .concat();

    match found.into_iter().next() {
        Some((path, columns)) => Err(CliError::Identifying { path, columns }),
        None => Ok(()),
    }
}

/// Which tables in a directory carry identifying columns. **Action.**
fn identifying_files(directory: &Path) -> Result<Vec<(PathBuf, String)>, CliError> {
    let mut found = Vec::new();
    for path in files::files_in(directory)?
        .into_iter()
        .filter(|path| is_table(path))
    {
        let columns = identifying_columns(&files::first_line(&path)?);
        if !columns.is_empty() {
            found.push((path, columns.join(", ")));
        }
    }
    Ok(found)
}

/// Whether a file is one the tripwire can read a header out of.
/// **Calculation.**
fn is_table(path: &Path) -> bool {
    matches!(extension(path).as_str(), "csv" | "tsv")
}

/// The columns of a header that identify people or machines. **Calculation.**
///
/// Matched on a column's *segments*, not on a substring: `sacct` writes
/// `JobName` and `NodeList`, which a substring test on a lowercased header
/// would miss, while `nameplate_gpus` is not a name and a substring test would
/// refuse it.
fn identifying_columns(header: &str) -> Vec<String> {
    header
        .split(',')
        .map(str::trim)
        .filter(|column| {
            segments(column)
                .iter()
                .any(|segment| IDENTIFYING.contains(&segment.as_str()))
        })
        .map(str::to_owned)
        .collect()
}

/// A column name's words, lowercased. **Calculation.**
///
/// Split on anything that is not a letter or a digit, and again where a
/// lowercase run meets a capital, so `node_list`, `NodeList` and `node list`
/// are the same two words.
fn segments(column: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut inside_word = false;
    for character in column.chars() {
        if !character.is_ascii_alphanumeric() {
            words.extend(finished(&mut word));
            inside_word = false;
            continue;
        }
        if inside_word && character.is_ascii_uppercase() {
            words.extend(finished(&mut word));
        }
        word.push(character.to_ascii_lowercase());
        inside_word = !character.is_ascii_uppercase();
    }
    words.extend(finished(&mut word));
    words
}

/// The word just ended, if there was one. **Calculation.**
fn finished(word: &mut String) -> Option<String> {
    (!word.is_empty()).then(|| std::mem::take(word))
}

/// One file filtered to its contract.
#[derive(Debug)]
struct Stripped {
    text: String,
    dropped: Vec<String>,
    rows: usize,
}

/// Keep the columns a contract declares, in the file's own order.
/// **Calculation.**
///
/// The output is LF with a trailing newline whatever the input was, so a
/// bundle made on Windows and one made on Linux hash the same. Cells are
/// trimmed, which is the same normalisation the ingest adapters apply.
fn strip(text: &str, allows: Allows) -> Result<Stripped, String> {
    let mut lines = text.lines();
    let header = lines.next().ok_or("the file has no header row")?;
    let columns: Vec<&str> = header.split(',').map(str::trim).collect();

    let kept: Vec<usize> = columns
        .iter()
        .enumerate()
        .filter(|(_, column)| allows(column))
        .map(|(at, _)| at)
        .collect();
    if kept.is_empty() {
        return Err("no column in the header belongs to the contract".to_owned());
    }

    let rows: Vec<String> = lines
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(offset, line)| row(line, columns.len(), &kept, offset + 2))
        .collect::<Result<_, _>>()?;

    let counted = rows.len();
    let body = std::iter::once(pick(&columns, &kept))
        .chain(rows)
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Stripped {
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

/// One data row, filtered to the kept columns. **Calculation.**
fn row(line: &str, width: usize, kept: &[usize], number: usize) -> Result<String, String> {
    let cells: Vec<&str> = line.split(',').map(str::trim).collect();
    if cells.len() == width {
        Ok(pick(&cells, kept))
    } else {
        Err(format!(
            "line {number}: the header has {width} columns, this row has {}",
            cells.len()
        ))
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

/// The bundled text of one member, if the bundle holds it. **Calculation.**
fn text_of<'a>(bundled: &'a [Bundled], name: &str) -> Option<&'a str> {
    bundled
        .iter()
        .find(|one| one.entry.name == name)
        .map(|one| one.text.as_str())
}

/// The price series' calendar anchor and length. **Calculation.**
///
/// `t0` is the `timestamp_iso` of hour 0 — the anchor a console dates
/// everything from — and `hours` is how many hours the series carries. Both
/// are read back out of the bundled file, so the manifest describes the bundle
/// rather than the input it was made from.
fn anchor(prices_csv: Option<&str>) -> Window {
    let empty = Window { t0: None, hours: 0 };
    let Some(text) = prices_csv else {
        return empty;
    };
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return empty;
    };
    let columns: Vec<&str> = header.split(',').map(str::trim).collect();
    let rows: Vec<Vec<&str>> = lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split(',').map(str::trim).collect())
        .collect();

    let cell = |row: &Vec<&str>, column| {
        column_at(&columns, column)
            .and_then(|at| row.get(at).copied())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    Window {
        t0: rows
            .iter()
            .find(|row| cell(row, prices::HOUR_INDEX).as_deref() == Some("0"))
            .and_then(|row| cell(row, prices::TIMESTAMP_ISO)),
        hours: rows.len(),
    }
}

fn column_at(columns: &[&str], wanted: &str) -> Option<usize> {
    columns.iter().position(|column| *column == wanted)
}

/// What a written bundle reports. **Calculation.**
fn written(manifest: &Manifest, bundled: &[Bundled], path: &Path) -> String {
    let files = manifest
        .files()
        .iter()
        .map(|entry| match entry.rows {
            Some(rows) => format!("{} ({rows} rows)", entry.name),
            None => entry.name.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    [
        labelled("site:", manifest.site_alias()),
        labelled("hours:", &manifest.hours().to_string()),
        labelled("files:", &files),
        labelled("dropped:", &dropped(bundled)),
        labelled("wrote:", &path.to_string_lossy()),
    ]
    .join("\n")
}

/// Which columns the bundle left behind, per file. **Calculation.**
///
/// Reported rather than silently removed: an export with a column the contract
/// does not know is something the operator should hear about, whether it was
/// a harmless extra or a name.
fn dropped(bundled: &[Bundled]) -> String {
    let reported: Vec<String> = bundled
        .iter()
        .filter(|one| !one.dropped.is_empty())
        .map(|one| format!("{} ({})", one.entry.name, one.dropped.join(" ")))
        .collect();
    if reported.is_empty() {
        "nothing".to_owned()
    } else {
        reported.join(", ")
    }
}

/// Recompute a bundle against its manifest. **Action.**
fn verify_bundle(directory: &Path) -> Result<String, CliError> {
    let manifest = Manifest::from_json(&files::read_text(&directory.join(MANIFEST))?)?;

    let faults: Vec<String> = manifest
        .files()
        .iter()
        .filter_map(|entry| fault(directory, entry))
        .chain(unlisted(directory, &manifest)?)
        .collect();

    if faults.is_empty() {
        Ok([
            labelled("site:", manifest.site_alias()),
            labelled("files:", &manifest.files().len().to_string()),
            labelled("verified:", &directory.to_string_lossy()),
        ]
        .join("\n"))
    } else {
        Err(CliError::Verify {
            directory: directory.to_owned(),
            faults: faults.join("; "),
        })
    }
}

/// What is wrong with one listed file, if anything. **Action.**
///
/// A file the manifest lists and the bundle does not hold is a fault, not a
/// read failure: verify's answer is about the bundle, so it reports every
/// fault it found rather than stopping at the first unreadable name.
fn fault(directory: &Path, entry: &FileEntry) -> Option<String> {
    let path = directory.join(&entry.name);
    let Ok(bytes) = files::read_bytes(&path) else {
        return Some(format!(
            "{}: listed in the manifest, not readable in the bundle",
            entry.name
        ));
    };

    let found = sha256_hex(&bytes);
    if found != entry.sha256 {
        return Some(format!(
            "{}: sha256 is {found}, the manifest says {}",
            entry.name, entry.sha256
        ));
    }
    entry
        .rows
        .map(|listed| (listed, data_rows(&String::from_utf8_lossy(&bytes))))
        .filter(|(listed, found)| listed != found)
        .map(|(listed, found)| {
            format!(
                "{}: {found} data rows, the manifest says {listed}",
                entry.name
            )
        })
}

/// Files in a bundle the manifest does not account for. **Action.**
///
/// A bundle is the contract files and nothing else, so something that arrived
/// later is as much a mismatch as a changed byte.
fn unlisted(directory: &Path, manifest: &Manifest) -> Result<Vec<String>, CliError> {
    let listed: BTreeSet<&str> = manifest
        .files()
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    Ok(files::files_in(directory)?
        .into_iter()
        .filter_map(|path| {
            let name = path.file_name()?.to_string_lossy().into_owned();
            (name != MANIFEST && !listed.contains(name.as_str()))
                .then(|| format!("{name}: in the bundle, not in the manifest"))
        })
        .collect())
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
    use loadshift_ingest::schema::jobs;

    use super::*;

    const JOBS_HEADER: &str = "id,tier,gpus,act_hours,arrival_h,dur_h,deadline_h,pad_h";

    fn stripped(text: &str, allows: Allows) -> Stripped {
        strip(text, allows).expect("the fixture matches its contract")
    }

    fn bundled_file(name: &str, rows: Option<usize>, dropped: Vec<String>) -> Bundled {
        Bundled {
            entry: FileEntry {
                name: name.to_owned(),
                sha256: sha256_hex(name.as_bytes()),
                rows,
            },
            dropped,
            text: String::new(),
        }
    }

    #[test]
    fn the_jobs_contract_is_the_declared_catalogue() {
        assert!(jobs_column(jobs::ID));
        assert!(jobs_column(jobs::PAD_H));
        assert!(!jobs_column("carbon_gco2"));
    }

    #[test]
    fn a_column_the_contract_declares_survives_and_one_it_does_not_is_dropped() {
        let csv = format!("{JOBS_HEADER},carbon_gco2\n0,2,1.0,0.8,1,4,169,4,12\n");

        let bundled = stripped(&csv, jobs_column);

        assert_eq!(
            bundled.text,
            format!("{JOBS_HEADER}\n0,2,1.0,0.8,1,4,169,4\n")
        );
        assert_eq!(bundled.dropped, vec!["carbon_gco2".to_owned()]);
        assert_eq!(bundled.rows, 1);
    }

    #[test]
    fn v1s_own_annotation_columns_are_part_of_the_jobs_contract_and_stay() {
        let csv = "id,tier,gpus,act_hours,arrival_h,dur_h,deadline_h,voltiq_start_h,pad_h,dollar_delta\n\
                   0,2,1.0,0.8,1,4,169,92,4,0\n";

        let bundled = stripped(csv, jobs_column);

        assert!(bundled.dropped.is_empty(), "got {:?}", bundled.dropped);
        assert!(bundled.text.contains("voltiq_start_h"));
    }

    #[test]
    fn a_crlf_file_is_rewritten_as_lf_so_a_hash_does_not_depend_on_the_platform() {
        let bundled = stripped(
            &format!("{JOBS_HEADER}\r\n0,2,1.0,0.8,1,4,169,4\r\n"),
            jobs_column,
        );

        assert!(!bundled.text.contains('\r'), "got {:?}", bundled.text);
        assert!(bundled.text.ends_with("169,4\n"));
    }

    #[test]
    fn a_trailing_blank_line_is_not_a_row() {
        let bundled = stripped(
            &format!("{JOBS_HEADER}\n0,2,1.0,0.8,1,4,169,4\n\n"),
            jobs_column,
        );

        assert_eq!(bundled.rows, 1);
        assert!(bundled.text.ends_with("169,4\n"));
    }

    #[test]
    fn a_row_with_the_wrong_number_of_cells_is_named_by_line_rather_than_re_columned() {
        let csv = format!("{JOBS_HEADER}\n0,2,1.0,0.8,1,4,169,4\n1,2,1.0\n");

        let error = strip(&csv, jobs_column).expect_err("that row is not on the contract");

        assert!(error.contains("line 3"), "got {error}");
    }

    #[test]
    fn a_file_with_no_contract_column_at_all_is_refused() {
        let error = strip("user,job_name\nnathan,train\n", jobs_column)
            .expect_err("that is not a jobs file");

        assert!(error.contains("no column"), "got {error}");
    }

    #[test]
    fn an_empty_file_is_refused_rather_than_bundled_as_nothing() {
        assert!(strip("", jobs_column).is_err());
    }

    #[test]
    fn the_nameplate_contract_is_its_two_columns_and_no_more() {
        let csv = "hour_index,nameplate_gpus,rack\n0,6122,A1\n";

        let bundled = stripped(csv, nameplate_column);

        assert_eq!(bundled.text, "hour_index,nameplate_gpus\n0,6122\n");
        assert_eq!(bundled.dropped, vec!["rack".to_owned()]);
    }

    #[test]
    fn a_written_bundle_reports_the_site_the_files_and_what_it_dropped() {
        let site = SiteAlias::parse("site-1").expect("site-1 is an alias");
        let bundled = vec![
            bundled_file("jobs.csv", Some(252), vec!["carbon_gco2".to_owned()]),
            bundled_file("cap_h.json", None, Vec::new()),
        ];
        let manifest = Manifest::new(
            &site,
            Window {
                t0: None,
                hours: 336,
            },
            bundled.iter().map(|one| one.entry.clone()).collect(),
            Written {
                tool_version: "0.1.0".to_owned(),
                created_at: "2026-09-19T12:01:34Z".to_owned(),
            },
        );

        let report = written(&manifest, &bundled, Path::new("export/manifest.json"));

        assert_eq!(
            report,
            concat!(
                "site:     site-1\n",
                "hours:    336\n",
                "files:    jobs.csv (252 rows), cap_h.json\n",
                "dropped:  jobs.csv (carbon_gco2)\n",
                "wrote:    export/manifest.json",
            )
        );
    }

    #[test]
    fn the_prices_contract_covers_settlement_too() {
        let csv = "hour_index,timestamp_iso,price_usd_per_mwh,node\n0,2026-01-19T00:00:00-06:00,23.91,HB_NORTH\n";

        let bundled = stripped(csv, prices_column);

        assert_eq!(bundled.dropped, vec!["node".to_owned()]);
    }

    #[test]
    fn a_sacct_header_is_identifying_however_it_is_spelled() {
        for header in [
            "JobID,JobName,User",
            "jobid,job_name",
            "id,node_list",
            "id,NodeList",
            "id,hostname",
            "id,HostName",
            "id,user",
        ] {
            assert!(
                !identifying_columns(header).is_empty(),
                "{header} identifies someone"
            );
        }
    }

    #[test]
    fn the_nameplate_contract_is_not_a_name() {
        assert!(identifying_columns("hour_index,nameplate_gpus").is_empty());
    }

    #[test]
    fn the_contract_headers_are_not_identifying() {
        for header in [
            JOBS_HEADER,
            "hour_index,timestamp_iso,price_usd_per_mwh",
            "id,tier,gpus,act_hours,arrival_h,dur_h,deadline_h,voltiq_start_h,pad_h,dollar_delta",
        ] {
            assert!(
                identifying_columns(header).is_empty(),
                "{header} is a contract, not a name"
            );
        }
    }

    #[test]
    fn every_identifying_column_of_a_header_is_reported_not_just_the_first() {
        assert_eq!(
            identifying_columns("JobID,User,JobName,NodeList"),
            vec![
                "User".to_owned(),
                "JobName".to_owned(),
                "NodeList".to_owned()
            ]
        );
    }

    #[test]
    fn a_column_name_splits_into_the_same_words_however_it_is_written() {
        assert_eq!(segments("NodeList"), vec!["node", "list"]);
        assert_eq!(segments("node_list"), vec!["node", "list"]);
        assert_eq!(segments("node list"), vec!["node", "list"]);
        assert_eq!(segments("nameplate_gpus"), vec!["nameplate", "gpus"]);
        assert_eq!(segments("h0"), vec!["h0"]);
        assert_eq!(segments("__"), Vec::<String>::new());
    }

    #[test]
    fn the_anchor_is_hour_zeros_timestamp_and_the_series_length() {
        let csv = "hour_index,timestamp_iso,price_usd_per_mwh\n\
                   0,2026-01-19T00:00:00-06:00,23.91\n\
                   1,2026-01-19T01:00:00-06:00,22.50\n";

        assert_eq!(
            anchor(Some(csv)),
            Window {
                t0: Some("2026-01-19T00:00:00-06:00".to_owned()),
                hours: 2,
            }
        );
    }

    #[test]
    fn a_series_that_starts_later_than_hour_zero_has_no_anchor_but_still_has_hours() {
        let csv = "hour_index,timestamp_iso,price_usd_per_mwh\n\
                   1,2026-01-19T01:00:00-06:00,22.50\n";

        assert_eq!(anchor(Some(csv)), Window { t0: None, hours: 1 });
    }

    #[test]
    fn a_series_with_no_timestamps_has_no_anchor() {
        let csv = "hour_index,price_usd_per_mwh\n0,23.91\n";

        assert_eq!(anchor(Some(csv)), Window { t0: None, hours: 1 });
    }

    #[test]
    fn a_bundle_with_no_price_file_has_no_anchor_and_no_hours() {
        assert_eq!(anchor(None), Window { t0: None, hours: 0 });
    }

    #[test]
    fn the_two_nameplate_shapes_get_the_names_the_bundle_uses() {
        assert_eq!(
            nameplate_member(Path::new("cap_h.json"))
                .expect("json is a nameplate shape")
                .name,
            "cap_h.json"
        );
        assert_eq!(
            nameplate_member(Path::new("nodes.CSV"))
                .expect("csv is a nameplate shape")
                .name,
            "nameplate.csv"
        );
    }

    #[test]
    fn a_nameplate_shape_the_bundle_cannot_read_is_refused_before_anything_is_copied() {
        let error = nameplate_member(Path::new("nameplate.parquet"))
            .expect_err("parquet is not one of the two shapes");

        assert!(
            matches!(error, CliError::NameplateShape { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_missing_flag_is_named_rather_than_defaulted() {
        let bundle = Bundle {
            jobs: Some(PathBuf::from("jobs.csv")),
            prices: None,
            settlement: None,
            nameplate: Some(PathBuf::from("cap_h.json")),
            tariff: None,
            site: Some("site-1".to_owned()),
            out: Some(PathBuf::from("out")),
            command: None,
        };

        let error = Request::parse(&bundle).expect_err("a bundle needs its prices");

        assert!(
            matches!(error, CliError::MissingFlag { flag: "--prices" }),
            "got {error}"
        );
    }

    #[test]
    fn a_site_name_is_refused_where_an_alias_belongs() {
        let bundle = Bundle {
            jobs: Some(PathBuf::from("jobs.csv")),
            prices: Some(PathBuf::from("prices.csv")),
            settlement: None,
            nameplate: Some(PathBuf::from("cap_h.json")),
            tariff: None,
            site: Some("Acme Corp".to_owned()),
            out: Some(PathBuf::from("out")),
            command: None,
        };

        let error = Request::parse(&bundle).expect_err("a company name is not an alias");

        assert!(matches!(error, CliError::Site(_)), "got {error}");
    }

    #[test]
    fn a_request_holds_the_contracts_in_the_order_the_bundle_writes_them() {
        let bundle = Bundle {
            jobs: Some(PathBuf::from("jobs.csv")),
            prices: Some(PathBuf::from("prices.csv")),
            settlement: Some(PathBuf::from("rt.csv")),
            nameplate: Some(PathBuf::from("cap_h.json")),
            tariff: Some(PathBuf::from("tariff.json")),
            site: Some("site-1".to_owned()),
            out: Some(PathBuf::from("out")),
            command: None,
        };
        let request = Request::parse(&bundle).expect("every flag is present");

        let names: Vec<&str> = request
            .members()
            .expect("the nameplate is a shape the bundle reads")
            .iter()
            .map(|member| member.name)
            .collect();

        assert_eq!(
            names,
            vec![
                "jobs.csv",
                "prices.csv",
                "settlement.csv",
                "cap_h.json",
                "tariff.json"
            ]
        );
    }

    #[test]
    fn the_optional_contracts_are_simply_absent_when_they_are_not_given() {
        let bundle = Bundle {
            jobs: Some(PathBuf::from("jobs.csv")),
            prices: Some(PathBuf::from("prices.csv")),
            settlement: None,
            nameplate: Some(PathBuf::from("nameplate.csv")),
            tariff: None,
            site: Some("site-1".to_owned()),
            out: Some(PathBuf::from("out")),
            command: None,
        };
        let request = Request::parse(&bundle).expect("every required flag is present");

        let names: Vec<&str> = request
            .members()
            .expect("a CSV is a shape the bundle reads")
            .iter()
            .map(|member| member.name)
            .collect();

        assert_eq!(names, vec!["jobs.csv", "prices.csv", "nameplate.csv"]);
    }

    #[test]
    fn data_rows_do_not_count_the_header_or_a_trailing_newline() {
        assert_eq!(data_rows("h\n1\n2\n"), 2);
        assert_eq!(data_rows("h\n"), 0);
        assert_eq!(data_rows(""), 0);
    }

    #[test]
    fn a_report_of_nothing_dropped_says_so() {
        let bundled = vec![bundled_file("jobs.csv", Some(0), Vec::new())];

        assert_eq!(dropped(&bundled), "nothing");
    }

    #[test]
    fn a_dropped_column_is_reported_against_the_file_it_came_from() {
        let bundled = vec![bundled_file(
            "jobs.csv",
            Some(0),
            vec!["carbon_gco2".to_owned()],
        )];

        assert_eq!(dropped(&bundled), "jobs.csv (carbon_gco2)");
    }

    #[test]
    fn only_a_table_is_inspected_for_a_header() {
        assert!(is_table(Path::new("users.csv")));
        assert!(is_table(Path::new("export.TSV")));
        assert!(!is_table(Path::new("cap_h.json")));
        assert!(!is_table(Path::new("notes")));
    }
}
