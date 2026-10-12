// SPDX-License-Identifier: Apache-2.0
//! Honest omission for the lossy entropy and density views.
//!
//! Both views shed lines. They used to do it silently, so a model saw code
//! that looked complete but lacked a table row, an enum's variants or a
//! declaration. These helpers keep every fact the view would otherwise lose
//! and mark each omitted run as `[lean-ctx: omitted N lines]` — the marker the
//! edit guards already reject if it is ever written back to a file.

use crate::core::tokens::count_tokens;

/// Why a line survives or leaves the view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LineFate {
    Keep,
    /// Among the file's most predictable lines (#1910), or outside a density
    /// budget.
    Predictable,
    /// Repeats an earlier near-identical block (Jaccard dedup).
    Duplicate,
}

/// Terms whose loss would lose information: string literals and code-shaped
/// identifiers (`snake_case`, `CamelCase`, digits). Plain words are not
/// counted, so prose and comments stay compressible.
pub(super) fn coverage_terms(line: &str) -> impl Iterator<Item = &str> {
    static TERM: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = TERM.get_or_init(|| {
        regex::Regex::new(r#""(?:[^"\\]|\\.)+"|'(?:[^'\\]|\\.){2,}'|[A-Za-z_][A-Za-z0-9_]*"#)
            .expect("BUG: invalid coverage term regex")
    });
    re.find_iter(line).map(|m| m.as_str()).filter(|t| {
        t.starts_with(['"', '\''])
            || (t.len() >= 3
                && (t.contains('_')
                    || t.bytes().any(|b| b.is_ascii_digit())
                    || t.bytes().skip(1).any(|b| b.is_ascii_uppercase())))
    })
}

/// Rescue every dropped line that holds a literal or identifier no kept line
/// carries (file order, so the result is deterministic). The view may shed
/// redundancy, never facts: `re("git", Category::Vcs)` in a table of
/// look-alike rows is predictable, but `"git"` exists nowhere else.
/// Returns the number of rescued lines.
pub(super) fn rescue_uncovered_lines(lines: &[&str], fate: &mut [LineFate]) -> usize {
    let mut vocab: std::collections::HashSet<&str> = lines
        .iter()
        .zip(fate.iter())
        .filter(|(_, f)| **f == LineFate::Keep)
        .flat_map(|(l, _)| coverage_terms(l))
        .collect();
    let mut rescued = 0;
    for (line, f) in lines.iter().zip(fate.iter_mut()) {
        if *f != LineFate::Keep && coverage_terms(line).any(|t| !vocab.contains(t)) {
            *f = LineFate::Keep;
            vocab.extend(coverage_terms(line));
            rescued += 1;
        }
    }
    rescued
}

/// Render the kept lines, replacing each run of dropped lines with one
/// `[lean-ctx: omitted N lines]` marker at the run's indentation, so the view
/// never passes for complete source. A run that costs no more tokens than its
/// marker is kept verbatim instead. Returns `(lines, omitted predictable,
/// omitted duplicate)`.
pub(super) fn render_with_omissions(
    lines: &[&str],
    fate: &[LineFate],
) -> (Vec<String>, usize, usize) {
    let mut out = Vec::with_capacity(lines.len());
    let (mut predictable, mut duplicate) = (0, 0);
    let mut i = 0;
    while i < lines.len() {
        if fate[i] == LineFate::Keep {
            out.push(lines[i].to_string());
            i += 1;
            continue;
        }
        let start = i;
        while i < lines.len() && fate[i] != LineFate::Keep {
            i += 1;
        }
        let run = &lines[start..i];
        let indent_len = run[0].len() - run[0].trim_start().len();
        let noun = if run.len() == 1 { "line" } else { "lines" };
        let marker = format!(
            "{}[lean-ctx: omitted {} {noun}]",
            &run[0][..indent_len],
            run.len()
        );
        let run_tokens: usize = run.iter().map(|l| count_tokens(l)).sum();
        if run_tokens <= count_tokens(&marker) {
            out.extend(run.iter().map(|l| (*l).to_string()));
            continue;
        }
        for f in &fate[start..i] {
            match f {
                LineFate::Predictable => predictable += 1,
                LineFate::Duplicate => duplicate += 1,
                LineFate::Keep => {}
            }
        }
        out.push(marker);
    }
    (out, predictable, duplicate)
}

/// Number of dropped runs (= omission markers) in a keep mask.
pub(super) fn omission_runs(keep: &[bool]) -> usize {
    keep.iter()
        .enumerate()
        .filter(|&(i, &k)| !k && (i == 0 || keep[i - 1]))
        .count()
}

/// Change in [`omission_runs`] when the dropped line `idx` is kept: it splits
/// its run (+1) when both neighbours are dropped, closes a one-line run (-1)
/// when neither is, and only shortens the run otherwise.
pub(super) fn gap_delta(keep: &[bool], idx: usize) -> isize {
    let dropped = |i: Option<usize>| i.and_then(|i| keep.get(i)).is_some_and(|k| !k);
    match (dropped(idx.checked_sub(1)), dropped(idx.checked_add(1))) {
        (true, true) => 1,
        (false, false) => -1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_delta_tracks_marker_count() {
        let keep = [false, false, false, true, false, true];
        assert_eq!(omission_runs(&keep), 2);
        assert_eq!(gap_delta(&keep, 1), 1, "splits the first run");
        assert_eq!(gap_delta(&keep, 0), 0, "shortens it from the edge");
        assert_eq!(gap_delta(&keep, 4), -1, "closes a one-line gap");
    }

    #[test]
    fn coverage_counts_literals_and_code_identifiers_not_words() {
        let terms: Vec<&str> =
            coverage_terms(r#"    re("git", Category::Vcs), // the version control row"#).collect();
        assert_eq!(
            terms,
            ["\"git\""],
            "`Category`, `Vcs` and prose words are plain"
        );
        let terms: Vec<&str> = coverage_terms("let parsed_value = HttpClient::new(v2);").collect();
        assert_eq!(terms, ["parsed_value", "HttpClient"]);
    }

    #[test]
    fn short_runs_stay_verbatim_long_runs_are_marked() {
        let lines = [
            "fn a() {",
            "    x,",
            "}",
            "    let first_long_line = compute_something_expensive(alpha, beta);",
            "    let second_long_line = compute_something_expensive(gamma, delta);",
            "end",
        ];
        let fate = [
            LineFate::Keep,
            LineFate::Predictable,
            LineFate::Keep,
            LineFate::Predictable,
            LineFate::Duplicate,
            LineFate::Keep,
        ];
        let (out, predictable, duplicate) = render_with_omissions(&lines, &fate);
        assert_eq!(
            out,
            [
                "fn a() {",
                "    x,",
                "}",
                "    [lean-ctx: omitted 2 lines]",
                "end"
            ],
            "a marker costing more than `x,` keeps the line"
        );
        assert_eq!((predictable, duplicate), (1, 1));
    }
}
