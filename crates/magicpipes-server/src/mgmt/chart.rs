//! Small charts of history, drawn on the server as SVG: no script, and the same in every browser.
//!
//! Each chart has one series, so its title names it and color never has to tell series apart
//! (failures in the "bad" color get a chart of their own). The marks stretch to the card's width
//! (`preserveAspectRatio="none"`, lines keep their 2 px), so text stays in HTML around them: the
//! top gridline's value above it, the times below. Hovering a slot shows its values (`<title>`),
//! and a table under each chart has them all, for keyboards and screen readers.

use std::fmt::Write;

use magicpipes_core::rfc3339;

use super::html::esc;
use crate::control::history::Period;

pub(super) const STYLE: &str = r#".periods{display:flex;flex-wrap:wrap;gap:4px;margin:0 0 14px}.periods .btn[aria-current]{border-color:var(--ink);color:var(--ink)}
.charts{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr))}
.chart{padding:18px 20px 16px;min-width:0}.chart h3{font:500 13.5px/1.3 var(--sans);margin:0}.chart .sum{margin:4px 0 0;font-size:13.5px;color:var(--muted);font-variant-numeric:tabular-nums}
.plot{position:relative;margin-top:26px;border-bottom:1px solid var(--line-2)}
.plot svg{display:block;width:100%;height:110px;overflow:visible}
.plot .peak{position:absolute;top:-20px;left:0;font-size:11.5px;color:var(--muted);font-variant-numeric:tabular-nums}
.chart .grid{stroke:var(--line);stroke-width:1px;vector-effect:non-scaling-stroke}
.chart .col,.spark .col{fill:var(--muted)}.chart .col.bad{fill:var(--bad)}
.chart .ln,.spark .ln{fill:none;stroke:var(--accent);stroke-width:2px;stroke-linecap:round;stroke-linejoin:round;vector-effect:non-scaling-stroke}
.chart .hit{fill:transparent}.chart .hit:hover{fill:color-mix(in srgb,var(--ink) 7%,transparent)}
.axis{display:flex;justify-content:space-between;margin-top:6px;font-size:11.5px;color:var(--muted)}
.chart details.more{margin-top:12px}.chart details.more>div{max-width:none}.chart details.more table{font-variant-numeric:tabular-nums}
.chart details.more th,.chart details.more td{padding:6px 10px 6px 0;font-size:12.5px}
.spark{display:block;width:100px;height:22px;margin-top:6px;overflow:visible}td.num .spark{margin-left:auto}
.quiet{margin:22px 0 4px;color:var(--muted);font-size:13.5px}
.pill{display:inline-block;min-width:20px;margin-left:6px;padding:1px 6px;border:1px solid var(--warn);border-radius:999px;font:500 11.5px/1.4 var(--sans);text-align:center;color:var(--ink);font-variant-numeric:tabular-nums}
.pill.bad{background:var(--bad);border-color:var(--bad);color:var(--bg)}
.notice{margin:0 0 12px;padding:12px 16px;border:1px solid var(--line);border-left:3px solid var(--warn);border-radius:10px;background:var(--surface);font-size:13.5px;overflow-wrap:anywhere}
.notice.bad{border-left-color:var(--bad)}.why{display:block;margin-top:4px;font-size:13.5px;color:var(--muted)}details.more.wide>div{max-width:none}.notice .status{font-weight:500;color:var(--ink);margin-right:6px}.notices{margin:24px 0 0}
@media (max-width:480px){.axis .mid{display:none}}"#;

/// Units across the drawing: each slot is 10 wide, and values go up to 100.
const SLOT: usize = 10;
const HIGH: f64 = 100.0;

/// The switch between periods, above what it scopes: those the database keeps enough days for
/// (`history_days`). `href`: the page's address.
pub(super) fn periods(href: &str, period: Period, history_days: u32) -> String {
    let links: String = Period::ALL
        .into_iter()
        .filter(|p| p.days() <= history_days)
        .map(|p| {
            let current = if p == period { r#" aria-current="page""# } else { "" };
            let query = if p == Period::default() { String::new() } else { format!("?period={}", p.key()) };
            let label = match p {
                Period::Minutes15 => "Last 15 minutes",
                Period::Hours24 => "Last 24 hours",
                Period::Days7 => "Last 7 days",
                Period::Days30 => "Last 30 days",
            };
            format!(r#"<a class="btn small ghost" href="{}{query}"{current}>{label}</a>"#, esc(href))
        })
        .collect();
    format!(r#"<nav class="periods" aria-label="Period">{links}</nav>"#)
}

/// What the period is called in a sentence.
pub(super) fn period_words(period: Period) -> &'static str {
    match period {
        Period::Minutes15 => "the last 15 minutes",
        Period::Hours24 => "the last 24 hours",
        Period::Days7 => "the last 7 days",
        Period::Days30 => "the last 30 days",
    }
}

/// What one slot is called: "10 seconds", "5 minutes".
pub(super) fn slot_words(period: Period) -> &'static str {
    match period {
        Period::Minutes15 => "10 seconds",
        Period::Hours24 => "5 minutes",
        Period::Days7 => "an hour",
        Period::Days30 => "6 hours",
    }
}

/// The next round number at or above `v`: 1, 2 or 5 times a power of ten.
pub(super) fn nice_max(v: f64) -> f64 {
    if v <= 0.0 || !v.is_finite() {
        return 1.0;
    }
    let mut step = 10f64.powf(v.log10().floor());
    for m in [1.0, 2.0, 5.0, 10.0] {
        if v <= step * m * (1.0 + 1e-9) {
            step *= m;
            return step;
        }
    }
    step * 10.0
}

/// One chart in a card: a title, a line of totals, the plot, times under it and the table.
pub(super) struct Chart<'a> {
    pub title: &'a str,
    pub summary: String,
    pub period: Period,
    /// When the last slot started (Unix time).
    pub last_slot_at: i64,
    pub plot: Plot,
    /// The top gridline's value, with its unit.
    pub top: String,
    /// The table's column heading for the values, and each slot's value as text (`None`: no row).
    pub column: &'a str,
    pub rows: Vec<Option<String>>,
}

pub(super) enum Plot {
    /// Columns from the baseline, scaled to `max`; `bad` for failures.
    Columns { values: Vec<f64>, max: f64, bad: bool },
    /// A line, broken where there's no value.
    Line { values: Vec<Option<f64>>, max: f64 },
}

impl Chart<'_> {
    pub fn render(&self) -> String {
        let n = match &self.plot {
            Plot::Columns { values, .. } => values.len(),
            Plot::Line { values, .. } => values.len(),
        };
        let slot = self.period.slot_secs();
        let first_at = self.last_slot_at - (n as i64 - 1) * slot;
        let mut svg = format!(
            r#"<svg viewBox="0 0 {w} {h}" preserveAspectRatio="none" role="img" aria-label="{label}"><line class="grid" x1="0" y1="0" x2="{w}" y2="0"/>"#,
            w = n * SLOT,
            h = HIGH,
            label = esc(&format!("{}, {}: {}", self.title, period_words(self.period), self.summary)),
        );
        match &self.plot {
            Plot::Columns { values, max, bad } => {
                let class = if *bad { "col bad" } else { "col" };
                for (i, v) in values.iter().enumerate().filter(|(_, v)| **v > 0.0) {
                    let h = (v / max * HIGH).clamp(1.5, HIGH);
                    let _ = write!(svg, r#"<rect class="{class}" x="{}" y="{:.2}" width="{}" height="{h:.2}"/>"#, i * SLOT + 1, HIGH - h, SLOT - 2);
                }
            }
            Plot::Line { values, max } => {
                for run in runs(values) {
                    let points: Vec<String> =
                        run.iter().map(|(i, v)| format!("{},{:.2}", i * SLOT + SLOT / 2, HIGH - (v / max * HIGH).clamp(0.0, HIGH))).collect();
                    // A lone point is drawn as a dot: a line of no length, with round ends.
                    let points = if points.len() == 1 { format!("{0} {0}", points[0]) } else { points.join(" ") };
                    let _ = write!(svg, r#"<polyline class="ln" points="{points}"/>"#);
                }
            }
        }
        // Hovering a slot says when it was and what it holds.
        for (i, row) in self.rows.iter().enumerate() {
            if let Some(text) = row {
                let at = first_at + i as i64 * slot;
                let _ = write!(svg, r#"<rect class="hit" x="{}" y="0" width="{SLOT}" height="{HIGH}"><title>{}: {}</title></rect>"#, i * SLOT, clock(at), esc(text));
            }
        }
        svg.push_str("</svg>");
        let table: String = self
            .rows
            .iter()
            .enumerate()
            .filter_map(|(i, row)| row.as_ref().map(|text| format!("<tr><td>{}</td><td>{}</td></tr>", clock(first_at + i as i64 * slot), esc(text))))
            .collect();
        let table = if table.is_empty() {
            String::new()
        } else {
            format!(
                r#"<details class="more"><summary>Show as a table</summary><div><table><thead><tr><th>From (UTC)</th><th>{}</th></tr></thead><tbody>{table}</tbody></table></div></details>"#,
                esc(self.column)
            )
        };
        format!(
            r#"<div class="card chart"><h3>{title}</h3><p class="sum">{summary}</p><div class="plot"><span class="peak">{top}</span>{svg}</div>{axis}{table}</div>"#,
            title = esc(self.title),
            summary = esc(&self.summary),
            top = esc(&self.top),
            axis = axis(self.period),
        )
    }
}

/// Consecutive points with values, with their slots.
fn runs(values: &[Option<f64>]) -> Vec<Vec<(usize, f64)>> {
    let mut out: Vec<Vec<(usize, f64)>> = Vec::new();
    let mut current = Vec::new();
    for (i, v) in values.iter().enumerate() {
        match v {
            Some(v) => current.push((i, *v)),
            None if !current.is_empty() => out.push(std::mem::take(&mut current)),
            None => {}
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Times under a chart, evenly spread like its slots; the middle ones go on narrow screens.
fn axis(period: Period) -> String {
    let labels: &[&str] = match period {
        Period::Minutes15 => &["15 min ago", "10 min ago", "5 min ago", "now"],
        Period::Hours24 => &["24 h ago", "18 h ago", "12 h ago", "6 h ago", "now"],
        Period::Days7 => &["7 days ago", "3½ days ago", "now"],
        Period::Days30 => &["30 days ago", "15 days ago", "now"],
    };
    let last = labels.len() - 1;
    let spans: String = labels
        .iter()
        .enumerate()
        .map(|(i, l)| if i == 0 || i == last { format!("<span>{l}</span>") } else { format!(r#"<span class="mid">{l}</span>"#) })
        .collect();
    format!(r#"<div class="axis" aria-hidden="true">{spans}</div>"#)
}

/// `14:05:30` (UTC), or with the date for the long view's rows.
fn clock(at: i64) -> String {
    let ts = rfc3339(at);
    match (ts.get(5..10), ts.get(11..19)) {
        (Some(day), Some(time)) => format!("{day} {time}"),
        _ => ts,
    }
}

/// A tiny chart for a list's row, beside its numbers: columns, or a line broken where there's
/// nothing. Decoration for the number next to it, so hidden from screen readers.
pub(super) fn spark(plot: &Plot) -> String {
    let (n, body) = match plot {
        Plot::Columns { values, max, .. } => {
            let mut b = String::new();
            for (i, v) in values.iter().enumerate().filter(|(_, v)| **v > 0.0) {
                let h = (v / max * HIGH).clamp(4.0, HIGH);
                let _ = write!(b, r#"<rect class="col" x="{}" y="{:.2}" width="{}" height="{h:.2}"/>"#, i * SLOT, HIGH - h, SLOT);
            }
            (values.len(), b)
        }
        Plot::Line { values, max } => {
            let mut b = String::new();
            for run in runs(values) {
                let points: Vec<String> = run.iter().map(|(i, v)| format!("{},{:.2}", i * SLOT + SLOT / 2, HIGH - (v / max * HIGH).clamp(0.0, HIGH))).collect();
                let points = if points.len() == 1 { format!("{0} {0}", points[0]) } else { points.join(" ") };
                let _ = write!(b, r#"<polyline class="ln" points="{points}"/>"#);
            }
            (values.len(), b)
        }
    };
    format!(r#"<svg class="spark" viewBox="0 0 {} {HIGH}" preserveAspectRatio="none" aria-hidden="true" focusable="false">{body}</svg>"#, n * SLOT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_maxima() {
        assert_eq!(nice_max(0.0), 1.0);
        assert_eq!(nice_max(1.0), 1.0);
        assert_eq!(nice_max(3.0), 5.0);
        assert_eq!(nice_max(42.0), 50.0);
        assert_eq!(nice_max(51.0), 100.0);
        assert_eq!(nice_max(0.004), 0.005);
        assert_eq!(nice_max(1_200.0), 2_000.0);
    }

    #[test]
    fn lines_break_where_nothing_is_known() {
        let v = [None, Some(1.0), Some(2.0), None, Some(3.0)];
        assert_eq!(runs(&v), vec![vec![(1, 1.0), (2, 2.0)], vec![(4, 3.0)]]);
        let chart = Chart {
            title: "Round trip <ms>",
            summary: "x".into(),
            period: Period::Minutes15,
            last_slot_at: 1_000,
            plot: Plot::Line { values: v.to_vec(), max: 5.0 },
            top: "5 ms".into(),
            column: "Round trip",
            rows: vec![None, Some("1 ms".into()), Some("2 ms".into()), None, Some("3 ms".into())],
        }
        .render();
        assert_eq!(chart.matches("<polyline").count(), 2, "{chart}");
        assert!(chart.contains(r#"points="45,40.00 45,40.00""#), "a lone point is a dot: {chart}");
        assert!(chart.contains("Round trip &lt;ms&gt;") && !chart.contains("<ms>"), "escaped: {chart}");
        assert_eq!(chart.matches("<tr><td>").count(), 3, "a row for each slot with a value: {chart}");
        assert!(chart.contains("<title>01-01 00:16:40: 3 ms</title>"), "the last slot started at 1,000 s: {chart}");
    }

    #[test]
    fn columns_are_drawn_only_where_there_is_something() {
        let chart = Chart {
            title: "Requests",
            summary: "3 in all".into(),
            period: Period::Hours24,
            last_slot_at: 0,
            plot: Plot::Columns { values: vec![0.0, 1.0, 0.0, 2.0], max: 2.0, bad: true },
            top: "2".into(),
            column: "Requests",
            rows: vec![None; 4],
        }
        .render();
        assert_eq!(chart.matches(r#"class="col bad""#).count(), 2, "{chart}");
        assert!(chart.contains(r#"<rect class="col bad" x="31" y="0.00" width="8" height="100.00"/>"#), "{chart}");
        assert!(!chart.contains("<details"), "no table without rows: {chart}");
        assert!(chart.contains("24 h ago") && chart.contains(r#"<span class="mid">12 h ago</span>"#));
    }
}
