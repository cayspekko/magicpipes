//! Small pieces of markup the UI pages share. None of them knows about a request.

use super::icons::{BACK, MORE, WARNING};

/// Row menus and the question asked before a change; appended to the theme on every page.
pub(super) const STYLE: &str = r#"details.menu{display:inline-block;position:relative;text-align:left}
details.menu>summary{list-style:none;font-size:15px;letter-spacing:1px;padding:5px 10px}details.menu>summary::-webkit-details-marker{display:none}
details.menu[open]>summary{border-color:var(--line-2);color:var(--ink)}
.menu-list{display:flex;flex-direction:column;min-width:12em;margin-top:6px;padding:5px;border:1px solid var(--line);border-radius:10px;background:var(--surface)}
details.menu.float .menu-list{position:fixed;z-index:20;margin:0;box-shadow:0 10px 30px rgba(0,0,0,.14)}
.menu-list form{margin:0}.menu-list hr{border:0;border-top:1px solid var(--line);margin:4px 2px}
.menu-item{display:block;width:100%;text-align:left;font:13.5px/1.2 var(--sans);padding:9px 11px;border:0;border-radius:6px;background:none;color:var(--ink);cursor:pointer;text-decoration:none;white-space:nowrap}
.menu-item:hover{background:var(--hover)}.menu-item:focus-visible{background:var(--hover);outline:2px solid var(--accent);outline-offset:-2px}.menu-item.danger{color:var(--bad)}
dialog{max-height:calc(100% - 48px);padding:20px 22px;border:1px solid var(--line);border-radius:14px;background:var(--surface);color:var(--ink)}dialog::backdrop{background:rgba(0,0,0,.45)}
dialog.ask{width:min(460px,calc(100% - 32px))}.ask p{margin:0;overflow-wrap:anywhere}
.dialog-foot{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:8px;margin-top:18px;padding-top:14px;border-top:1px solid var(--line)}"#;

pub(super) fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// An error message, if there is one.
pub(super) fn alert(msg: Option<&str>) -> String {
    msg.map(|m| format!(r#"<div class="alert with-ic" role="alert">{WARNING}<span>{}</span></div>"#, esc(m))).unwrap_or_default()
}

/// An error about a form, for the top of that form; [`invalid`] ties a field to it.
pub(super) fn form_alert(msg: Option<&str>) -> String {
    msg.map(|m| format!(r#"<div class="alert with-ic" role="alert" id="form-error">{WARNING}<span>{}</span></div>"#, esc(m))).unwrap_or_default()
}

/// A field's attributes when the form's error is about it: announced with the message, and focused.
pub(super) fn invalid(on: bool) -> &'static str {
    if on { r#" aria-invalid="true" aria-describedby="form-error" autofocus"# } else { "" }
}

/// A page's title when its form came back with an error, as a screen reader hears it first.
pub(super) fn title_of(title: &str, has_error: bool) -> String {
    if has_error { format!("Error: {title}") } else { title.to_string() }
}

/// `3 people`, `1 person`.
pub(super) fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The color of a state.
pub(super) fn tone(state: &str) -> &'static str {
    match state {
        "connected" | "ready" => "ok",
        "pending" => "warn",
        "disconnected" | "error" | "failed" => "bad",
        _ => "",
    }
}

/// A status dot plus its label. The tone comes from the state, the text stays the raw state name.
pub(super) fn badge(state: &str) -> String {
    format!(r#"<span class="status {}">{}</span>"#, tone(state), esc(state))
}

/// `2026-10-30T04:08:00Z` -> `2026-10-30 · 04:08 UTC`, with the exact value as a tooltip.
pub(super) fn when(ts: &str) -> String {
    let short = match (ts.get(..10), ts.get(11..16)) {
        (Some(d), Some(t)) if ts.as_bytes().get(10) == Some(&b'T') => format!("{d} · {t} UTC"),
        _ => ts.to_string(),
    };
    format!(r#"<time class="when" datetime="{0}" title="{0}">{1}</time>"#, esc(ts), esc(&short))
}

/// The way back from a page, at its top.
pub(super) fn back(to: &str, label: &str) -> String {
    format!(r#"<a class="crumb" href="{}">{BACK}{}</a>"#, esc(to), esc(label))
}

/// A column of a [`table`].
#[derive(Clone, Copy)]
pub(super) enum Th {
    Text(&'static str),
    Number(&'static str),
    /// The row's buttons. A heading only screen readers need.
    Actions,
}

pub(super) use Th::{Actions, Number, Text};

/// A list in a card, scrolling inside its own box when it's wide. `rows` and `empty` are HTML;
/// `empty` says what's there when there are no rows, and where to go from there.
pub(super) fn table(columns: &[Th], rows: &str, empty: &str) -> String {
    let head: String = columns
        .iter()
        .map(|c| match c {
            Text(label) => format!("<th>{label}</th>"),
            Number(label) => format!(r#"<th class="num">{label}</th>"#),
            Actions => r#"<th aria-label="Actions"></th>"#.to_string(),
        })
        .collect();
    let nothing = format!(r#"<tr><td colspan="{}" class="empty">{empty}</td></tr>"#, columns.len());
    let rows = if rows.is_empty() { nothing.as_str() } else { rows };
    format!(r#"<div class="card scroll"><table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table></div>"#)
}

/// A row's "More actions" menu. Without scripts the list opens in place; `ui.js` floats it next
/// to the button.
pub(super) fn row_menu(subject: &str, items: &[String]) -> String {
    format!(
        r#"<details class="menu"><summary class="btn small ghost" aria-label="More actions for {}" title="More actions">{MORE}</summary><div class="menu-list">{}</div></details>"#,
        esc(subject),
        items.concat()
    )
}

/// A menu entry that posts `fields` to `action`; `csrf`: the form's hidden field; `confirm`: a
/// question asked first (by `ui.js`).
pub(super) fn menu_post(action: &str, csrf: &str, fields: &[(&str, &str)], label: &str, danger: bool, confirm: Option<&str>) -> String {
    let hidden: String = fields.iter().map(|(k, v)| format!(r#"<input type="hidden" name="{}" value="{}">"#, esc(k), esc(v))).collect();
    format!(
        r#"<form method="post" action="{action}"{confirm}>{csrf}{hidden}<button class="menu-item{danger}">{label}</button></form>"#,
        action = esc(action),
        confirm = confirm.map(|c| format!(r#" data-confirm="{}""#, esc(c))).unwrap_or_default(),
        danger = if danger { " danger" } else { "" },
        label = esc(label),
    )
}

/// One tag. `title`: the tag itself, where `shown` is a person's name for it.
pub(super) fn tag_chip(shown: &str, title: Option<&str>) -> String {
    let title = title.map(|t| format!(r#" title="{}""#, esc(t))).unwrap_or_default();
    format!(r#"<code class="tag"{title}>{}</code>"#, esc(shown))
}

/// Tags as small chips that wrap; `none` when empty.
pub(super) fn chips(tags: &[String]) -> String {
    if tags.is_empty() {
        return r#"<span class="sub">none</span>"#.into();
    }
    let list: Vec<String> = tags.iter().map(|t| tag_chip(t, None)).collect();
    format!(r#"<span class="taglist">{}</span>"#, list.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_chips_that_escape_what_they_show() {
        assert_eq!(chips(&[]), r#"<span class="sub">none</span>"#);
        assert_eq!(chips(&["team:dev".into()]), r#"<span class="taglist"><code class="tag">team:dev</code></span>"#);
        assert_eq!(tag_chip("<ann>", Some("user:\"x")), r#"<code class="tag" title="user:&quot;x">&lt;ann&gt;</code>"#);
    }

    #[test]
    fn a_table_says_what_to_do_when_it_has_no_rows() {
        let columns = [Text("Name"), Number("Requests"), Actions];
        let empty = table(&columns, "", "Nothing yet. Run <code>x</code>.");
        assert!(empty.contains(r#"<td colspan="3" class="empty">Nothing yet. Run <code>x</code>.</td>"#), "{empty}");
        assert!(empty.contains(r#"<th>Name</th><th class="num">Requests</th><th aria-label="Actions"></th>"#), "{empty}");
        let full = table(&columns, "<tr><td>a</td></tr>", "Nothing yet.");
        assert!(full.contains("<tbody><tr><td>a</td></tr></tbody>") && !full.contains("Nothing yet"), "{full}");
    }
}
