//! Editing access tags in the UI: the markup the tag picker in `ui.js` enhances, the plain pages
//! it falls back to without scripts, and reading what those forms submit.
//!
//! A form says which tags were shown (`base`) and which are wanted (`tags`, or checkboxes named
//! `tag`); the server applies only the difference to the tags held now, so two people editing
//! different tags at once don't undo each other.

use std::collections::HashMap;

use magicpipes_core::tags;

use super::AppState;
use crate::authz::Principal;
use super::accounts::form_urlencoded_pairs;
use super::ui::{UiUser, chips, esc};

/// Styles for the picker and its fallback checkboxes; appended to the theme on every page.
pub(super) const STYLE: &str = r#"[hidden]{display:none!important}
.tagcell{display:flex;gap:8px;align-items:center}.tagchips{white-space:normal;min-width:13em;max-width:22em;line-height:1.8}
.chip.add{color:var(--ok)}.chip.remove{color:var(--bad);text-decoration:line-through}
fieldset.tags{border:0;padding:0;margin:22px 0 0;min-width:0}
fieldset.tags legend{padding:0;font-size:13px;font-weight:500;color:var(--ink-2);margin-bottom:8px}
.tagboxes{display:flex;flex-wrap:wrap;gap:0 18px;max-height:18em;overflow:auto}.tagboxes label{margin:8px 0 0}
.tagsum{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center}
dialog.tagpick{width:min(600px,calc(100% - 32px));max-height:calc(100% - 48px);padding:20px 22px;border:1px solid var(--line);border-radius:14px;background:var(--surface);color:var(--ink)}
dialog.tagpick[open]{display:flex;flex-direction:column}.tp-list{overflow:auto;min-height:6em;flex:1 1 auto}
dialog.tagpick::backdrop{background:rgba(0,0,0,.45)}
.tp-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:14px}.tp-head h3{margin:0}
.tp-meta{display:flex;justify-content:space-between;gap:12px;font-size:12.5px;color:var(--muted);margin:6px 2px 0}
.tp-tray{margin-top:12px;padding:10px 12px;border-radius:10px;background:var(--bg)}
.tp-empty-tray{font-size:13px;color:var(--muted)}.tp-warn{margin:8px 0 0;font-size:12.5px;color:var(--bad)}
.tp-key{font:12px var(--mono);color:var(--muted);margin:14px 0 6px}
.pills{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.pill{display:inline-flex;align-items:center;gap:6px;font:12.5px/1.4 var(--mono);padding:4px 5px 4px 11px;border-radius:999px;border:1px solid var(--line-2);background:var(--surface);color:var(--ink);cursor:pointer}
.pill:hover{border-color:var(--ink)}.pill:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.pill .act{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:50%;background:var(--hover);color:var(--muted);font-size:13px}
.pill.held{background:var(--hover)}
.pill.add{background:color-mix(in srgb,var(--ok) 14%,var(--surface));border-color:color-mix(in srgb,var(--ok) 45%,var(--line));color:var(--ok)}
.pill.remove{background:color-mix(in srgb,var(--bad) 12%,var(--surface));border-color:color-mix(in srgb,var(--bad) 45%,var(--line));color:var(--bad)}
.pill.remove .nm{text-decoration:line-through}.pill.add .act,.pill.remove .act{background:transparent;color:inherit}
.pill[aria-disabled]{cursor:not-allowed;color:var(--muted);border-style:dashed}.pill[aria-disabled]:hover{border-color:var(--line-2)}
.pill mark{background:color-mix(in srgb,var(--warn) 30%,transparent);color:inherit;border-radius:2px}
.tp-create{margin-top:12px;padding:5px 12px;border-style:dashed;border-color:var(--accent);color:var(--accent);font-family:var(--sans)}.tp-syntax{margin:10px 2px 0;font-size:12.5px}
.tp-new{font:10.5px/1 var(--sans);text-transform:uppercase;letter-spacing:.04em;padding:2px 5px;border-radius:5px;background:color-mix(in srgb,currentColor 14%,transparent)}
.tp-foot{display:flex;justify-content:flex-end;gap:8px;margin-top:18px;padding-top:14px;border-top:1px solid var(--line)}"#;

/// The registered tags as JSON for the picker, on administrators' pages. A data block isn't run,
/// so the CSP doesn't apply; `<` is escaped so a description can't end the element.
pub(super) fn registry(app: &AppState, user: &UiUser) -> String {
    if !user.who.is_admin() {
        return String::new();
    }
    let list: Vec<serde_json::Value> =
        app.control.tags(&user.who).into_iter().map(|t| serde_json::json!({ "n": t.name, "d": t.description })).collect();
    let json = serde_json::to_string(&list).unwrap_or_else(|_| "[]".into()).replace('<', "\\u003c");
    format!(r#"<script type="application/json" id="mp-tags">{json}</script>"#)
}

/// Whose tags a cell edits, for the picker's wording.
#[derive(Clone, Copy)]
pub(super) enum Holder {
    User,
    Agent,
}

/// What a row's tag Edit link opens: the picker, or without scripts the page at `href` (which
/// also takes the picker's POST).
pub(super) struct Edit<'a> {
    pub held: &'a [String],
    pub href: String,
    /// Whose tags, as the picker and screen readers name it.
    pub subject: &'a str,
    pub addable: bool,
    pub holder: Holder,
    /// Private tunnels per tag that removing it would close.
    pub reach: Option<&'a HashMap<String, usize>>,
}

impl Edit<'_> {
    /// The row's tags with a small Edit link next to them.
    pub fn cell(&self, user: &UiUser) -> String {
        if self.held.is_empty() && !self.addable {
            return chips(self.held);
        }
        let label = format!("Edit tags of {}", self.subject);
        format!(r#"<div class="tagcell"><span class="tagchips">{}</span>{}</div>"#, chips(self.held), self.link(user, "btn small ghost", "Edit", &label))
    }

    /// A link that opens the picker; `aria` names it for screen readers when `text` is short.
    pub fn link(&self, user: &UiUser, class: &str, text: &str, aria: &str) -> String {
        let reach: Vec<String> =
            self.reach.map(|r| self.held.iter().filter_map(|t| r.get(t).map(|n| format!("{t}={n}"))).collect()).unwrap_or_default();
        format!(
            r#"<a class="{class}" href="{href}" aria-label="{aria}" data-tag-edit data-subject="{subject}" data-held="{held}" data-addable="{addable}" data-reach="{reach}" data-reach-kind="{kind}" data-csrf="{csrf}">{text}</a>"#,
            class = esc(class),
            href = esc(&self.href),
            aria = esc(aria),
            subject = esc(self.subject),
            held = esc(&self.held.join(" ")),
            addable = if self.addable { "1" } else { "0" },
            reach = esc(&reach.join(" ")),
            kind = match self.holder {
                Holder::User => "user",
                Holder::Agent => "agent",
            },
            csrf = esc(&user.csrf),
            text = esc(text),
        )
    }
}

/// Checkboxes named `tag` for `(name, description)` pairs, in a fieldset. With `picker` the
/// script replaces them with a summary and a "Choose tags" button that opens the picker.
pub(super) fn fieldset(legend: &str, all: &[(String, String)], checked: &[String], picker: Option<&str>) -> String {
    let boxes: String = all
        .iter()
        .map(|(name, description)| {
            format!(
                r#"<label title="{d}"><input type="checkbox" name="tag" value="{n}"{c}> <code>{n}</code></label>"#,
                n = esc(name),
                d = esc(description),
                c = if checked.contains(name) { " checked" } else { "" },
            )
        })
        .collect();
    let boxes = if boxes.is_empty() { r#"<p class="note" style="margin:0">None yet: create them under <a href="/tags">Tags</a>.</p>"#.to_string() } else { boxes };
    let picker = picker.map(|subject| format!(r#" data-picker data-title="{0}" data-subject="{1}""#, esc(legend), esc(subject))).unwrap_or_default();
    format!(r#"<fieldset class="tags"{picker}><legend>{}</legend><div class="tagboxes">{boxes}</div></fieldset>"#, esc(legend))
}

/// What a tag form submitted.
pub(super) struct Submitted {
    pub csrf: String,
    /// The tags wanted: `tags` (space or comma separated) and every `tag` checkbox.
    pub want: Vec<String>,
    /// The tags shown when the page was made; `None` from a form that replaces the whole list.
    pub base: Option<Vec<String>>,
    /// New tags the picker made up (`create`), registered before the change is applied.
    pub create: Vec<String>,
    /// Every field, for forms with more in them.
    pub fields: Vec<(String, String)>,
}

impl Submitted {
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        let fields = form_urlencoded_pairs(raw);
        let get = |k: &str| fields.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let wanted: Vec<&str> = fields.iter().filter(|(n, _)| n == "tags" || n == "tag").map(|(_, v)| v.as_str()).collect();
        let csrf = get("csrf").unwrap_or("").to_string();
        let want = tags::normalize_list(&wanted)?;
        let base = get("base").map(|b| tags::normalize_list(&[b])).transpose()?;
        let create: Vec<&str> = fields.iter().filter(|(n, _)| n == "create").map(|(_, v)| v.as_str()).collect();
        let create = tags::normalize_list(&create)?;
        Ok(Self { csrf, want, base, create, fields })
    }

    /// Registers the `create` tags that don't exist yet (administrators only: `create_tag`
    /// refuses anyone else). One made meanwhile by someone else is fine.
    pub fn create_missing(&self, app: &AppState, who: &Principal) -> Result<(), String> {
        if self.create.is_empty() {
            return Ok(());
        }
        let known = |n: &str| app.control.tags(who).iter().any(|t| t.name == n);
        for name in self.create.iter().filter(|n| !known(n)) {
            if let Err(e) = app.control.create_tag(who, name, "")
                && !known(name)
            {
                return Err(e.message);
            }
        }
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.iter().find(|(n, _)| n == key).map(|(_, v)| v.as_str())
    }

    /// `(add, remove)` relative to `base`, or `None` to replace the whole list with `want`.
    pub fn change(&self) -> Option<(Vec<String>, Vec<String>)> {
        let base = self.base.as_ref()?;
        let add = self.want.iter().filter(|t| !base.contains(t)).cloned().collect();
        let remove = base.iter().filter(|t| !self.want.contains(t)).cloned().collect();
        Some((add, remove))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_say_what_changed() {
        let f = Submitted::parse(b"csrf=x&base=team%3Adev+env%3Aprod&tags=team%3Adev+team%3Aops").unwrap();
        assert_eq!(f.csrf, "x");
        assert_eq!(f.change(), Some((vec!["team:ops".to_string()], vec!["env:prod".to_string()])));

        // Checkboxes from the page without scripts, with nothing left checked.
        let f = Submitted::parse(b"csrf=x&base=team%3Adev").unwrap();
        assert_eq!(f.change(), Some((vec![], vec!["team:dev".to_string()])));
        let f = Submitted::parse(b"csrf=x&base=&tag=b&tag=a&tag=a").unwrap();
        assert_eq!(f.change(), Some((vec!["a".to_string(), "b".to_string()], vec![])));

        // An older page's text field replaces the list.
        let f = Submitted::parse(b"csrf=x&tags=a%2C+b").unwrap();
        assert_eq!((f.change(), f.want), (None, vec!["a".to_string(), "b".to_string()]));

        assert!(Submitted::parse(b"csrf=x&base=&tags=not+ok%21").is_err());

        // Tags the picker made up, from the dialog (one field) or the enrollment form (several).
        let f = Submitted::parse(b"csrf=x&base=&tags=team%3Aqa&create=Team%3AQA+env%3Anew&create=env%3Anew").unwrap();
        assert_eq!(f.create, ["env:new", "team:qa"]);
        assert!(Submitted::parse(b"csrf=x&create=bad%21").is_err());
    }
}
