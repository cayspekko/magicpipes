//! The directory listing page, in the same theme as the management UI.
//!
//! It works without JavaScript (links, checkboxes and the download form are plain HTML); the
//! small inline script adds select-all, the selection summary, sorting and local times.

use std::fmt::Write as _;

use magicpipes_core::theme::{GLYPH, STYLE};

use super::kinds::{self, ICON_SYMBOLS};
use super::{esc, human_size, percent_encode};

pub struct Entry {
    pub name: String,
    pub dir: bool,
    pub size: u64,
    pub modified: Option<i64>,
}

pub struct Page<'a> {
    /// Name of the served directory, shown as the site name.
    pub site: &'a str,
    /// Decoded path segments of this directory below the root.
    pub segments: &'a [String],
    pub entries: &'a [Entry],
    pub omitted: usize,
    /// Per-response CSP nonce for the inline script.
    pub nonce: &'a str,
}

const LISTING_STYLE: &str = r#"
.brand{max-width:70%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag{font-size:12.5px;color:var(--muted);white-space:nowrap}
.crumbs{display:flex;flex-wrap:wrap;align-items:center;gap:4px 8px;font-size:13.5px;color:var(--muted)}
.crumbs a{text-decoration:none}.crumbs a:hover{color:var(--accent)}.crumbs .sep{color:var(--line-2)}
h1{overflow-wrap:anywhere}
.head .btn{margin-bottom:6px}
.list{margin-top:32px}
table.files td{padding:13px 18px}
table.files tbody tr{transition:background .12s}
.ck{width:46px;padding-right:0!important}
input[type=checkbox]{accent-color:var(--ink);width:16px;height:16px;margin:0;vertical-align:middle;cursor:pointer}
th button{all:unset;cursor:pointer;border-radius:4px}th button:hover{color:var(--ink)}
th button:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
th[aria-sort=ascending] button::after{content:" ↑"}th[aria-sort=descending] button::after{content:" ↓"}
.nm{white-space:normal;width:100%}
.nm a{display:flex;align-items:center;gap:13px;text-decoration:none;font-weight:500;min-width:0}
.nm a:hover .fn,.nm a:hover .ic{color:var(--accent)}
.fn{overflow-wrap:anywhere}
.ic{width:22px;height:22px;flex:none;fill:none;stroke:currentColor;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round;color:var(--muted)}
.ic{transition:color .12s}
.meta{display:none;font:400 12.5px var(--sans);color:var(--muted);margin-top:2px}
.c-size,.c-mod{color:var(--muted);font-size:13.5px;font-variant-numeric:tabular-nums}
.act{width:1%;text-align:right;padding-left:4px!important}
.dl{display:inline-flex;padding:7px;border-radius:8px;color:var(--muted);opacity:.75;transition:opacity .12s,background .12s}
tr:hover .dl,.dl:focus-visible{opacity:1}.dl:hover{color:var(--accent);background:var(--bg)}
.dl .ic{width:18px;height:18px;color:inherit}
tr.up .ic{color:var(--muted)}tr.up .fn{color:var(--muted);font-weight:400}
tbody tr.sel td{background:color-mix(in srgb,var(--ink) 5%,var(--surface))}
.bar{position:sticky;bottom:18px;z-index:2;margin-top:18px;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:10px 10px 10px 20px;
background:var(--ink);color:var(--bg);border-radius:12px;box-shadow:0 10px 30px rgb(0 0 0/.16)}
.bar[hidden]{display:none}
.bar span{font-size:14px;font-variant-numeric:tabular-nums}
.bar .actions{display:flex;gap:6px}
.bar .btn{background:var(--bg);border-color:var(--bg);color:var(--ink)}.bar .btn:hover{background:var(--surface);border-color:var(--surface);color:var(--ink)}
.bar .btn.ghost{background:transparent;border-color:transparent;color:var(--bg);opacity:.8}.bar .btn.ghost:hover{opacity:1;background:transparent;color:var(--bg)}
.more{margin:14px 0 0;color:var(--muted);font-size:13.5px}
@media (max-width:640px){.c-size,.c-mod{display:none}.meta{display:block}.tag{display:none}table.files td{padding:12px 12px}.bar{padding-left:16px}}
"#;

const SCRIPT: &str = r#"(()=>{
const form=document.getElementById('files'),all=document.getElementById('all'),bar=document.getElementById('bar'),info=document.getElementById('sel-info');
const boxes=[...form.querySelectorAll('input[name=f]')];
const fmt=n=>{const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return (i?n.toFixed(1):n)+' '+u[i]};
let last=null;
function update(){
  const sel=boxes.filter(b=>b.checked);let bytes=0,dirs=0;
  boxes.forEach(b=>b.closest('tr').classList.toggle('sel',b.checked));
  sel.forEach(b=>{const r=b.closest('tr');if(r.dataset.dir)dirs++;else bytes+=+r.dataset.size});
  if(all){all.checked=boxes.length>0&&sel.length===boxes.length;all.indeterminate=sel.length>0&&sel.length<boxes.length}
  bar.hidden=sel.length===0;
  let t=sel.length+' selected';if(sel.length>dirs)t+=' · '+fmt(bytes);if(dirs)t+=dirs>1?' · '+dirs+' folders':' · 1 folder';
  info.textContent=t;
}
if(all)all.addEventListener('change',()=>{boxes.forEach(b=>b.checked=all.checked);update()});
boxes.forEach(b=>b.addEventListener('click',e=>{
  if(e.shiftKey&&last&&last!==b){const order=[...form.querySelectorAll('input[name=f]')],a=order.indexOf(last),c=order.indexOf(b);
    order.slice(Math.min(a,c),Math.max(a,c)+1).forEach(x=>x.checked=b.checked)}
  last=b;update()}));
document.getElementById('clear').addEventListener('click',()=>{boxes.forEach(b=>b.checked=false);update()});
const p2=n=>String(n).padStart(2,'0');
document.querySelectorAll('time[data-ts]').forEach(t=>{const d=new Date(t.dataset.ts*1000),day=d.getFullYear()+'-'+p2(d.getMonth()+1)+'-'+p2(d.getDate());
  t.textContent=t.closest('.meta')?day:day+' · '+p2(d.getHours())+':'+p2(d.getMinutes());t.title=d.toString()});
const tbody=form.querySelector('tbody'),coll=new Intl.Collator(undefined,{numeric:true,sensitivity:'base'});
let key='name',dir=1;
const cmp=(a,b)=>key==='name'?coll.compare(a.dataset.name,b.dataset.name):(+a.dataset[key]-+b.dataset[key])||coll.compare(a.dataset.name,b.dataset.name);
document.querySelectorAll('th button[data-sort]').forEach(btn=>btn.addEventListener('click',()=>{
  const k=btn.dataset.sort;dir=k===key?-dir:(k==='name'?1:-1);key=k;
  const rows=[...tbody.querySelectorAll('tr[data-name]')];
  rows.sort((a,b)=>(b.dataset.dir?1:0)-(a.dataset.dir?1:0)||dir*cmp(a,b));
  rows.forEach(r=>tbody.appendChild(r));
  document.querySelectorAll('th[aria-sort]').forEach(th=>th.removeAttribute('aria-sort'));
  btn.closest('th').setAttribute('aria-sort',dir>0?'ascending':'descending');
}));
update();
})();"#;

pub fn render(p: &Page<'_>) -> String {
    let here = p.segments.last().map(String::as_str).unwrap_or(p.site);
    let mut crumbs = format!(r#"<a href="/">{}</a>"#, esc(p.site));
    let mut href = String::from("/");
    for (i, s) in p.segments.iter().enumerate() {
        href.push_str(&percent_encode(s));
        href.push('/');
        crumbs.push_str(r#"<span class="sep">/</span>"#);
        if i + 1 == p.segments.len() {
            let _ = write!(crumbs, "<span>{}</span>", esc(s));
        } else {
            let _ = write!(crumbs, r#"<a href="{href}">{}</a>"#, esc(s));
        }
    }

    let folders = p.entries.iter().filter(|e| e.dir).count();
    let files = p.entries.len() - folders;
    let bytes: u64 = p.entries.iter().filter(|e| !e.dir).map(|e| e.size).sum();
    let plural = |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    let mut summary = Vec::new();
    if folders > 0 {
        summary.push(plural(folders, "folder", "folders"));
    }
    if files > 0 {
        summary.push(plural(files, "file", "files"));
        summary.push(human_size(bytes));
    }
    if summary.is_empty() {
        summary.push("Empty folder".to_string());
    }

    let mut rows = String::new();
    if !p.segments.is_empty() {
        rows.push_str(
            r##"<tr class="up"><td class="ck"></td><td class="nm"><a href="../"><svg class="ic"><use href="#i-up"/></svg><span class="fn">Parent folder</span></a></td><td class="c-size"></td><td class="c-mod"></td><td class="act"></td></tr>"##,
        );
    }
    for e in p.entries {
        rows.push_str(&row(e));
    }
    if p.entries.is_empty() {
        rows.push_str(r#"<tr><td colspan="5" class="empty">This folder is empty.</td></tr>"#);
    }
    let select_all = if p.entries.is_empty() {
        String::new()
    } else {
        r#"<input type="checkbox" id="all" aria-label="Select all">"#.to_string()
    };
    let more = if p.omitted > 0 { format!(r#"<p class="more">{} more entries are not shown.</p>"#, p.omitted) } else { String::new() };

    format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="referrer" content="no-referrer"><title>{title}</title><style>{STYLE}{LISTING_STYLE}</style></head><body>
{ICON_SYMBOLS}
<header class="top"><div class="top-in"><a class="brand" href="/">{GLYPH}{site}</a><span class="tag">Shared with MagicPipes</span></div></header>
<main>
<div class="head"><div>{crumbs}<h1>{here}</h1><p class="lede">{summary}</p></div>
<a class="btn" href="?archive" download><svg class="ic" style="width:16px;height:16px;color:inherit"><use href="#i-download"/></svg>Download folder</a></div>
<form id="files" class="list" method="post" action="./">
<div class="card scroll"><table class="files">
<thead><tr><th class="ck">{select_all}</th><th aria-sort="ascending"><button type="button" data-sort="name">Name</button></th><th class="num c-size"><button type="button" data-sort="size">Size</button></th><th class="c-mod"><button type="button" data-sort="mtime">Modified</button></th><th class="act"></th></tr></thead>
<tbody>{rows}</tbody></table></div>{more}
<div class="bar" id="bar"><span id="sel-info">Selected items</span><span class="actions"><button type="button" class="btn ghost small" id="clear">Clear</button><button class="btn small" type="submit"><svg class="ic" style="width:16px;height:16px;color:inherit"><use href="#i-download"/></svg>Download .tar.gz</button></span></div>
</form>
</main>
<footer class="foot">Shared with MagicPipes · read-only</footer>
<script nonce="{nonce}">{SCRIPT}</script>
</body></html>
"##,
        title = if p.segments.is_empty() { esc(p.site) } else { esc(&format!("{here} · {}", p.site)) },
        crumbs = if p.segments.is_empty() {
            r#"<div class="eyebrow">Shared folder</div>"#.to_string()
        } else {
            format!(r#"<nav class="crumbs" aria-label="Path">{crumbs}</nav>"#)
        },
        site = esc(p.site),
        here = esc(here),
        summary = summary.join(" · "),
        nonce = p.nonce,
    )
}

fn row(e: &Entry) -> String {
    let kind = kinds::kind(&e.name, e.dir);
    let enc = percent_encode(&e.name);
    let name = esc(&e.name);
    let (href, target, download) = if e.dir {
        (format!("{enc}/"), "", format!("{enc}/?archive"))
    } else if kinds::opens_in_browser(&e.name) {
        (enc.clone(), r#" target="_blank" rel="noopener""#, format!("{enc}?download"))
    } else {
        (format!("{enc}?download"), " download", format!("{enc}?download"))
    };
    let size = if e.dir { "—".to_string() } else { human_size(e.size) };
    let mtime = e.modified.unwrap_or(0);
    let (time, meta_time) = match e.modified {
        Some(m) => {
            let iso = magicpipes_core::rfc3339(m);
            let short = format!("{} · {} UTC", &iso[..10.min(iso.len())], iso.get(11..16).unwrap_or(""));
            (format!(r#"<time data-ts="{m}" datetime="{iso}">{short}</time>"#), format!(r#" · <time data-ts="{m}" datetime="{iso}">{short}</time>"#))
        }
        None => (String::new(), String::new()),
    };
    let meta_size = if e.dir { kind.label().to_string() } else { format!("{} · {size}", kind.label()) };
    format!(
        r##"<tr data-name="{name}" data-size="{bytes}" data-mtime="{mtime}"{dir}><td class="ck"><input type="checkbox" name="f" value="{name}" aria-label="Select {name}"></td><td class="nm"><a class="k-{id}" href="{href}"{target} title="{label}"><svg class="ic"><use href="#i-{id}"/></svg><span><span class="fn">{name}{slash}</span><span class="meta">{meta_size}{meta_time}</span></span></a></td><td class="num c-size">{size}</td><td class="c-mod">{time}</td><td class="act"><a class="dl" href="{download}" download aria-label="Download {name}" title="Download"><svg class="ic"><use href="#i-download"/></svg></a></td></tr>"##,
        bytes = if e.dir { 0 } else { e.size },
        dir = if e.dir { r#" data-dir="1""# } else { "" },
        id = kind.id(),
        label = kind.label(),
        slash = if e.dir { "/" } else { "" },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::serve::kinds::Kind;

    #[test]
    fn every_kind_has_an_icon() {
        for k in [Kind::Folder, Kind::Image, Kind::Audio, Kind::Video, Kind::Pdf, Kind::Text, Kind::Code, Kind::Data, Kind::Archive, Kind::Other] {
            let id = format!(r#"id="i-{}""#, k.id());
            assert!(ICON_SYMBOLS.contains(&id), "{id}");
        }
    }

    #[test]
    fn names_are_escaped_everywhere() {
        let entries = [Entry { name: r#"<b>"x'.mp3"#.into(), dir: false, size: 3, modified: Some(0) }];
        let html = render(&Page { site: "Site<1", segments: &["Dir&2".into()], entries: &entries, omitted: 0, nonce: "n" });
        assert!(!html.contains("<b>") && !html.contains("Site<1") && !html.contains("Dir&2"), "{html}");
        assert!(html.contains("Site&lt;1") && html.contains("Dir&amp;2"));
        assert!(html.contains("&lt;b&gt;&quot;x&#39;.mp3") && html.contains("%3Cb%3E%22x%27.mp3"));
    }
}
