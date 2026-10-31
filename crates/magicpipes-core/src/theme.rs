//! The MagicPipes visual theme, shared by the management UI (`magicpipesd`) and the agent's
//! built-in file server, so both look like one product.

/// Warm paper and ink, one terracotta accent, serif display type over a sans body, hairlines
/// instead of shadows. Inline-only: no web fonts or images, so pages work under a strict CSP.
pub const STYLE: &str = r#"
:root{--bg:#f6f4ef;--surface:#fffdf8;--hover:#f8f5ee;--ink:#1d1c1a;--ink-2:#4b4842;--muted:#7a766d;--line:#e6e1d6;--line-2:#d6d0c3;
--accent:#c2562b;--ok:#3f7d50;--warn:#b0741c;--bad:#b23a2c;--term:#1d1c1a;--term-ink:#ece9e2;
--serif:ui-serif,"New York","Iowan Old Style",Georgia,serif;--sans:ui-sans-serif,-apple-system,"Helvetica Neue","Segoe UI",sans-serif;--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#131312;--surface:#1a1a18;--hover:#1f1f1d;--ink:#ece9e2;--ink-2:#c3bfb6;--muted:#8e8a82;--line:#2a2927;--line-2:#3a3834;
--accent:#ec7a4b;--ok:#7cc48e;--warn:#e2a954;--bad:#ef7a6b;--term:#0c0c0b;--term-ink:#ece9e2}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--bg);color:var(--ink);font:15px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration-color:var(--line-2);text-underline-offset:3px}a:hover{color:var(--accent);text-decoration-color:currentColor}
code{font:12.5px var(--mono);color:var(--ink-2)}
.top{border-bottom:1px solid var(--line)}
.top-in,main,.foot{width:100%;max-width:1080px;margin:0 auto;padding-left:24px;padding-right:24px}
.top-in{display:flex;align-items:center;justify-content:space-between;gap:16px;height:64px}
.brand{display:flex;align-items:center;gap:10px;font:400 20px/1 var(--serif);letter-spacing:-.01em;text-decoration:none}
.brand:hover{color:var(--ink)}
.glyph{color:var(--ink)}.glyph .flow{stroke:var(--accent);stroke-dasharray:1.5 3.5}
@media (prefers-reduced-motion:no-preference){.glyph .flow{animation:flow 1.6s linear infinite}}
@keyframes flow{to{stroke-dashoffset:-10}}
main{flex:1;padding-top:44px;padding-bottom:72px}
.foot{padding-top:20px;padding-bottom:28px;font-size:12.5px;color:var(--muted);border-top:1px solid var(--line)}
.eyebrow{font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
h1{font:400 clamp(34px,5.4vw,48px)/1.05 var(--serif);letter-spacing:-.022em;margin:10px 0 12px}
h1 em{font-style:italic;color:var(--accent)}
h2{font:400 23px/1.2 var(--serif);letter-spacing:-.01em;margin:0}
.lede{color:var(--muted);max-width:62ch;margin:0}
.head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap}
.section{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin:52px 0 14px}
.count{font:13px var(--sans);color:var(--muted);margin-left:8px;letter-spacing:0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1px;margin-top:32px;background:var(--line);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.stat{background:var(--surface);padding:18px 20px 16px}
.stat .k{font-size:12.5px;color:var(--muted)}
.stat .v{font:400 34px/1.15 var(--serif);letter-spacing:-.02em;margin-top:6px;font-variant-numeric:tabular-nums}
.stat .v small{font:14px var(--sans);color:var(--muted);letter-spacing:0;margin-left:6px}
.stat .v.sm{font:15px/1.4 var(--sans);letter-spacing:0;margin-top:16px;min-height:23px}
.stat .v.sm .status,.stat .v.sm .when{font-size:15px;color:var(--ink)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{font-size:11px;font-weight:500;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);text-align:left;padding:13px 18px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:15px 18px;border-bottom:1px solid var(--line);vertical-align:middle;white-space:nowrap}
tbody tr:last-child td{border-bottom:0}tbody tr:hover td{background:var(--hover)}
.num{text-align:right;font-variant-numeric:tabular-nums}
.name{font-weight:500;text-decoration:none}
.sub{display:block;margin-top:2px;font:12.5px var(--mono);color:var(--muted);text-decoration:none}
a.sub:hover{color:var(--accent)}
.when{color:var(--muted);font-size:13.5px;font-variant-numeric:tabular-nums}
.empty{padding:36px 20px;text-align:center;color:var(--muted)}
.status{display:inline-flex;align-items:center;gap:8px;font-size:13.5px;color:var(--ink-2)}
.status::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--muted);box-shadow:0 0 0 3px color-mix(in srgb,var(--muted) 16%,transparent)}
.status.ok::before{background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 18%,transparent)}
.status.warn::before{background:var(--warn);box-shadow:0 0 0 3px color-mix(in srgb,var(--warn) 18%,transparent)}
.status.bad::before{background:var(--bad);box-shadow:0 0 0 3px color-mix(in srgb,var(--bad) 18%,transparent)}
form{margin:0}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;font:500 13.5px/1 var(--sans);padding:10px 15px;border-radius:9px;border:1px solid var(--line-2);background:var(--surface);color:var(--ink);cursor:pointer;text-decoration:none;white-space:nowrap;transition:border-color .15s,background .15s,transform .08s}
.btn:hover{border-color:var(--ink);color:var(--ink)}.btn:active{transform:scale(.985)}
.btn.primary{background:var(--ink);border-color:var(--ink);color:var(--bg)}.btn.primary:hover{background:var(--ink-2);border-color:var(--ink-2);color:var(--bg)}
.btn.ghost{background:transparent;border-color:transparent;color:var(--muted)}.btn.ghost:hover{color:var(--ink);border-color:var(--line-2)}
.btn.danger{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 35%,var(--line))}
.btn.danger:hover{border-color:var(--bad);background:color-mix(in srgb,var(--bad) 7%,var(--surface));color:var(--bad)}
.btn.small{padding:7px 11px;font-size:12.5px}.btn.block{width:100%}
.panel{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;padding:22px 24px}
.panel h3{font:400 19px/1.25 var(--serif);margin:0 0 4px}.panel p{margin:0;color:var(--muted);max-width:56ch}
.panel.danger{border-color:color-mix(in srgb,var(--bad) 30%,var(--line))}
.crumb{display:inline-flex;gap:6px;font-size:13.5px;color:var(--muted);text-decoration:none}
dl{display:grid;grid-template-columns:200px 1fr;margin:0}
dt,dd{padding:14px 22px;border-bottom:1px solid var(--line);margin:0}
dt{color:var(--muted);font-size:13.5px}dd{overflow-wrap:anywhere}
dl>:nth-last-child(-n+2){border-bottom:0}
.term{background:var(--term);color:var(--term-ink);border-radius:14px;padding:20px 22px;margin:24px 0 0;overflow-x:auto;font:13.5px/1.6 var(--mono)}
.term .p{color:#8e8a82;user-select:none}
.codebox{position:relative;margin:24px 0 0}.codebox .term{margin:0;padding-right:60px}
.copy{position:absolute;top:12px;right:12px;display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;padding:0;border-radius:8px;border:1px solid #3a3834;background:var(--term);color:#8e8a82;cursor:pointer;transition:color .15s,border-color .15s}
.copy:hover,.copy:focus-visible{color:var(--term-ink);border-color:#8e8a82;outline:none}
.copy.done{color:#7cc48e;border-color:#7cc48e}
.note{margin:16px 0 0;color:var(--muted);font-size:13.5px}
.auth{width:100%;max-width:400px;margin:6vh auto 0}
.auth .card{padding:30px 28px 26px}
label{display:block;font-size:13px;font-weight:500;color:var(--ink-2);margin:22px 0 8px}
input[type=password]{width:100%;font:14px var(--mono);padding:12px 14px;border-radius:10px;border:1px solid var(--line-2);background:var(--bg);color:var(--ink);outline:none;transition:border-color .15s,box-shadow .15s}
input[type=password]:focus{border-color:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 16%,transparent)}
.alert{margin:0 0 20px;padding:11px 14px;border-radius:10px;font-size:13.5px;color:var(--bad);background:color-mix(in srgb,var(--bad) 8%,var(--surface));border:1px solid color-mix(in srgb,var(--bad) 25%,var(--line))}
@media (max-width:640px){.top-in,main,.foot{padding-left:16px;padding-right:16px}main{padding-top:32px}dl{grid-template-columns:1fr}dt{border-bottom:0;padding-bottom:2px}dd{padding-top:0}}
"#;

/// The MagicPipes mark: two endpoints joined by a flowing line.
pub const GLYPH: &str = r#"<svg class="glyph" width="26" height="14" viewBox="0 0 26 14" aria-hidden="true"><line class="flow" x1="6" y1="7" x2="20" y2="7" stroke-width="2.4" stroke-linecap="round"/><circle cx="4.5" cy="7" r="3.2" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="21.5" cy="7" r="3.2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>"#;
