(() => {
  const COPY = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>';
  const DONE = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>';
  // The text a user would want to paste: the block's content without prompt markers.
  const text = (pre) => {
    const c = pre.cloneNode(true);
    c.querySelectorAll('.p').forEach((p) => p.remove());
    return c.textContent.trim();
  };
  const fallback = (s) => {
    const t = document.createElement('textarea');
    t.value = s;
    t.setAttribute('readonly', '');
    t.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(t);
    t.select();
    const ok = document.execCommand('copy');
    t.remove();
    return ok;
  };
  document.querySelectorAll('pre.term:not([data-nocopy])').forEach((pre) => {
    const box = document.createElement('div');
    box.className = 'codebox';
    pre.replaceWith(box);
    box.appendChild(pre);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy';
    btn.title = 'Copy to clipboard';
    btn.setAttribute('aria-label', 'Copy to clipboard');
    btn.innerHTML = COPY;
    let timer;
    btn.addEventListener('click', async () => {
      const s = text(pre);
      let ok;
      try { await navigator.clipboard.writeText(s); ok = true; } catch { ok = fallback(s); }
      if (!ok) return;
      btn.classList.add('done');
      btn.innerHTML = DONE;
      btn.title = 'Copied';
      clearTimeout(timer);
      timer = setTimeout(() => { btn.classList.remove('done'); btn.innerHTML = COPY; btn.title = 'Copy to clipboard'; }, 1600);
    });
    box.appendChild(btn);
  });
})();

// The tag picker: one dialog that lists every tag as a pill, with a filter box and a tray
// of the changes picked so far, applied only on save. It enhances two kinds of markup:
// * `a[data-tag-edit]` next to a row's tags. Without the script the link opens a page of
//   checkboxes; with it, saving posts `base` (the tags shown) and `tags` (the tags wanted) to the
//   same URL, so the server applies only what changed. Attributes: `data-subject`, `data-held`
//   (space separated), `data-addable` ("1" when tags may be added), `data-reach` ("tag=3 …":
//   private tunnels that removing the tag would close) and `data-reach-kind` ("user" or "agent").
// * `fieldset[data-picker]` holding checkboxes named `tag` inside `.tagboxes`: the checkboxes stay
//   in the form and the dialog sets them.
// The registry (`#mp-tags`, JSON `[{"n":name,"d":description}]`) is on the page for administrators.
(() => {
  const data = document.getElementById('mp-tags');
  const admin = !!data;
  const registry = (() => { try { return data ? JSON.parse(data.textContent) : []; } catch { return []; } })();
  const make = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  const words = (s) => (s || '').split(/[\s,]+/).filter(Boolean);
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const GLYPH = { none: '+', held: '−', add: '✓', remove: '−' };
  // The tag syntax (magicpipes_core::tags): `key` or `key:value`, the value may also hold `@`.
  const validTag = (t) => t.length <= 64 && /^[a-z0-9][a-z0-9._-]*(:[a-z0-9][a-z0-9._@-]*)?$/.test(t);

  let dlg, ui, cur;

  const build = () => {
    dlg = make('dialog', 'tagpick');
    dlg.setAttribute('aria-labelledby', 'tp-title');
    dlg.innerHTML = `<div class="tp-head"><div><h3 id="tp-title"></h3><span class="sub tp-subject"></span></div>
<button type="button" class="btn ghost small tp-x" aria-label="Close">×</button></div>
<input type="search" class="tp-q" placeholder="Filter tags · Enter picks the first match" autocomplete="off" spellcheck="false" aria-describedby="tp-count">
<div class="tp-meta"><span id="tp-count" aria-live="polite"></span><span class="tp-hint"></span></div>
<div class="tp-tray"></div><button type="button" class="pill tp-create" hidden></button><p class="note tp-syntax" hidden>A tag is <code>key</code> or <code>key:value</code>, with a-z, 0-9 and <code>._-</code>.</p><div class="tp-list"></div>
<p class="note tp-locked" hidden>You can remove this machine's tags. Adding one takes an administrator.</p>
<div class="tp-foot"><button type="button" class="btn tp-cancel">Cancel</button><button type="button" class="btn primary tp-save"></button></div>`;
    document.body.appendChild(dlg);
    const q = (s) => dlg.querySelector(s);
    ui = { title: q('#tp-title'), subject: q('.tp-subject'), filter: q('.tp-q'), count: q('#tp-count'), hint: q('.tp-hint'),
      tray: q('.tp-tray'), list: q('.tp-list'), locked: q('.tp-locked'), save: q('.tp-save'), create: q('.tp-create'), syntax: q('.tp-syntax') };
    ui.filter.addEventListener('input', update);
    ui.filter.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter') return;
      e.preventDefault();
      const first = firstMatch();
      if (first) toggle(first); else if (newName()) create(newName()); else return;
      ui.filter.value = '';
      update();
    });
    ui.create.addEventListener('click', () => { create(newName()); ui.filter.value = ''; update(); ui.filter.focus(); });
    // Escape clears the filter first, then closes (asking when there are changes to lose).
    dlg.addEventListener('cancel', (e) => {
      e.preventDefault();
      if (ui.filter.value) { ui.filter.value = ''; update(); } else { leave(); }
    });
    q('.tp-x').addEventListener('click', leave);
    q('.tp-cancel').addEventListener('click', () => dlg.close());
    ui.save.addEventListener('click', () => {
      // A form's checkboxes follow even an empty change: undoing everything picked before.
      if (!cur.pending.size && !cur.opts.inForm) { dlg.close(); return; }
      const want = new Set([...cur.held].filter((n) => cur.pending.get(n) !== 'remove'));
      cur.pending.forEach((v, n) => { if (v === 'add') want.add(n); });
      const created = [...cur.created].filter((n) => want.has(n));
      if (cur.opts.onSave(want, created) === 'busy') { ui.save.disabled = true; ui.save.textContent = 'Saving…'; } else { dlg.close(); }
    });
    ui.list.addEventListener('click', (e) => { const p = e.target.closest('.pill'); if (p) { toggle(p.dataset.n); update(); } });
    ui.tray.addEventListener('click', (e) => {
      const p = e.target.closest('.pill');
      if (p) { cur.pending.delete(p.dataset.n); update(); }
      if (e.target.closest('.tp-clear')) { cur.pending.clear(); update(); }
    });
  };

  const leave = () => { if (!cur.pending.size || confirm('Discard your changes to these tags?')) dlg.close(); };
  const stateOf = (n) => cur.pending.get(n) || (cur.held.has(n) ? 'held' : 'none');
  const canAdd = (n) => cur.opts.addable || cur.held.has(n);
  const actionable = (n) => stateOf(n) !== 'none' || canAdd(n);
  const matches = (t, q) => !q || t.n.includes(q) || t.d.toLowerCase().includes(q);
  const query = () => ui.filter.value.trim().toLowerCase();
  const firstMatch = () => { const q = query(); const t = q && cur.tags.find((t) => matches(t, q) && actionable(t.n)); return t ? t.n : null; };

  // What the filter would create: a valid name no tag has, when the viewer may make tags.
  const newName = () => { const q = query(); return cur.opts.creatable && q && validTag(q) && !cur.descs.has(q) ? q : null; };
  const create = (n) => {
    if (!n) return;
    cur.descs.set(n, '');
    cur.tags = [...cur.tags, { n, d: '' }].sort((a, b) => a.n.localeCompare(b.n));
    cur.created.add(n);
    cur.pending.set(n, 'add');
    buildList();
  };

  const toggle = (n) => {
    if (cur.pending.has(n)) cur.pending.delete(n);
    else if (cur.held.has(n)) cur.pending.set(n, 'remove');
    else if (canAdd(n)) cur.pending.set(n, 'add');
  };

  // A pill's name, with the part matching the filter marked.
  const nameNode = (n, q) => {
    const span = make('span', 'nm');
    const i = q ? n.indexOf(q) : -1;
    if (i < 0) { span.textContent = n; return span; }
    span.append(n.slice(0, i), make('mark', null, n.slice(i, i + q.length)), n.slice(i + q.length));
    return span;
  };

  const paint = (pill, n, q, inTray) => {
    const s = stateOf(n);
    const locked = s === 'none' && !canAdd(n);
    const fresh = cur.created.has(n);
    pill.className = `pill ${s}${fresh ? ' new' : ''}`;
    if (locked) pill.setAttribute('aria-disabled', 'true'); else pill.removeAttribute('aria-disabled');
    pill.setAttribute('aria-pressed', String(s === 'add' || s === 'remove'));
    const verb = inTray ? 'undo' : { none: locked ? 'adding a tag takes an administrator' : 'add', held: 'remove', add: 'will be added, undo', remove: 'will be removed, undo' }[s];
    const desc = fresh ? 'New tag, created when you save' : cur.descs.get(n);
    pill.title = desc ? `${desc} (${verb})` : verb;
    pill.setAttribute('aria-label', `${n}: ${verb}`);
    pill.replaceChildren();
    if (inTray) pill.append(make('span', 'sign', s === 'add' ? '+' : '−'));
    pill.append(nameNode(n, q));
    if (fresh) pill.append(make('span', 'tp-new', 'new'));
    pill.append(make('span', 'act', inTray ? '×' : GLYPH[s]));
  };

  const update = () => {
    const q = query();
    let shown = 0;
    for (const g of ui.list.querySelectorAll('.tp-group')) {
      let any = false;
      for (const pill of g.querySelector('.pills').children) {
        const n = pill.dataset.n;
        const hit = matches({ n, d: cur.descs.get(n) || '' }, q);
        pill.hidden = !hit;
        if (hit) { any = true; shown++; paint(pill, n, q, false); }
      }
      g.hidden = !any;
    }
    const total = cur.tags.length;
    ui.count.textContent = q ? `${shown} of ${plural(total, 'tag', 'tags')}` : `${plural(total, 'tag', 'tags')}${cur.held.size ? ` · ${cur.held.size} ${cur.opts.heldWord}` : ''}`;
    const first = firstMatch();
    const fresh = newName();
    ui.hint.textContent = first ? `Enter: ${cur.pending.has(first) ? 'undo' : cur.held.has(first) ? 'remove' : 'add'} ${first}` : fresh ? `Enter: create ${fresh}` : '';
    ui.create.hidden = !fresh;
    if (fresh) ui.create.textContent = `+ Create tag “${fresh}” and add it`;
    ui.syntax.hidden = !(cur.opts.creatable && q && !validTag(q) && !shown);
    if (!shown && !fresh) {
      const empty = make('p', 'note tp-empty');
      if (q) empty.append(`No tag matches “${q}”. `);
      else empty.append(cur.opts.creatable ? 'There are no tags yet. Type a name to create one.' : 'There are no tags yet. ');
      if (!cur.opts.addable) empty.append('An administrator gives out tags.');
      ui.list.querySelector('.tp-empty')?.remove();
      ui.list.append(empty);
    } else {
      ui.list.querySelector('.tp-empty')?.remove();
    }
    const made = [...cur.created].filter((n) => cur.pending.get(n) === 'add').length;
    const adds = [...cur.pending].filter(([, v]) => v === 'add').map(([n]) => n).sort();
    const removes = [...cur.pending].filter(([, v]) => v === 'remove').map(([n]) => n).sort();
    ui.tray.replaceChildren();
    if (!cur.pending.size) {
      ui.tray.append(make('span', 'tp-empty-tray', 'The changes you pick show here. Nothing changes until you save.'));
    } else {
      const row = make('div', 'pills');
      for (const n of [...adds, ...removes]) { const p = make('button'); p.type = 'button'; p.dataset.n = n; paint(p, n, '', true); row.append(p); }
      const clear = make('button', 'btn ghost small tp-clear', 'Clear all');
      clear.type = 'button';
      row.append(clear);
      ui.tray.append(row);
      const closes = removes.reduce((sum, n) => sum + (cur.reach.get(n) || 0), 0);
      if (closes) {
        const these = removes.length === 1 ? 'this tag' : 'these tags';
        const tunnels = plural(closes, 'private tunnel', 'private tunnels');
        ui.tray.append(make('p', 'tp-warn', cur.opts.reachKind === 'agent'
          ? `Up to ${tunnels} of this machine stop admitting people through ${these}, at once.`
          : `Removing ${these} ends access to up to ${tunnels} at once.`));
      }
    }
    const parts = [];
    if (adds.length) parts.push(`add ${adds.length}${made ? ` (${made} new)` : ''}`);
    if (removes.length) parts.push(`remove ${removes.length}`);
    ui.save.disabled = false;
    ui.save.textContent = parts.length ? `${cur.opts.saveWord}: ${parts.join(', ')}` : (cur.opts.saveWord === 'Save' ? 'No changes' : 'Done');
    ui.locked.hidden = cur.opts.addable || !cur.opts.lockedNote;
  };

  // Pills grouped by the part before the colon; tags without one come last.
  const buildList = () => {
    const groups = new Map();
    for (const t of cur.tags) {
      const k = t.n.includes(':') ? t.n.slice(0, t.n.indexOf(':')) : '';
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(t.n);
    }
    const keys = [...groups.keys()].sort((a, b) => (a === '') - (b === '') || a.localeCompare(b));
    ui.list.replaceChildren();
    for (const k of keys) {
      const g = make('div', 'tp-group');
      g.append(make('div', 'tp-key', k || 'other'));
      const row = make('div', 'pills');
      for (const n of groups.get(k)) { const p = make('button'); p.type = 'button'; p.dataset.n = n; row.append(p); }
      g.append(row);
      ui.list.append(g);
    }
  };

  // opts: title, subject, tags [{n, d}], held Set, want Set (defaults to held), addable,
  // creatable (new tags may be made up; the server creates them on save), reach Map,
  // reachKind, heldWord, saveWord, lockedNote, inForm (setting a form's checkboxes, so saving
  // nothing still applies), onSave(want, created) -> 'busy' to stay open.
  const open = (opts) => {
    if (!dlg) build();
    const descs = new Map();
    for (const t of opts.tags) descs.set(t.n, t.d || '');
    for (const n of opts.held) if (!descs.has(n)) descs.set(n, '');
    const tags = [...descs.keys()].sort().map((n) => ({ n, d: descs.get(n) }));
    const pending = new Map();
    const want = opts.want || opts.held;
    for (const n of want) if (!opts.held.has(n)) pending.set(n, 'add');
    for (const n of opts.held) if (!want.has(n)) pending.set(n, 'remove');
    cur = { opts, held: opts.held, tags, descs, pending, created: new Set(opts.created || []), reach: opts.reach || new Map() };
    ui.title.textContent = opts.title;
    ui.subject.textContent = opts.subject || '';
    ui.filter.value = '';
    ui.filter.placeholder = opts.creatable ? 'Filter or create tags · Enter picks the first match' : 'Filter tags · Enter picks the first match';
    buildList();
    update();
    dlg.showModal();
    ui.filter.focus();
  };

  const post = (action, fields) => {
    const f = make('form');
    f.method = 'post';
    f.action = action;
    for (const [k, v] of Object.entries(fields)) { const i = make('input'); i.type = 'hidden'; i.name = k; i.value = v; f.append(i); }
    document.body.append(f);
    f.submit();
    return 'busy';
  };

  document.querySelectorAll('a[data-tag-edit]').forEach((a) => {
    a.addEventListener('click', (e) => {
      if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      e.preventDefault();
      const held = new Set(words(a.dataset.held));
      const reach = new Map(words(a.dataset.reach).map((kv) => { const i = kv.lastIndexOf('='); return [kv.slice(0, i), Number(kv.slice(i + 1)) || 0]; }));
      const addable = a.dataset.addable === '1';
      open({ title: a.dataset.title || 'Edit tags', subject: a.dataset.subject, tags: addable ? registry : [], held, addable,
        creatable: addable && admin, reach, reachKind: a.dataset.reachKind, heldWord: 'held', saveWord: 'Save', lockedNote: true,
        onSave: (want, created) => post(a.href, { csrf: a.dataset.csrf, base: [...held].join(' '), tags: [...want].join(' '), create: created.join(' ') }) });
    });
  });

  document.querySelectorAll('fieldset[data-picker]').forEach((fs) => {
    const boxes = [...fs.querySelectorAll('input[type=checkbox][name=tag]')];
    const list = fs.querySelector('.tagboxes');
    // Administrators may make up tags here too, so they get the picker even with none yet.
    if (!list || (!boxes.length && !admin)) return;
    const held = new Set(boxes.filter((b) => b.checked).map((b) => b.value));
    const tags = boxes.map((b) => ({ n: b.value, d: b.closest('label')?.title || '' }));
    list.hidden = true;
    const sum = make('div', 'tagsum');
    fs.append(sum);
    const render = () => {
      const want = new Set(boxes.filter((b) => b.checked).map((b) => b.value));
      sum.replaceChildren();
      const shown = [...new Set([...held, ...want])].sort();
      if (!shown.length) sum.append(make('span', 'sub', 'none'));
      for (const n of shown) {
        const s = !want.has(n) ? 'remove' : held.has(n) ? 'held' : 'add';
        sum.append(make('code', `chip ${s}`, s === 'add' ? `+ ${n}` : s === 'remove' ? `− ${n}` : n));
      }
      const btn = make('button', 'btn small', 'Choose tags');
      btn.type = 'button';
      btn.addEventListener('click', () => open({ title: fs.dataset.title || 'Tags', subject: fs.dataset.subject, tags, held, want, addable: true,
        inForm: true, creatable: admin, created: boxes.filter((b) => b.dataset.created).map((b) => b.value), heldWord: 'selected', saveWord: 'Done', lockedNote: false,
        onSave: (w, created) => {
          // A new tag becomes a checkbox like the others, plus a `create` field for the server.
          for (const n of created.filter((n) => !boxes.some((b) => b.value === n))) {
            const box = make('input');
            Object.assign(box, { type: 'checkbox', name: 'tag', value: n });
            box.dataset.created = '1';
            const made = make('input');
            Object.assign(made, { type: 'hidden', name: 'create', value: n });
            const label = make('label');
            label.append(box, made, ' ', make('code', null, n));
            list.append(label);
            boxes.push(box);
            tags.push({ n, d: '' });
          }
          boxes.forEach((b) => {
            b.checked = w.has(b.value);
            const made = b.parentElement.querySelector('input[name=create]');
            if (made) made.disabled = !b.checked;
          });
          render();
        } }));
      sum.append(btn);
    };
    render();
  });
})();

// Row menus (`details.menu`): without the script the list opens in place, inside the row. With
// it the list floats next to its button, outside the table's scroll box, one menu at a time; it
// closes on Escape, a click elsewhere, choosing an item, or scrolling. Forms with `data-confirm`
// ask first.
(() => {
  const menus = [...document.querySelectorAll('details.menu')];
  const closeAll = (except) => menus.forEach((d) => { if (d !== except) d.open = false; });
  const place = (d) => {
    const list = d.querySelector('.menu-list');
    const r = d.querySelector('summary').getBoundingClientRect();
    const below = r.bottom + 4 + list.offsetHeight <= innerHeight - 8;
    list.style.top = `${below ? r.bottom + 4 : Math.max(8, r.top - 4 - list.offsetHeight)}px`;
    list.style.left = `${Math.min(innerWidth - list.offsetWidth - 8, Math.max(8, r.right - list.offsetWidth))}px`;
  };
  for (const d of menus) {
    d.classList.add('float');
    d.addEventListener('toggle', () => {
      if (!d.open) return;
      closeAll(d);
      place(d);
      d.querySelector('.menu-item')?.focus();
    });
    d.querySelector('.menu-list').addEventListener('click', (e) => { if (e.target.closest('.menu-item')) d.open = false; });
  }
  document.addEventListener('click', (e) => { if (!e.target.closest('details.menu')) closeAll(); });
  document.addEventListener('keydown', (e) => {
    const d = menus.find((m) => m.open);
    if (e.key === 'Escape' && d) { d.open = false; d.querySelector('summary').focus(); }
  });
  addEventListener('resize', () => closeAll());
  addEventListener('scroll', (e) => { if (!e.target.closest?.('.menu-list')) closeAll(); }, true);
  document.querySelectorAll('form[data-confirm]').forEach((f) => {
    f.addEventListener('submit', (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
})();
