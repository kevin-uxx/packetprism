/* PacketPrism — UI controller */
(() => {
  'use strict';

  // ================================================================ helpers
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
  const coll = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
  const nextFrame = () => new Promise(r => requestAnimationFrame(() => setTimeout(r, 0)));
  const ROW_H = 30;

  const PC = {
    TCP: '#60a5fa', UDP: '#a78bfa', HTTP: '#34d399', TLS: '#2dd4bf', DNS: '#fbbf24', MDNS: '#facc15', ICMP: '#f472b6', ICMPv6: '#fb7185',
    ARP: '#fb923c', DHCP: '#c084fc', NTP: '#94a3b8', SSDP: '#e879f9', IPv4: '#818cf8', IPv6: '#818cf8', Ethernet: '#64748b', Frame: '#64748b'
  };
  const LC = {
    frame: '#64748b', eth: '#94a3b8', vlan: '#94a3b8', sll: '#94a3b8', null: '#94a3b8', arp: PC.ARP, ip: '#818cf8', ipv6: '#818cf8', icmp: PC.ICMP,
    icmpv6: PC.ICMPv6, tcp: PC.TCP, udp: PC.UDP, dns: PC.DNS, mdns: PC.MDNS, http: PC.HTTP, ssdp: PC.SSDP, tls: PC.TLS, dhcp: PC.DHCP, ntp: PC.NTP,
    data: '#64748b', malformed: '#ef4444'
  };
  const colorOf = p => PC[p] || '#818cf8';
  const CHIP_PROTOS = [['arp', 'ARP'], ['ip', 'IPv4'], ['ipv6', 'IPv6'], ['icmp', 'ICMP'], ['icmpv6', 'ICMPv6'], ['tcp', 'TCP'], ['udp', 'UDP'], ['dns', 'DNS'], ['mdns', 'mDNS'], ['http', 'HTTP'], ['tls', 'TLS'], ['dhcp', 'DHCP'], ['ntp', 'NTP'], ['ssdp', 'SSDP']];
  const FLAG_COLORS = { SYN: '#34d399', ACK: '#60a5fa', FIN: '#fbbf24', RST: '#f87171', PSH: '#a78bfa', URG: '#f472b6', ECE: '#2dd4bf', CWR: '#94a3b8' };
  const COLS = [
    { k: 'no', label: 'No.' }, { k: 'time', label: 'Time' }, { k: 'src', label: 'Source' }, { k: 'dst', label: 'Destination' },
    { k: 'proto', label: 'Protocol' }, { k: 'len', label: 'Length' }, { k: 'info', label: 'Info' }
  ];
  const EXAMPLES = [
    ['tcp.flags.syn == 1 && tcp.flags.ack == 0', 'Connection attempts'],
    ['tcp.flags.rst == 1', 'Resets / refused connections'],
    ['dns.qry.name contains github', 'DNS lookups for a name'],
    ['tls.sni', 'TLS Client Hellos with SNI'],
    ['http.request.method == POST', 'HTTP POST requests'],
    ['ip.addr == 8.8.8.8', 'Traffic to/from a host'],
    ['frame.len > 1000', 'Large frames'],
    ['icmp || icmpv6', 'ICMP of either version'],
    ['!(tcp.port == 443) && tcp', 'Non-HTTPS TCP']
  ];

  const fmtBytes = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : n < 1073741824 ? `${(n / 1048576).toFixed(2)} MB` : `${(n / 1073741824).toFixed(2)} GB`;
  const fmtNum = n => n.toLocaleString('en-US');
  const fmtDur = s => s < 0.001 ? `${(s * 1e6).toFixed(0)} µs` : s < 1 ? `${(s * 1000).toFixed(1)} ms` : s < 120 ? `${s.toFixed(2)} s` : s < 7200 ? `${(s / 60).toFixed(1)} min` : `${(s / 3600).toFixed(1)} h`;
  const fmtRate = bps => bps < 1000 ? `${bps.toFixed(0)} bps` : bps < 1e6 ? `${(bps / 1e3).toFixed(1)} kbps` : bps < 1e9 ? `${(bps / 1e6).toFixed(2)} Mbps` : `${(bps / 1e9).toFixed(2)} Gbps`;
  function fmtClock(ts) {
    const d = new Date(ts * 1000);
    const us = Math.round((ts - Math.floor(ts)) * 1e6) % 1e6;
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}.${String(us).padStart(6, '0')}`;
  }

  // ================================================================ state & elements
  const S = { name: '', cap: null, recs: [], view: [], sort: { k: 'no', d: 1 }, protos: new Set(), filt: null, ftext: '', sel: -1, time: 'rel', tab: 'packets', convSort: { k: 'bytes', d: -1 }, convs: null, streamMode: 'ascii', streamKey: null };
  const E = {
    landing: $('#landing'), ws: $('#workspace'), status: $('#statusbar'), fwrap: $('#filterWrap'), finput: $('#filterInput'), fstate: $('#filterState'), suggest: $('#suggest'),
    stats: $('#stats'), chips: $('#protoChips'), thead: $('#thead'), tbody: $('#tbody'), spacer: $('#spacer'), rows: $('#rows'), tableEmpty: $('#tableEmpty'),
    dhead: $('#detailHead'), keyf: $('#keyfields'), tree: $('#tree'), hex: $('#hex'), hexSel: $('#hexSel'), file: $('#fileInput'), exportBtn: $('#btnExport'),
    exportMenu: $('#exportMenu'), ctx: $('#ctxMenu'), toasts: $('#toasts'), loading: $('#loading'), loadingText: $('#loadingText'), modal: $('#streamModal'),
    viewP: $('#view-packets'), viewI: $('#view-insights'), viewC: $('#view-convs'), splitter: $('#splitter'), drop: $('#dropOverlay')
  };

  // ================================================================ toasts & loading
  function toast(msg, kind = '') {
    const t = document.createElement('div');
    t.className = 'toast ' + kind; t.textContent = msg;
    E.toasts.appendChild(t);
    setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, kind === 'err' ? 5200 : 3000);
  }
  const showLoading = m => { E.loadingText.textContent = m; E.loading.hidden = false; };
  const hideLoading = () => { E.loading.hidden = true; };

  // ================================================================ loading captures
  async function loadBuffer(buf, name) {
    showLoading('Parsing capture…');
    await nextFrame();
    try {
      const cap = PcapParser.parse(buf);
      if (!cap.packets.length) throw new Error('The capture file contains no packets.');
      const g = Decoder.createState(cap.packets[0].ts);
      const n = cap.packets.length, recs = new Array(n);
      for (let i = 0; i < n; i++) {
        recs[i] = Decoder.decode(cap.packets[i], i, g);
        if (i % 2500 === 2499) { E.loadingText.textContent = `Decoding packets… ${fmtNum(i + 1)} / ${fmtNum(n)}`; await nextFrame(); }
      }
      Object.assign(S, { name, cap, recs, sel: -1, protos: new Set(), convs: null, sort: { k: 'no', d: 1 } });
      E.landing.hidden = true; E.ws.hidden = false; E.status.hidden = false; E.fwrap.hidden = false; E.exportBtn.disabled = false;
      document.title = `${name} · PacketPrism`;
      buildHead(); buildChips();
      refresh();
      E.tbody.scrollTop = 0;
      if (S.view.length) select(S.view[0]);
      switchTab('packets');
      toast(`Loaded ${fmtNum(n)} packets from ${name}${cap.truncated ? ' (file truncated — partial load)' : ''}`);
    } catch (e) {
      console.error(e);
      toast(e.message || String(e), 'err');
    } finally { hideLoading(); }
  }
  async function loadFile(file) {
    if (!file) return;
    showLoading(`Reading ${file.name}…`);
    try { await loadBuffer(await file.arrayBuffer(), file.name); }
    catch (e) { hideLoading(); toast(e.message, 'err'); }
  }
  function loadSample() { const bytes = SampleCapture.build(); loadBuffer(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength), 'sample-home-network.pcap'); }
  function download(data, name, type) {
    const url = URL.createObjectURL(new Blob([data], { type }));
    const a = Object.assign(document.createElement('a'), { href: url, download: name });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // ================================================================ view computation
  function sortKey(k) {
    switch (k) {
      case 'no': return r => r.no;
      case 'time': return r => r.ts;
      case 'len': return r => r.len;
      case 'src': return r => r.src;
      case 'dst': return r => r.dst;
      case 'proto': return r => r.proto;
      default: return r => r.info;
    }
  }
  function computeView() {
    const ps = [...S.protos], fl = S.filt, out = [];
    for (let i = 0; i < S.recs.length; i++) {
      const r = S.recs[i];
      if (ps.length && !ps.some(p => r.f[p])) continue;
      if (fl) { let ok = false; try { ok = fl(r.f); } catch { ok = false; } if (!ok) continue; }
      out.push(i);
    }
    const { k, d } = S.sort;
    if (!(k === 'no' && d === 1)) {
      const key = sortKey(k);
      out.sort((a, b) => {
        const x = key(S.recs[a]), y = key(S.recs[b]);
        const c = typeof x === 'number' ? x - y : coll.compare(String(x), String(y));
        return c ? c * d : a - b;
      });
    }
    S.view = out;
  }
  function refresh() {
    computeView();
    E.spacer.style.height = `${S.view.length * ROW_H}px`;
    E.tableEmpty.hidden = S.view.length > 0;
    renderRows(); renderStats(); renderStatus(); updateChipState();
    if (S.tab === 'insights') renderInsights();
    if (S.tab === 'convs') renderConvs();
  }

  // ================================================================ table
  function buildHead() {
    E.thead.className = 'thead cols';
    E.thead.innerHTML = COLS.map(c => `<div class="th${S.sort.k === c.k ? ' on' + (S.sort.d < 0 ? ' desc' : '') : ''}" data-k="${c.k}">${c.label}<span class="arr">▲</span></div>`).join('');
  }
  E.thead.addEventListener('click', e => {
    const th = e.target.closest('.th'); if (!th) return;
    const k = th.dataset.k;
    S.sort = S.sort.k === k ? { k, d: -S.sort.d } : { k, d: 1 };
    buildHead(); refresh(); ensureVisible();
  });
  function timeText(r) {
    if (S.time === 'abs') return fmtClock(r.ts);
    if (S.time === 'delta') return r.delta.toFixed(6);
    return r.rel.toFixed(6);
  }
  function infoHtml(r) {
    let s = esc(r.info);
    if (r.flags != null) s = s.replace(/\[([A-Z, ]+)\]/, (m, f) => `<span class="flg${/RST/.test(f) ? ' r' : ''}">[${f}]</span>`);
    return s;
  }
  let rowRaf = 0;
  function renderRows() {
    const st = E.tbody.scrollTop, h = E.tbody.clientHeight || 600;
    const start = Math.max(0, Math.floor(st / ROW_H) - 8), end = Math.min(S.view.length, Math.ceil((st + h) / ROW_H) + 8);
    E.rows.style.transform = `translateY(${start * ROW_H}px)`;
    let html = '';
    for (let i = start; i < end; i++) {
      const idx = S.view[i], r = S.recs[idx];
      html += `<div class="row cols${idx === S.sel ? ' sel' : ''}${r.warn ? ' warn' : ''}" data-i="${idx}" style="--pc:${colorOf(r.proto)}">` +
        `<div class="c-no">${r.no}</div><div class="c-time">${timeText(r)}</div><div title="${esc(r.src)}">${esc(r.src)}</div><div title="${esc(r.dst)}">${esc(r.dst)}</div>` +
        `<div><span class="pbadge" style="--pc:${colorOf(r.proto)}">${esc(r.proto)}</span></div><div class="c-len">${r.len}</div><div title="${esc(r.info)}">${infoHtml(r)}</div></div>`;
    }
    E.rows.innerHTML = html;
  }
  E.tbody.addEventListener('scroll', () => { cancelAnimationFrame(rowRaf); rowRaf = requestAnimationFrame(renderRows); });
  window.addEventListener('resize', () => { if (!E.ws.hidden) renderRows(); });
  E.rows.addEventListener('click', e => { const row = e.target.closest('.row'); if (row) { select(+row.dataset.i); E.tbody.focus({ preventScroll: true }); } });
  E.rows.addEventListener('dblclick', e => { const row = e.target.closest('.row'); if (row) { const r = S.recs[+row.dataset.i]; if (r.skind) openStream(r); } });
  E.rows.addEventListener('contextmenu', e => {
    const row = e.target.closest('.row'); if (!row) return;
    e.preventDefault(); select(+row.dataset.i); openCtx(e.clientX, e.clientY, S.recs[+row.dataset.i]);
  });

  function ensureVisible() {
    const pos = S.view.indexOf(S.sel);
    if (pos < 0) return;
    const top = pos * ROW_H, st = E.tbody.scrollTop, h = E.tbody.clientHeight;
    if (top < st) E.tbody.scrollTop = top;
    else if (top + ROW_H > st + h) E.tbody.scrollTop = top + ROW_H - h;
  }
  function select(i, scroll) {
    if (i == null || i < 0 || !S.recs[i]) return;
    S.sel = i;
    if (scroll) ensureVisible();
    renderRows();
    renderDetail(S.recs[i]);
  }
  function moveSel(delta) {
    if (!S.view.length) return;
    let pos = S.view.indexOf(S.sel);
    pos = pos < 0 ? 0 : Math.max(0, Math.min(S.view.length - 1, pos + delta));
    select(S.view[pos], true);
  }

  // ================================================================ chips & stats
  function buildChips() {
    const counts = {};
    for (const r of S.recs) for (const [k] of CHIP_PROTOS) if (r.f[k]) counts[k] = (counts[k] || 0) + 1;
    E.chips.innerHTML = `<button class="chip clear on" data-p="*"><i></i>All<span>${fmtNum(S.recs.length)}</span></button>` +
      CHIP_PROTOS.filter(([k]) => counts[k]).map(([k, n]) => `<button class="chip" data-p="${k}" style="--c:${LC[k]}" title="Show packets containing ${n} (multi-select)"><i></i>${n}<span>${fmtNum(counts[k])}</span></button>`).join('');
  }
  function updateChipState() {
    $$('.chip', E.chips).forEach(c => c.classList.toggle('on', c.dataset.p === '*' ? S.protos.size === 0 : S.protos.has(c.dataset.p)));
  }
  E.chips.addEventListener('click', e => {
    const c = e.target.closest('.chip'); if (!c) return;
    const p = c.dataset.p;
    if (p === '*') S.protos.clear();
    else if (e.shiftKey || e.ctrlKey || e.metaKey || S.protos.size) { S.protos.has(p) ? S.protos.delete(p) : S.protos.add(p); }
    else S.protos.add(p);
    refresh(); keepSelection();
  });
  function keepSelection() {
    if (S.view.includes(S.sel)) ensureVisible();
    else if (S.view.length) { E.tbody.scrollTop = 0; select(S.view[0]); }
  }

  function sparkline(vals, color = '#22d3ee') {
    const max = Math.max(1, ...vals), w = 100, h = 30, n = vals.length;
    const pts = vals.map((v, i) => `${(i / (n - 1 || 1)) * w},${h - (v / max) * (h - 3) - 1}`);
    return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><defs><linearGradient id="sg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${color}" stop-opacity=".45"/><stop offset="1" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>` +
      `<path d="M0,${h} L${pts.join(' L')} L${w},${h}Z" fill="url(#sg)"/><polyline points="${pts.join(' ')}" fill="none" stroke="${color}" stroke-width="1.4" vector-effect="non-scaling-stroke"/></svg>`;
  }
  function renderStats() {
    const v = S.view.map(i => S.recs[i]);
    let bytes = 0, t0 = Infinity, t1 = -Infinity;
    const hosts = new Set(), streams = new Set();
    for (const r of v) {
      bytes += r.len; if (r.ts < t0) t0 = r.ts; if (r.ts > t1) t1 = r.ts;
      const a = r.f['ip.src'] || r.f['ipv6.src'], b = r.f['ip.dst'] || r.f['ipv6.dst'];
      if (a) hosts.add(a); if (b) hosts.add(b);
      if (r.skind) streams.add(r.skind + r.stream);
    }
    const dur = v.length > 1 ? t1 - t0 : 0;
    const B = 40, buckets = new Array(B).fill(0);
    for (const r of v) buckets[Math.min(B - 1, Math.floor(((r.ts - t0) / (dur || 1)) * B))]++;
    const pct = S.recs.length ? (v.length / S.recs.length * 100) : 0;
    E.stats.innerHTML = `
      <div class="stat hero-stat"><div class="k">Packets</div><div class="v">${fmtNum(v.length)}${v.length !== S.recs.length ? `<small>of ${fmtNum(S.recs.length)}</small>` : ''}</div>${sparkline(buckets)}</div>
      <div class="stat"><div class="k">Data</div><div class="v">${fmtBytes(bytes)}</div></div>
      <div class="stat"><div class="k">Duration</div><div class="v">${v.length ? fmtDur(dur) : '—'}</div></div>
      <div class="stat"><div class="k">Avg size</div><div class="v">${v.length ? Math.round(bytes / v.length) : 0}<small>B</small></div></div>
      <div class="stat"><div class="k">Throughput</div><div class="v">${dur ? fmtRate(bytes * 8 / dur) : '—'}</div></div>
      <div class="stat"><div class="k">Hosts</div><div class="v">${hosts.size}</div></div>
      <div class="stat"><div class="k">Streams</div><div class="v">${streams.size}<small>${pct < 100 ? pct.toFixed(0) + '%' : ''}</small></div></div>`;
  }
  function renderStatus() {
    const c = S.cap;
    E.status.innerHTML = `<span>📄 <b>${esc(S.name)}</b></span><span class="hide-sm">${esc(c.format)} · ${esc(c.linkName)}</span>` +
      `<span>Displayed: <b>${fmtNum(S.view.length)}</b> / ${fmtNum(S.recs.length)}</span>` +
      (S.ftext ? `<span class="ok hide-sm">filter: ${esc(S.ftext)}</span>` : '') +
      `<span class="sp"></span><span class="hide-sm"><kbd>↑</kbd><kbd>↓</kbd> navigate · <kbd>/</kbd> filter · <kbd>F</kbd> follow · <kbd>Esc</kbd> clear</span>`;
  }

  // ================================================================ detail pane
  const ARROW = '<svg viewBox="0 0 26 12"><path d="M1 6h22m0 0-5-4.5M23 6l-5 4.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>';
  function endpoint(addr, port) { return `<span class="ep">${esc(addr || '—')}${port != null ? `<b>:${port}</b>` : ''}</span>`; }

  function renderDetail(r) {
    const pc = colorOf(r.proto);
    let flags = '';
    if (r.flags != null) {
      flags = '<div class="flagbox" title="TCP flags">' + ['SYN', 'ACK', 'PSH', 'FIN', 'RST', 'URG', 'ECE', 'CWR'].map(n => {
        const bit = Decoder.TCP_FLAGS.find(x => x[1] === n)[0];
        return `<span class="fl${r.flags & bit ? ' on' : ''}" style="--fc:${FLAG_COLORS[n]}">${n}</span>`;
      }).join('') + '</div>';
    } else if (r.f['ip.flags.df'] != null) {
      flags = `<div class="flagbox" title="IPv4 flags"><span class="fl${r.f['ip.flags.df'] ? ' on' : ''}" style="--fc:#818cf8">DF</span><span class="fl${r.f['ip.flags.mf'] ? ' on' : ''}" style="--fc:#818cf8">MF</span></div>`;
    }
    E.dhead.innerHTML = `
      <div class="dh-main"><span class="pbadge" style="--pc:${pc}">${esc(r.proto)}</span>
        <div style="min-width:0"><div class="dh-title">Packet #${r.no}<span>${r.len} bytes · +${r.rel.toFixed(6)}s · ${fmtClock(r.ts)}</span></div>
        <div class="dh-route">${endpoint(r.src, r.sport)}${ARROW}${endpoint(r.dst, r.dport)}</div></div></div>
      ${flags}
      <div class="dh-actions">
        ${r.skind ? `<button class="btn ghost sm" data-act="follow" title="Follow stream (F)">⇄ Follow ${r.skind.toUpperCase()} stream</button>` : ''}
        <button class="btn ghost sm" data-act="conv" title="Filter on this conversation">ƒ Conversation</button>
        <button class="btn ghost sm" data-act="copy" title="Copy packet bytes as hex">⧉ Hex</button>
      </div>`;
    renderKeyFields(r);
    renderTree(r);
    renderHex(r.d);
    E.hexSel.textContent = `${r.cap} bytes`;
  }
  E.dhead.addEventListener('click', e => {
    const b = e.target.closest('[data-act]'); if (!b) return;
    const r = S.recs[S.sel]; if (!r) return;
    if (b.dataset.act === 'follow') openStream(r);
    if (b.dataset.act === 'conv') setFilter(convFilter(r));
    if (b.dataset.act === 'copy') copyText(Array.from(r.d, x => HEX[x]).join(''), 'Packet bytes copied as hex');
  });

  function renderKeyFields(r) {
    const f = r.f, items = [];
    const add = (k, v, cls = '', hl = null) => { if (v !== undefined && v !== null && v !== '') items.push({ k, v, cls, hl }); };
    const findField = name => { for (const L of r.layers) for (const fl of L.fields) if (fl.n === name) return fl; return null; };
    add('Source MAC', f['eth.src'], '', findField('Source'));
    add('Dest MAC', f['eth.dst'], '', findField('Destination'));
    add('Source IP', f['ip.src'] || f['ipv6.src'], '', findField('Source Address'));
    add('Dest IP', f['ip.dst'] || f['ipv6.dst'], '', findField('Destination Address'));
    if (r.sport != null) add('Ports', `${r.sport} → ${r.dport}`, '', findField('Source Port'));
    add('Length', r.len === r.cap ? `${r.len} B` : `${r.len} B (cap ${r.cap})`);
    add(f['ip.ttl'] != null ? 'TTL' : 'Hop limit', f['ip.ttl'] ?? f['ipv6.hlim'], '', findField('Time to Live') || findField('Hop Limit'));
    if (f['ip.id'] != null) add('IP ID', '0x' + f['ip.id'].toString(16).padStart(4, '0'), '', findField('Identification'));
    if (r.flags != null) {
      add('TCP Flags', Decoder.flagStr(r.flags) || 'none', '', findField('Flags'));
      add('Seq / Ack', `${f['tcp.seq']} / ${f['tcp.ack']}`, '', findField('Sequence Number'));
      add('Window', f['tcp.window_size'], '', findField('Window'));
      add('Payload', `${f['tcp.len']} B`);
    }
    if (f['icmp.type'] != null) add('ICMP', `type ${f['icmp.type']} / code ${f['icmp.code']}`);
    if (f['ip.checksum.bad'] != null) add('IP checksum', f['ip.checksum.bad'] ? 'bad' : 'valid', f['ip.checksum.bad'] ? 'bad' : 'good', findField('Header Checksum'));
    if (f['tls.sni']) add('SNI', f['tls.sni'], '');
    if (f['http.host']) add('Host', f['http.host']);
    if (f['dns.qry.name']) add('Query', [].concat(f['dns.qry.name'])[0]);
    E.keyf.innerHTML = items.map((it, i) => `<div class="kf ${it.cls}" data-i="${i}" title="${esc(it.k)}: ${esc(it.v)}"><div class="k">${esc(it.k)}</div><div class="v">${esc(it.v)}</div></div>`).join('');
    E.keyf._items = items;
  }
  E.keyf.addEventListener('click', e => {
    const kf = e.target.closest('.kf'); if (!kf) return;
    const it = E.keyf._items[+kf.dataset.i];
    if (it && it.hl) { const el = fieldEls.find(x => x.f === it.hl); if (el) focusField(el.el); }
  });
  E.keyf.addEventListener('mouseover', e => {
    const kf = e.target.closest('.kf'); if (!kf) return;
    const it = E.keyf._items[+kf.dataset.i];
    if (it && it.hl) setHL(it.hl.o, it.hl.l, 'hh');
  });
  E.keyf.addEventListener('mouseleave', () => setHL(0, 0, 'hh'));

  // ---- tree
  let fieldEls = [];
  const openState = new Set(['ip', 'ipv6', 'tcp', 'udp', 'arp', 'icmp', 'icmpv6', 'dns', 'mdns', 'http', 'ssdp', 'tls', 'dhcp', 'ntp', 'data', 'malformed', 'vlan']);
  function valueClass(v) { return /\[correct\]|valid/.test(v) ? ' ok' : /\[incorrect|Malformed|truncated/i.test(v) ? ' bad' : ''; }
  function fieldHTML(f, depth, path) {
    const has = f.c && f.c.length;
    return `<div class="fld${has ? ' has' : ''}" data-p="${path}"><div class="fl-line" style="--d:${depth}"><span class="tw">${has ? '▶' : ''}</span>` +
      `${f.bits ? `<span class="bits">${f.bits} =</span>` : ''}<span class="fn">${esc(f.n)}</span>${f.v !== '' ? `<span class="fsep">:</span><span class="fv${valueClass(f.v)}">${esc(f.v)}</span>` : ''}</div>` +
      (has ? `<div class="kids">${f.c.map((c, i) => fieldHTML(c, depth + 1, path + '.' + i)).join('')}</div>` : '') + '</div>';
  }
  function renderTree(r) {
    E.tree.innerHTML = r.layers.map((L, li) =>
      `<div class="layer${openState.has(L.key) ? ' open' : ''}" data-key="${L.key}" data-li="${li}" style="--lc:${LC[L.key] || '#818cf8'}">` +
      `<div class="layer-h"><span class="tw">▶</span><span class="ln">${esc(L.name)}</span><span class="ls">${esc(L.sum)}</span><span class="lb">${L.l ? L.l + ' B' : ''}</span></div>` +
      `<div class="layer-b">${L.fields.map((f, fi) => fieldHTML(f, 0, li + '.' + fi)).join('')}</div></div>`).join('');
    // map elements -> field objects for hex linking
    fieldEls = [];
    $$('.layer', E.tree).forEach(el => { const L = r.layers[+el.dataset.li]; fieldEls.push({ el, f: { o: L.o, l: L.l }, layer: true }); });
    $$('.fld', E.tree).forEach(el => {
      const p = el.dataset.p.split('.').map(Number);
      let f = r.layers[p[0]].fields[p[1]];
      for (let i = 2; i < p.length; i++) f = f.c[p[i]];
      fieldEls.push({ el, f });
    });
  }
  function fieldOf(el) { const x = fieldEls.find(y => y.el === el); return x && x.f; }
  E.tree.addEventListener('click', e => {
    const lh = e.target.closest('.layer-h');
    if (lh) {
      const layer = lh.parentElement; layer.classList.toggle('open');
      const k = layer.dataset.key; layer.classList.contains('open') ? openState.add(k) : openState.delete(k);
      const f = fieldOf(layer); if (f) selectRange(f, layer);
      return;
    }
    const line = e.target.closest('.fl-line'); if (!line) return;
    const fld = line.parentElement;
    if (fld.classList.contains('has') && (e.target.classList.contains('tw') || fld.classList.contains('on') || e.detail === 2)) fld.classList.toggle('open');
    else if (fld.classList.contains('has') && !fld.classList.contains('open')) fld.classList.add('open');
    focusField(fld, false);
  });
  E.tree.addEventListener('mouseover', e => {
    const t = e.target.closest('.fl-line, .layer-h'); if (!t) return;
    const f = fieldOf(t.parentElement); if (f) setHL(f.o, f.l, 'hh');
  });
  E.tree.addEventListener('mouseleave', () => setHL(0, 0, 'hh'));
  function selectRange(f, el) {
    $$('.fld.on', E.tree).forEach(x => x.classList.remove('on'));
    if (el && el.classList.contains('fld')) el.classList.add('on');
    setHL(f.o, f.l, 'hs');
    E.hexSel.textContent = f.l ? `offset 0x${f.o.toString(16).padStart(4, '0')} · ${f.l} byte${f.l === 1 ? '' : 's'}` : 'no bytes (generated field)';
    if (f.l && hexEls[f.o]) hexEls[f.o].scrollIntoView({ block: 'nearest' });
  }
  function focusField(el, scroll = true) {
    let p = el.parentElement;
    while (p && p !== E.tree) { if (p.classList.contains('fld') || p.classList.contains('layer')) p.classList.add('open'); p = p.parentElement; }
    const f = fieldOf(el); if (f) selectRange(f, el);
    if (scroll) el.scrollIntoView({ block: 'nearest' });
  }
  $('#expandAll').addEventListener('click', () => $$('.layer, .fld.has', E.tree).forEach(x => x.classList.add('open')));
  $('#collapseAll').addEventListener('click', () => { $$('.fld.has', E.tree).forEach(x => x.classList.remove('open')); $$('.layer', E.tree).forEach(x => x.classList.remove('open')); });

  // ---- hex
  let hexEls = [], ascEls = [];
  const hl = { hh: [0, 0], hs: [0, 0] };
  function renderHex(d) {
    let h = '';
    for (let r = 0; r < d.length; r += 16) {
      let hb = '', ha = '';
      for (let i = r; i < r + 16 && i < d.length; i++) {
        const b = d[i];
        hb += `<span data-i="${i}"${b === 0 ? ' class="z"' : ''}>${HEX[b]}</span>`;
        ha += `<span data-i="${i}">${b >= 32 && b < 127 ? esc(String.fromCharCode(b)) : '·'}</span>`;
      }
      const pad = 16 - Math.min(16, d.length - r);
      h += `<div class="hr"><span class="ho">${r.toString(16).padStart(4, '0')}</span><span class="hb">${hb}${'<span class="pad"> </span>'.repeat(pad)}</span><span class="ha">${ha}</span></div>`;
    }
    E.hex.innerHTML = h;
    hexEls = []; ascEls = [];
    $$('.hb span[data-i]', E.hex).forEach(s => { hexEls[+s.dataset.i] = s; });
    $$('.ha span[data-i]', E.hex).forEach(s => { ascEls[+s.dataset.i] = s; });
    hl.hh = [0, 0]; hl.hs = [0, 0];
  }
  function setHL(o, l, cls) {
    const [po, pl] = hl[cls];
    for (let i = po; i < po + pl; i++) { hexEls[i] && hexEls[i].classList.remove(cls); ascEls[i] && ascEls[i].classList.remove(cls); }
    hl[cls] = [o, l];
    for (let i = o; i < o + l; i++) { hexEls[i] && hexEls[i].classList.add(cls); ascEls[i] && ascEls[i].classList.add(cls); }
  }
  E.hex.addEventListener('click', e => {
    const s = e.target.closest('span[data-i]'); if (!s) return;
    const i = +s.dataset.i;
    let best = null;
    for (const x of fieldEls) if (x.f.l > 0 && i >= x.f.o && i < x.f.o + x.f.l && (!best || x.f.l < best.f.l || (x.f.l === best.f.l && !x.layer))) best = x;
    if (best) focusField(best.el);
  });
  E.hex.addEventListener('mouseover', e => {
    const s = e.target.closest('span[data-i]'); if (!s) return;
    const i = +s.dataset.i;
    let best = null;
    for (const x of fieldEls) if (x.f.l > 0 && i >= x.f.o && i < x.f.o + x.f.l && (!best || x.f.l < best.f.l)) best = x;
    if (best) setHL(best.f.o, best.f.l, 'hh');
  });
  E.hex.addEventListener('mouseleave', () => setHL(0, 0, 'hh'));

  // ================================================================ filter input
  const knownField = f => Decoder.FIELDS[f] !== undefined || Decoder.PROTOCOLS.includes(f);
  let fTimer = 0;
  function applyFilterText(txt, commit) {
    const t = txt.trim();
    E.fwrap.classList.remove('valid', 'invalid');
    if (!t) { S.filt = null; S.ftext = ''; E.fstate.textContent = ''; if (commit !== false) { refresh(); keepSelection(); } return true; }
    try {
      const fn = DisplayFilter.compile(t, knownField);
      S.filt = fn; S.ftext = t;
      E.fwrap.classList.add('valid');
      refresh(); keepSelection();
      E.fstate.textContent = `${fmtNum(S.view.length)} match${S.view.length === 1 ? '' : 'es'}`;
      return true;
    } catch (err) {
      E.fwrap.classList.add('invalid');
      E.fstate.textContent = 'invalid';
      E.fwrap.dataset.err = err.message;
      return false;
    }
  }
  function setFilter(txt) { E.finput.value = txt; applyFilterText(txt); closeSuggest(); switchTab('packets'); toast(`Filter applied: ${txt}`); }
  function convFilter(r) {
    if (r.skind) return `${r.skind}.stream == ${r.stream}`;
    const a = r.f['ip.src'] || r.f['ipv6.src'], b = r.f['ip.dst'] || r.f['ipv6.dst'];
    const k = r.f['ip.src'] ? 'ip' : 'ipv6';
    if (a) return `${k}.addr == ${a} && ${k}.addr == ${b}`;
    return `eth.addr == ${r.f['eth.src']} && eth.addr == ${r.f['eth.dst']}`;
  }
  E.finput.addEventListener('input', () => {
    clearTimeout(fTimer);
    fTimer = setTimeout(() => applyFilterText(E.finput.value), 180);
    openSuggest();
  });
  E.finput.addEventListener('focus', openSuggest);
  E.finput.addEventListener('blur', () => setTimeout(closeSuggest, 150));
  let sgIndex = -1;
  E.finput.addEventListener('keydown', e => {
    const items = $$('button', E.suggest);
    if (e.key === 'ArrowDown' && items.length) { e.preventDefault(); sgIndex = (sgIndex + 1) % items.length; items.forEach((b, i) => b.classList.toggle('hl', i === sgIndex)); }
    else if (e.key === 'ArrowUp' && items.length) { e.preventDefault(); sgIndex = (sgIndex - 1 + items.length) % items.length; items.forEach((b, i) => b.classList.toggle('hl', i === sgIndex)); }
    else if ((e.key === 'Tab' || (e.key === 'Enter' && sgIndex >= 0)) && items.length && E.suggest.classList.contains('open')) {
      e.preventDefault(); (items[Math.max(0, sgIndex)]).dispatchEvent(new MouseEvent('mousedown'));
    }
    else if (e.key === 'Enter') { clearTimeout(fTimer); if (applyFilterText(E.finput.value)) { closeSuggest(); E.tbody.focus(); } else toast(E.fwrap.dataset.err, 'err'); }
    else if (e.key === 'Escape') { if (E.suggest.classList.contains('open')) closeSuggest(); else { E.finput.value = ''; applyFilterText(''); E.finput.blur(); } }
  });
  function openSuggest() {
    sgIndex = -1;
    const v = E.finput.value, caret = E.finput.selectionStart ?? v.length;
    const before = v.slice(0, caret);
    const m = before.match(/([a-z][a-z0-9_.]*)$/i);
    let html = '';
    if (E.fwrap.classList.contains('invalid') && v.trim()) html += `<div class="sg-err">⚠ ${esc(E.fwrap.dataset.err || 'Invalid filter')}</div>`;
    if (m && !/(==|!=|>=|<=|>|<|contains|matches|~)\s*$/i.test(before.slice(0, before.length - m[1].length))) {
      const tok = m[1].toLowerCase();
      const fields = Object.keys(Decoder.FIELDS).concat(Decoder.PROTOCOLS).filter(k => k.startsWith(tok) && k !== tok).slice(0, 9);
      if (fields.length) html += '<div class="sg-h">Fields</div>' + fields.map(k => `<button data-ins="${k}" data-tok="${m[1].length}"><b>${k}</b><span>${esc(Decoder.FIELDS[k] || 'Protocol')}</span></button>`).join('');
    }
    if (!v.trim()) html += '<div class="sg-h">Try a filter</div>' + EXAMPLES.map(([f, d]) => `<button data-set="${esc(f)}"><b>${esc(f)}</b><span>${d}</span></button>`).join('');
    E.suggest.innerHTML = html;
    E.suggest.classList.toggle('open', !!html);
  }
  function closeSuggest() { E.suggest.classList.remove('open'); }
  E.suggest.addEventListener('mousedown', e => {
    const b = e.target.closest('button'); if (!b) return;
    e.preventDefault();
    if (b.dataset.set) { E.finput.value = b.dataset.set; applyFilterText(b.dataset.set); closeSuggest(); return; }
    const v = E.finput.value, caret = E.finput.selectionStart ?? v.length, n = +b.dataset.tok;
    const nv = v.slice(0, caret - n) + b.dataset.ins + ' ' + v.slice(caret);
    E.finput.value = nv;
    const pos = caret - n + b.dataset.ins.length + 1;
    E.finput.setSelectionRange(pos, pos);
    E.finput.focus();
    applyFilterText(nv);
    openSuggest();
  });
  $('#filterClear').addEventListener('click', () => { E.finput.value = ''; applyFilterText(''); E.finput.focus(); });
  $('#resetFilters').addEventListener('click', () => { E.finput.value = ''; S.protos.clear(); applyFilterText(''); });

  // ================================================================ tabs / time mode
  function switchTab(t) {
    S.tab = t;
    $$('#viewTabs button').forEach(b => b.classList.toggle('on', b.dataset.view === t));
    E.viewP.hidden = t !== 'packets'; E.viewI.hidden = t !== 'insights'; E.viewC.hidden = t !== 'convs';
    if (t === 'insights') renderInsights();
    if (t === 'convs') renderConvs();
    if (t === 'packets') requestAnimationFrame(renderRows);
  }
  $('#viewTabs').addEventListener('click', e => { const b = e.target.closest('button'); if (b) switchTab(b.dataset.view); });
  $('#timeMode').addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b) return;
    S.time = b.dataset.tm;
    $$('#timeMode button').forEach(x => x.classList.toggle('on', x === b));
    renderRows();
  });

  // ================================================================ insights
  function countBy(arr, fn) { const m = new Map(); for (const x of arr) { const k = fn(x); if (k == null) continue; m.set(k, (m.get(k) || 0) + 1); } return [...m].sort((a, b) => b[1] - a[1]); }
  function donut(data, total) {
    const R = 80, r = 52, cx = 90, cy = 90;
    let a = -Math.PI / 2, out = '';
    for (const [k, v] of data) {
      const frac = v / total, a2 = a + frac * Math.PI * 2;
      const col = colorOf(k);
      if (frac >= 0.9999) out += `<path d="M${cx},${cy - R}A${R},${R} 0 1 1 ${cx - 0.01},${cy - R}L${cx - 0.01},${cy - r}A${r},${r} 0 1 0 ${cx},${cy - r}Z" fill="${col}" data-f="${k.toLowerCase()}"><title>${k}: ${v}</title></path>`;
      else {
        const lg = frac > 0.5 ? 1 : 0, gap = Math.min(0.012, frac * 0.2);
        const p = (ang, rad) => `${(cx + rad * Math.cos(ang)).toFixed(2)},${(cy + rad * Math.sin(ang)).toFixed(2)}`;
        out += `<path d="M${p(a + gap, R)}A${R},${R} 0 ${lg} 1 ${p(a2 - gap, R)}L${p(a2 - gap, r)}A${r},${r} 0 ${lg} 0 ${p(a + gap, r)}Z" fill="${col}" data-f="${k.toLowerCase()}"><title>${k}: ${v} (${(frac * 100).toFixed(1)}%)</title></path>`;
      }
      a = a2;
    }
    return `<svg class="donut" viewBox="0 0 180 180">${out}<text x="90" y="88" text-anchor="middle" font-size="26" font-weight="800">${fmtNum(total)}</text><text x="90" y="108" text-anchor="middle" font-size="10.5" fill="#6b7690" style="fill:#6b7690;letter-spacing:.1em">PACKETS</text></svg>`;
  }
  function barRows(rows, max, fmt, color) {
    return rows.map(([label, v, filter, sub]) => `<div class="bar-row" data-filter="${esc(filter)}" title="Filter: ${esc(filter)}"><span class="bl">${esc(label)}${sub ? ` <small>${esc(sub)}</small>` : ''}</span><span class="bt"><i style="width:${Math.max(2, v / max * 100)}%;${color ? `background:${color}` : 'background:var(--grad)'}"></i></span><span class="bv">${fmt(v)}</span></div>`).join('');
  }
  function protoFilterName(p) { return ({ IPv4: 'ip', MDNS: 'mdns', ICMPv6: 'icmpv6' })[p] || p.toLowerCase(); }

  function renderInsights() {
    const v = S.view.map(i => S.recs[i]);
    if (!v.length) { E.viewI.innerHTML = '<div class="card ins"><p style="color:var(--muted)">No packets in the current view.</p></div>'; return; }
    const total = v.length;
    const protos = countBy(v, r => r.proto);
    // timeline
    let t0 = Infinity, t1 = -Infinity;
    for (const r of v) { if (r.rel < t0) t0 = r.rel; if (r.rel > t1) t1 = r.rel; }
    const span = (t1 - t0) || 1, NB = 72;
    const top = protos.slice(0, 6).map(x => x[0]);
    const buckets = Array.from({ length: NB }, () => ({ t: 0, by: {} }));
    for (const r of v) {
      const b = buckets[Math.min(NB - 1, Math.floor((r.rel - t0) / span * NB))];
      const k = top.includes(r.proto) ? r.proto : 'Other';
      b.t++; b.by[k] = (b.by[k] || 0) + 1;
    }
    const bmax = Math.max(...buckets.map(b => b.t)), W = 720, Hh = 170, bw = W / NB;
    let tl = '';
    buckets.forEach((b, i) => {
      let y = Hh;
      for (const k of [...top, 'Other']) {
        const c = b.by[k]; if (!c) continue;
        const h = c / bmax * (Hh - 8);
        y -= h;
        tl += `<rect x="${(i * bw + 1).toFixed(1)}" y="${y.toFixed(1)}" width="${(bw - 2).toFixed(1)}" height="${h.toFixed(1)}" rx="1.5" fill="${k === 'Other' ? '#475569' : colorOf(k)}"><title>${(t0 + i * span / NB).toFixed(2)}s – ${(t0 + (i + 1) * span / NB).toFixed(2)}s · ${k}: ${c}</title></rect>`;
      }
    });
    // talkers
    const talk = new Map();
    for (const r of v) for (const a of [r.f['ip.src'] || r.f['ipv6.src'], r.f['ip.dst'] || r.f['ipv6.dst']]) if (a && !/^(255\.|0\.0\.0\.0|ff02|224\.|239\.)/.test(a)) talk.set(a, (talk.get(a) || 0) + r.len);
    const talkers = [...talk].sort((a, b) => b[1] - a[1]).slice(0, 8);
    // services
    const svc = new Map();
    for (const r of v) {
      if (r.sport == null) continue;
      const port = Math.min(r.sport, r.dport) <= 1024 || Decoder.SERVICES[Math.min(r.sport, r.dport)] ? Math.min(r.sport, r.dport) : (Decoder.SERVICES[r.dport] ? r.dport : r.sport);
      const key = `${port}/${r.skind}`;
      const e = svc.get(key) || { port, kind: r.skind, n: 0 }; e.n++; svc.set(key, e);
    }
    const services = [...svc.values()].sort((a, b) => b.n - a.n).slice(0, 8);
    // flags
    const fl = { SYN: 0, 'SYN-ACK': 0, FIN: 0, RST: 0, PSH: 0, 'Pure ACK': 0 };
    let tcpN = 0;
    for (const r of v) {
      if (r.flags == null) continue; tcpN++;
      const f = r.flags;
      if ((f & 2) && !(f & 16)) fl.SYN++; if ((f & 2) && (f & 16)) fl['SYN-ACK']++;
      if (f & 1) fl.FIN++; if (f & 4) fl.RST++; if (f & 8) fl.PSH++;
      if (f === 16 && !r.f['tcp.len']) fl['Pure ACK']++;
    }
    const flagFilters = { SYN: 'tcp.flags.syn == 1 && tcp.flags.ack == 0', 'SYN-ACK': 'tcp.flags.syn == 1 && tcp.flags.ack == 1', FIN: 'tcp.flags.fin == 1', RST: 'tcp.flags.rst == 1', PSH: 'tcp.flags.push == 1', 'Pure ACK': 'tcp.flags == 0x10 && tcp.len == 0' };
    const flagCol = { SYN: '#34d399', 'SYN-ACK': '#2dd4bf', FIN: '#fbbf24', RST: '#f87171', PSH: '#a78bfa', 'Pure ACK': '#60a5fa' };
    // sizes
    const bins = [[0, 64], [65, 128], [129, 256], [257, 512], [513, 1024], [1025, 1518], [1519, Infinity]];
    const hist = bins.map(([a, b]) => v.filter(r => r.len >= a && r.len <= b).length);
    const hmax = Math.max(1, ...hist);
    // dns
    const dnsQ = new Map();
    for (const r of v) {
      if (!r.f.dns && !r.f.mdns) continue;
      const names = [].concat(r.f['dns.qry.name'] || []);
      for (const n of names) {
        const e = dnsQ.get(n) || { n, q: 0, r: 0, type: [].concat(r.f['dns.qry.type'] || [])[0], ans: new Set(), rcode: 0 };
        if (r.f['dns.flags.response']) { e.r++; [].concat(r.f['dns.a'] || [], r.f['dns.aaaa'] || [], r.f['dns.cname'] || [], r.f['dns.ptr'] || []).forEach(a => e.ans.add(a)); if (r.f['dns.flags.rcode']) e.rcode = r.f['dns.flags.rcode']; }
        else e.q++;
        dnsQ.set(n, e);
      }
    }
    const dnsRows = [...dnsQ.values()].sort((a, b) => (b.q + b.r) - (a.q + a.r)).slice(0, 12);

    E.viewI.innerHTML = `<div class="ins-grid">
      <div class="card ins span-5"><h3>Protocol hierarchy <span>top-layer protocol</span></h3>
        <div class="donut-wrap">${donut(protos, total)}<div class="legend">${protos.slice(0, 9).map(([k, n]) => `<button data-filter="${protoFilterName(k)}" style="--c:${colorOf(k)}"><i></i><b>${esc(k)}</b><span>${fmtNum(n)} · ${(n / total * 100).toFixed(1)}%</span></button>`).join('')}</div></div></div>
      <div class="card ins span-7 timeline"><h3>Traffic over time <span>${fmtDur(span)} · ${NB} buckets</span></h3>
        <svg viewBox="0 0 ${W} ${Hh}" preserveAspectRatio="none">${tl}</svg>
        <div class="axis"><span>${t0.toFixed(2)}s</span><span>${(t0 + span / 2).toFixed(2)}s</span><span>${t1.toFixed(2)}s</span></div>
        <div class="tl-legend" style="margin-top:8px">${top.map(k => `<span><i style="--c:${colorOf(k)}"></i>${esc(k)}</span>`).join('')}${protos.length > 6 ? '<span><i style="--c:#475569"></i>Other</span>' : ''}</div></div>
      <div class="card ins span-6"><h3>Top talkers <span>by bytes</span></h3><div class="bars">${barRows(talkers.map(([a, b]) => [a, b, `addr == ${a}`]), talkers[0] ? talkers[0][1] : 1, fmtBytes)}</div></div>
      <div class="card ins span-6"><h3>Services <span>by packets</span></h3><div class="bars">${barRows(services.map(s => [`${s.port}/${s.kind}`, s.n, `${s.kind}.port == ${s.port}`, Decoder.SERVICES[s.port] || '']), services[0] ? services[0].n : 1, fmtNum, 'linear-gradient(90deg,#a78bfa,#f472b6)')}</div></div>
      <div class="card ins span-6"><h3>TCP flags <span>${fmtNum(tcpN)} segments</span></h3><div class="flag-grid">${Object.entries(fl).map(([k, n]) => `<div data-filter="${flagFilters[k]}" style="--fc:${flagCol[k]}"><b>${fmtNum(n)}</b><span>${k}</span></div>`).join('')}</div></div>
      <div class="card ins span-6"><h3>Frame sizes <span>bytes on wire</span></h3><div class="hist">${hist.map((n, i) => `<div data-filter="frame.len >= ${bins[i][0]}${isFinite(bins[i][1]) ? ` && frame.len <= ${bins[i][1]}` : ''}" title="${n} frames"><b>${n}</b><i style="height:${n / hmax * 100}%"></i><span>${isFinite(bins[i][1]) ? `${bins[i][0]}–${bins[i][1]}` : `${bins[i][0]}+`}</span></div>`).join('')}</div></div>
      <div class="card ins span-12"><h3>DNS lookups <span>${dnsQ.size} names</span></h3>${dnsRows.length ? `<table class="dtable"><thead><tr><th>Name</th><th>Type</th><th>Queries</th><th>Responses</th><th>Answers</th></tr></thead><tbody>${dnsRows.map(e => `<tr data-filter="dns.qry.name == &quot;${esc(e.n)}&quot;"><td class="t">${esc(e.n)}</td><td>${esc(e.type || '')}</td><td>${e.q}</td><td>${e.r}</td><td>${e.rcode ? '<span style="color:var(--bad)">NXDOMAIN / error</span>' : esc([...e.ans].join(', ') || '—')}</td></tr>`).join('')}</tbody></table>` : '<p style="color:var(--muted);margin:0">No DNS traffic in view.</p>'}</div>
    </div>`;
  }
  E.viewI.addEventListener('click', e => {
    const t = e.target.closest('[data-filter]'); if (t) setFilter(t.dataset.filter);
  });

  // ================================================================ conversations
  function buildConvs() {
    const m = new Map();
    for (const r of S.recs) {
      let key, a, b, label;
      const src = r.f['ip.src'] || r.f['ipv6.src'], dst = r.f['ip.dst'] || r.f['ipv6.dst'];
      if (r.skind) { key = r.skind + ':' + r.stream; a = `${src}:${r.sport}`; b = `${dst}:${r.dport}`; label = r.skind.toUpperCase(); }
      else if (src) { const [x, y] = [src, dst].sort(); key = 'ip:' + x + '|' + y + ':' + r.proto; a = src; b = dst; label = r.proto; }
      else continue;
      let c = m.get(key);
      if (!c) { c = { key, kind: label, a, b, pk: 0, bytes: 0, ab: 0, ba: 0, start: r.rel, end: r.rel, apps: new Set(), filter: r.skind ? `${r.skind}.stream == ${r.stream}` : convFilter(r), warn: 0 }; m.set(key, c); }
      c.pk++; c.bytes += r.len; c.end = r.rel;
      const fromA = r.skind ? `${src}:${r.sport}` === c.a : src === c.a;
      if (fromA) c.ab += r.len; else c.ba += r.len;
      if (!['TCP', 'UDP', 'IPv4', 'IPv6'].includes(r.proto)) c.apps.add(r.proto);
      if (r.warn) c.warn++;
    }
    return [...m.values()];
  }
  function renderConvs() {
    if (!S.convs) S.convs = buildConvs();
    const { k, d } = S.convSort;
    const list = S.convs.slice().sort((x, y) => {
      const a = x[k], b = y[k];
      return (typeof a === 'number' ? a - b : coll.compare(String(a), String(b))) * d;
    });
    const maxB = Math.max(1, ...list.map(c => c.bytes));
    const cols = [['kind', 'Type'], ['a', 'Address A'], ['b', 'Address B'], ['apps', 'Application'], ['pk', 'Packets'], ['bytes', 'Bytes'], ['ab', 'A → B'], ['ba', 'B → A'], ['start', 'Start'], ['dur', 'Duration']];
    list.forEach(c => { c.dur = c.end - c.start; });
    E.viewC.innerHTML = `<div class="card conv-card"><div class="conv-head"><div><h3>Conversations</h3><p>${list.length} endpoint pairs across the whole capture · click a row to filter</p></div></div>
      <table class="dtable"><thead><tr>${cols.map(([ck, l]) => `<th data-k="${ck}" class="${k === ck ? 'on' : ''}">${l}${k === ck ? (d > 0 ? ' ▲' : ' ▼') : ''}</th>`).join('')}</tr></thead>
      <tbody>${list.map(c => `<tr data-filter="${esc(c.filter)}"><td><span class="pbadge" style="--pc:${colorOf(c.kind === 'TCP' ? 'TCP' : c.kind === 'UDP' ? 'UDP' : c.kind)}">${esc(c.kind)}</span></td><td class="t">${esc(c.a)}</td><td class="t">${esc(c.b)}</td>
        <td>${[...c.apps].map(p => `<span class="pbadge" style="--pc:${colorOf(p)}">${esc(p)}</span>`).join(' ') || '—'}${c.warn ? ` <span style="color:var(--bad)" title="packets with warnings">⚠ ${c.warn}</span>` : ''}</td>
        <td>${c.pk}</td><td><span class="mini" style="width:${Math.max(3, c.bytes / maxB * 60)}px"></span>${fmtBytes(c.bytes)}</td><td>${fmtBytes(c.ab)}</td><td>${fmtBytes(c.ba)}</td><td>${c.start.toFixed(3)}s</td><td>${fmtDur(c.dur)}</td></tr>`).join('')}</tbody></table></div>`;
  }
  E.viewC.addEventListener('click', e => {
    const th = e.target.closest('th[data-k]');
    if (th) { const k = th.dataset.k; S.convSort = S.convSort.k === k ? { k, d: -S.convSort.d } : { k, d: k === 'a' || k === 'b' || k === 'kind' ? 1 : -1 }; renderConvs(); return; }
    const tr = e.target.closest('tr[data-filter]'); if (tr) setFilter(tr.dataset.filter);
  });

  // ================================================================ follow stream
  function openStream(r) {
    if (!r.skind) return toast('Not a TCP/UDP packet — nothing to follow.', 'err');
    const key = `${r.skind}.stream`, id = r.stream;
    const pk = S.recs.filter(x => x.f[key] === id);
    const first = pk[0];
    const client = `${first.f['ip.src'] || first.f['ipv6.src']}:${first.sport}`, server = `${first.f['ip.dst'] || first.f['ipv6.dst']}:${first.dport}`;
    S.streamKey = { key, id, pk, client, server };
    $('#streamTitle').textContent = `Follow ${r.skind.toUpperCase()} stream #${id}`;
    renderStream();
    E.modal.hidden = false;
  }
  function renderStream() {
    const { pk, client, server, key, id } = S.streamKey;
    let cb = 0, sb = 0, html = '', last = null, buf = [];
    const flush = () => {
      if (!buf.length) return;
      const bytes = buf.flatMap(x => Array.from(x.r.d.subarray(x.p.o, x.p.o + x.p.l)));
      const isC = last === client;
      let body;
      if (S.streamMode === 'hex') {
        body = '';
        for (let i = 0; i < bytes.length; i += 16) {
          const sl = bytes.slice(i, i + 16);
          body += i.toString(16).padStart(8, '0') + '  ' + sl.map(b => HEX[b]).join(' ').padEnd(48) + '  ' + sl.map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('') + '\n';
        }
      } else body = bytes.map(b => (b >= 32 && b < 127) || b === 10 || b === 13 || b === 9 ? String.fromCharCode(b) : '.').join('');
      const shown = body.length > 20000 ? body.slice(0, 20000) + '\n… (truncated)' : body;
      html += `<pre class="chunk ${isC ? 'c' : 's'}"><span class="meta">${isC ? '▶ client' : '◀ server'} · ${bytes.length} bytes · frames ${buf.map(x => x.r.no).join(', ')}</span>${esc(shown)}</pre>`;
      buf = [];
    };
    for (const r of pk) {
      if (!r.payload || !r.payload.l) continue;
      if (r.payload.from !== last) { flush(); last = r.payload.from; }
      if (r.payload.from === client) cb += r.payload.l; else sb += r.payload.l;
      buf.push({ r, p: r.payload });
    }
    flush();
    $('#streamSub').textContent = `${key} == ${id} · ${pk.length} packets · ${fmtDur(pk[pk.length - 1].rel - pk[0].rel)}`;
    $('#streamLegend').innerHTML = `<span><i style="background:#f87171"></i>${esc(client)} → ${esc(server)} · ${fmtBytes(cb)}</span><span><i style="background:#60a5fa"></i>${esc(server)} → ${esc(client)} · ${fmtBytes(sb)}</span>`;
    $('#streamBody').innerHTML = html || '<p style="color:var(--muted)">This stream carries no payload bytes (handshake / control only).</p>';
  }
  $('#streamMode').addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b) return;
    S.streamMode = b.dataset.sm;
    $$('#streamMode button').forEach(x => x.classList.toggle('on', x === b));
    renderStream();
  });
  const closeModal = () => { E.modal.hidden = true; };
  $('#streamClose').addEventListener('click', closeModal);
  E.modal.addEventListener('click', e => { if (e.target === E.modal) closeModal(); });
  $('#streamFilter').addEventListener('click', () => { const { key, id } = S.streamKey; closeModal(); setFilter(`${key} == ${id}`); });

  // ================================================================ context menu
  function openCtx(x, y, r) {
    const src = r.f['ip.src'] || r.f['ipv6.src'], dst = r.f['ip.dst'] || r.f['ipv6.dst'];
    const items = [];
    if (r.skind) items.push(['follow', `Follow ${r.skind.toUpperCase()} stream`, 'F']);
    items.push(['conv', 'Filter conversation', convFilter(r)]);
    if (src) items.push(['f', 'Filter source host', `addr == ${src}`], ['f', 'Filter destination host', `addr == ${dst}`]);
    if (r.sport != null) items.push(['f', 'Filter destination port', `port == ${r.dport}`]);
    const top = r.layers[r.layers.length - 1];
    if (top && top.key !== 'frame') items.push(['f', `Filter protocol`, top.key]);
    items.push(['f', 'Exclude this protocol', `!${top.key}`]);
    items.push(null, ['copy', 'Copy summary line', ''], ['hex', 'Copy bytes as hex', '']);
    E.ctx.innerHTML = items.map(it => it ? `<button data-a="${it[0]}" data-v="${esc(it[2])}">${esc(it[1])}${it[2] && it[0] !== 'follow' ? `<code>${esc(it[2])}</code>` : it[0] === 'follow' ? '<code>F</code>' : ''}</button>` : '<hr>').join('');
    E.ctx.classList.add('open');
    const w = E.ctx.offsetWidth, h = E.ctx.offsetHeight;
    E.ctx.style.left = Math.min(x, innerWidth - w - 8) + 'px';
    E.ctx.style.top = Math.min(y, innerHeight - h - 8) + 'px';
    E.ctx._r = r;
  }
  E.ctx.addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b) return;
    const r = E.ctx._r; E.ctx.classList.remove('open');
    const a = b.dataset.a;
    if (a === 'follow') openStream(r);
    else if (a === 'conv' || a === 'f') setFilter(b.dataset.v);
    else if (a === 'copy') copyText(`${r.no}\t${r.rel.toFixed(6)}\t${r.src}\t${r.dst}\t${r.proto}\t${r.len}\t${r.info}`, 'Summary copied');
    else if (a === 'hex') copyText(Array.from(r.d, x => HEX[x]).join(''), 'Packet bytes copied as hex');
  });
  async function copyText(t, msg) {
    try { await navigator.clipboard.writeText(t); toast(msg); }
    catch { toast('Clipboard unavailable in this context', 'err'); }
  }

  // ================================================================ export
  E.exportBtn.addEventListener('click', e => { e.stopPropagation(); E.exportMenu.classList.toggle('open'); });
  E.exportMenu.addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b) return;
    E.exportMenu.classList.remove('open');
    const v = S.view.map(i => S.recs[i]);
    const base = S.name.replace(/\.(pcapng|pcap|cap)$/i, '') + (S.ftext || S.protos.size ? '-filtered' : '');
    if (b.dataset.exp === 'pcap') {
      download(PcapParser.write(v.slice().sort((a, b) => a.no - b.no), S.cap.linktype), base + '.pcap', 'application/vnd.tcpdump.pcap');
    } else if (b.dataset.exp === 'csv') {
      const q = s => `"${String(s).replace(/"/g, '""')}"`;
      const csv = ['No.,Time,Source,Destination,Protocol,Length,Info'].concat(v.map(r => [r.no, r.rel.toFixed(6), q(r.src), q(r.dst), r.proto, r.len, q(r.info)].join(','))).join('\r\n');
      download(csv, base + '.csv', 'text/csv');
    } else {
      const strip = f => { const o = { name: f.n, value: f.v, offset: f.o, length: f.l }; if (f.bits) o.bits = f.bits; if (f.c) o.children = f.c.map(strip); return o; };
      const json = v.map(r => ({ no: r.no, time: r.ts, relative: r.rel, src: r.src, dst: r.dst, protocol: r.proto, length: r.len, info: r.info, layers: r.layers.map(L => ({ protocol: L.key, name: L.name, summary: L.sum, fields: L.fields.map(strip) })) }));
      download(JSON.stringify(json, null, 2), base + '.json', 'application/json');
    }
    toast(`Exported ${fmtNum(v.length)} packets as .${b.dataset.exp}`);
  });

  // ================================================================ splitter
  E.splitter.addEventListener('pointerdown', e => {
    e.preventDefault();
    E.splitter.setPointerCapture(e.pointerId); E.splitter.classList.add('drag');
    const rect = E.viewP.getBoundingClientRect();
    const move = ev => { const h = Math.max(120, Math.min(rect.height - 200, ev.clientY - rect.top)); E.viewP.style.setProperty('--top', h + 'px'); renderRows(); };
    const up = () => { E.splitter.classList.remove('drag'); E.splitter.removeEventListener('pointermove', move); E.splitter.removeEventListener('pointerup', up); };
    E.splitter.addEventListener('pointermove', move); E.splitter.addEventListener('pointerup', up);
  });

  // ================================================================ global events
  $('#btnOpen').addEventListener('click', () => E.file.click());
  $('#dzOpen').addEventListener('click', e => { e.stopPropagation(); E.file.click(); });
  $('#btnSample').addEventListener('click', loadSample);
  $('#dzSample').addEventListener('click', e => { e.stopPropagation(); loadSample(); });
  $('#dropzone').addEventListener('click', () => E.file.click());
  $('#dropzone').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); E.file.click(); } });
  $('#dlSample').addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); download(SampleCapture.build(), 'sample-home-network.pcap', 'application/vnd.tcpdump.pcap'); toast('sample-home-network.pcap downloaded'); });
  $('#brandHome').addEventListener('click', e => { e.preventDefault(); if (!S.recs.length) return; E.landing.hidden = !E.landing.hidden; E.ws.hidden = !E.landing.hidden; E.status.hidden = E.ws.hidden; if (!E.ws.hidden) renderRows(); });
  E.file.addEventListener('change', () => { loadFile(E.file.files[0]); E.file.value = ''; });

  let dragDepth = 0;
  window.addEventListener('dragenter', e => { if (e.dataTransfer && [...e.dataTransfer.types].includes('Files')) { dragDepth++; E.drop.classList.add('on'); } });
  window.addEventListener('dragleave', () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) E.drop.classList.remove('on'); });
  window.addEventListener('dragover', e => e.preventDefault());
  window.addEventListener('drop', e => { e.preventDefault(); dragDepth = 0; E.drop.classList.remove('on'); const f = e.dataTransfer.files[0]; if (f) loadFile(f); });

  document.addEventListener('click', e => {
    if (!e.target.closest('.menu-wrap')) E.exportMenu.classList.remove('open');
    if (!e.target.closest('.ctx')) E.ctx.classList.remove('open');
  });
  window.addEventListener('blur', () => E.ctx.classList.remove('open'));

  document.addEventListener('keydown', e => {
    const typing = /INPUT|TEXTAREA/.test(document.activeElement.tagName);
    if (e.key === 'Escape') {
      if (!E.modal.hidden) return closeModal();
      E.ctx.classList.remove('open'); E.exportMenu.classList.remove('open');
      if (!typing && (S.ftext || S.protos.size)) { E.finput.value = ''; S.protos.clear(); applyFilterText(''); }
      return;
    }
    if (typing || !S.recs.length || !E.modal.hidden) return;
    if (e.key === '/' || (e.key === 'f' && (e.ctrlKey || e.metaKey))) { e.preventDefault(); E.finput.focus(); E.finput.select(); return; }
    if (S.tab !== 'packets') return;
    const page = Math.max(1, Math.floor(E.tbody.clientHeight / ROW_H) - 1);
    const keys = { ArrowDown: 1, j: 1, ArrowUp: -1, k: -1, PageDown: page, PageUp: -page };
    if (keys[e.key] != null) { e.preventDefault(); moveSel(keys[e.key]); }
    else if (e.key === 'Home') { e.preventDefault(); select(S.view[0], true); }
    else if (e.key === 'End') { e.preventDefault(); select(S.view[S.view.length - 1], true); }
    else if (e.key === 'f' || e.key === 'F') { const r = S.recs[S.sel]; if (r && r.skind) openStream(r); }
  });

  // deep-link: ?sample opens the demo directly
  if (/[?&#]sample\b/.test(location.href)) loadSample();
})();
