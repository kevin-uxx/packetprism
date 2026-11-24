/* PacketPrism — deterministic sample capture generator.
 * Builds a realistic home-network session (DHCP, ARP, IPv6 ND, DNS, HTTP, TLS 1.3,
 * ICMP ping + traceroute, NTP, SSDP, mDNS, refused port probes) as a real .pcap file
 * with correct IPv4 / TCP / UDP / ICMPv6 checksums.
 */
(function (global) {
  'use strict';
  const enc = new TextEncoder();
  function cat(...parts) {
    const out = [];
    for (const p of parts) {
      if (typeof p === 'number') out.push(p & 255);
      else if (typeof p === 'string') for (const b of enc.encode(p)) out.push(b);
      else for (const b of p) out.push(b);
    }
    return out;
  }
  const u16 = n => [(n >>> 8) & 255, n & 255];
  const u24 = n => [(n >>> 16) & 255, (n >>> 8) & 255, n & 255];
  const u32 = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
  const macB = s => s.split(':').map(h => parseInt(h, 16));
  const ipB = s => s.split('.').map(Number);
  function ip6B(s) {
    const [h, t] = s.split('::');
    const hp = h ? h.split(':') : [], tp = t !== undefined ? (t ? t.split(':') : []) : [];
    const fill = t !== undefined ? 8 - hp.length - tp.length : 0;
    return [...hp, ...Array(fill).fill('0'), ...tp].flatMap(g => u16(parseInt(g, 16)));
  }
  let seed = 1;
  function rnd() { seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }
  const rb = n => Array.from({ length: n }, () => Math.floor(rnd() * 256));
  const ri = (a, b) => a + Math.floor(rnd() * (b - a + 1));
  const rf = (a, b) => a + rnd() * (b - a);
  const r32 = () => Math.floor(rnd() * 4294967295) >>> 0;
  function csum(b) { let s = 0; for (let i = 0; i < b.length; i += 2) s += (b[i] << 8) | (b[i + 1] || 0); while (s >>> 16) s = (s & 0xffff) + (s >>> 16); return (~s) & 0xffff; }

  const FIN = 1, SYN = 2, RST = 4, PSH = 8, ACK = 16;

  // ---- frame builders
  function eth(dst, src, type, pl) { const f = cat(macB(dst), macB(src), u16(type), pl); while (f.length < 60) f.push(0); return f; }
  let ipid = 0;
  function ip4(src, dst, proto, pl, ttl = 64, df = true) {
    const h = cat(0x45, 0, u16(20 + pl.length), u16(ipid = (ipid + ri(1, 3)) & 0xffff), u16(df ? 0x4000 : 0), ttl, proto, 0, 0, ipB(src), ipB(dst));
    const c = csum(h); h[10] = c >> 8; h[11] = c & 255;
    return cat(h, pl);
  }
  const pseudo4 = (s, d, p, l) => cat(ipB(s), ipB(d), 0, p, u16(l));
  function tcpSeg(src, dst, sp, dp, seq, ack, flags, pl = [], win = 64240, opts = []) {
    const s = cat(u16(sp), u16(dp), u32(seq), u32(ack), ((20 + opts.length) / 4) << 4, flags, u16(win), 0, 0, 0, 0, opts, pl);
    const c = csum(cat(pseudo4(src, dst, 6, s.length), s)); s[16] = c >> 8; s[17] = c & 255;
    return s;
  }
  function udpSeg(src, dst, sp, dp, pl) {
    const s = cat(u16(sp), u16(dp), u16(8 + pl.length), 0, 0, pl);
    let c = csum(cat(pseudo4(src, dst, 17, s.length), s)); if (c === 0) c = 0xffff;
    s[6] = c >> 8; s[7] = c & 255;
    return s;
  }
  function ip6(src, dst, nh, pl, hop = 255) { return cat(0x60, 0, 0, 0, u16(pl.length), nh, hop, ip6B(src), ip6B(dst), pl); }
  function icmp6(src, dst, type, code, body, hop = 255) {
    const m = cat(type, code, 0, 0, body);
    const c = csum(cat(ip6B(src), ip6B(dst), u32(m.length), 0, 0, 0, 58, m)); m[2] = c >> 8; m[3] = c & 255;
    return ip6(src, dst, 58, m, hop);
  }
  function icmp4(type, code, rest, data) { const m = cat(type, code, 0, 0, rest, data); const c = csum(m); m[2] = c >> 8; m[3] = c & 255; return m; }

  // ---- network
  const H = { ip: '192.168.1.42', mac: '3c:22:fb:9a:41:07', ll: 'fe80::3e22:fbff:fe9a:4107', g6: '2001:db8:1::3e22:fbff:fe9a:4107' };
  const GW = { ip: '192.168.1.1', mac: 'a4:91:b1:0c:2e:58', ll: 'fe80::a691:b1ff:fe0c:2e58' };
  const TV = { ip: '192.168.1.17', mac: '8c:85:90:5e:12:aa' };
  const NAS = { ip: '192.168.1.20', mac: '00:11:32:3a:4f:9c' };
  const BC = 'ff:ff:ff:ff:ff:ff';
  const DNS1 = '1.1.1.1';

  let ev = [];
  const at = (t, f) => ev.push([t, f]);
  const toNet = (p, mac = GW.mac) => eth(mac, H.mac, 0x0800, p);
  const fromNet = (p, mac = GW.mac) => eth(H.mac, mac, 0x0800, p);

  // ---- DNS
  function dname(n) { const o = []; for (const l of n.split('.')) o.push(l.length, ...enc.encode(l)); o.push(0); return o; }
  const T = { A: 1, CNAME: 5, PTR: 12, AAAA: 28, HTTPS: 65 };
  function dnsQ(id, name, type, flags = 0x0100) { return cat(u16(id), u16(flags), u16(1), u16(0), u16(0), u16(0), dname(name), u16(type), u16(1)); }
  function dnsR(id, name, type, answers, rcode = 0) {
    return cat(u16(id), u16(0x8180 | rcode), u16(1), u16(answers.length), u16(0), u16(0), dname(name), u16(type), u16(1),
      ...answers.map(a => cat(a.name ? dname(a.name) : [0xc0, 0x0c], u16(a.type), u16(a.cls || 1), u32(a.ttl), u16(a.data.length), a.data)));
  }
  function dnsLookup(t, name, type, answers, rcode = 0, rtt = rf(0.008, 0.03)) {
    const id = ri(1, 65535), sp = ri(49152, 65000);
    at(t, toNet(ip4(H.ip, DNS1, 17, udpSeg(H.ip, DNS1, sp, 53, dnsQ(id, name, type)))));
    at(t + rtt, fromNet(ip4(DNS1, H.ip, 17, udpSeg(DNS1, H.ip, 53, sp, dnsR(id, name, type, answers, rcode)), 57)));
    return t + rtt;
  }
  const A = (ip, ttl = 300, name) => ({ type: T.A, ttl, data: ipB(ip), name });

  // ---- TCP conversation helper (tracks seq/ack correctly)
  function tcpConv(t0, sIp, sp, cp, { ttl = 56, rtt = 0.02, mac = GW.mac } = {}) {
    let cs = r32(), ss = r32(), t = t0;
    const c = (dt, fl, pl = [], opts = [], win = 513) => {
      t += dt;
      at(t, toNet(ip4(H.ip, sIp, 6, tcpSeg(H.ip, sIp, cp, sp, cs, (fl & ACK) ? ss : 0, fl, pl, fl & SYN ? 64240 : win, opts)), mac));
      cs = (cs + pl.length + ((fl & (SYN | FIN)) ? 1 : 0)) >>> 0;
    };
    const s = (dt, fl, pl = [], opts = [], win = 501) => {
      t += dt;
      at(t, fromNet(ip4(sIp, H.ip, 6, tcpSeg(sIp, H.ip, sp, cp, ss, (fl & ACK) ? cs : 0, fl, pl, fl & SYN ? 65535 : win, opts), ttl), mac));
      ss = (ss + pl.length + ((fl & (SYN | FIN)) ? 1 : 0)) >>> 0;
    };
    const SYN_OPT = [2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2];
    const SYNACK_OPT = [2, 4, 0x05, 0xac, 1, 1, 4, 2, 1, 3, 3, 9];
    return {
      c, s, rtt,
      get t() { return t; },
      open() { c(0, SYN, [], SYN_OPT); s(rtt, SYN | ACK, [], SYNACK_OPT); c(rf(0.0001, 0.0004), ACK); },
      close(gap = 0.3) { c(gap, FIN | ACK); s(rtt, FIN | ACK); c(rf(0.0001, 0.0004), ACK); }
    };
  }

  // ---- TLS records
  const ext = (t, data) => cat(u16(t), u16(data.length), data);
  const rec = (ct, body, ver = 0x0303) => cat(ct, u16(ver), u16(body.length), body);
  function clientHello(sni) {
    const suites = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8];
    const exts = cat(
      ext(0, cat(u16(sni.length + 3), 0, u16(sni.length), sni)),
      ext(23, []), ext(65281, [0]),
      ext(10, cat(u16(8), u16(0x11ec), u16(0x001d), u16(0x0017), u16(0x0018))),
      ext(11, [1, 0]),
      ext(35, []),
      ext(16, cat(u16(12), 2, 'h2', 8, 'http/1.1')),
      ext(13, cat(u16(8), u16(0x0403), u16(0x0804), u16(0x0401), u16(0x0503))),
      ext(51, cat(u16(36), u16(0x001d), u16(32), rb(32))),
      ext(45, [1, 1]),
      ext(43, cat(4, u16(0x0304), u16(0x0303)))
    );
    const body = cat(u16(0x0303), rb(32), 32, rb(32), u16(suites.length * 2), suites.flatMap(u16), 1, 0, u16(exts.length), exts);
    return rec(22, cat(1, u24(body.length), body), 0x0301);
  }
  function serverHello() {
    const exts = cat(ext(43, u16(0x0304)), ext(51, cat(u16(0x001d), u16(32), rb(32))));
    const body = cat(u16(0x0303), rb(32), 32, rb(32), u16(0x1301), 0, u16(exts.length), exts);
    return rec(22, cat(2, u24(body.length), body));
  }
  const ccs = () => rec(20, [1]);
  const appData = n => rec(23, rb(n));

  function tlsSession(t0, host, ip, { requests = 6, ttl = 56, rtt = 0.02, gap = [0.2, 2.5], cname = null } = {}) {
    const answers = cname ? [{ type: T.CNAME, ttl: 300, data: dname(cname) }, A(ip, 60, cname)] : [A(ip, ri(60, 300))];
    const t1 = dnsLookup(t0, host, T.A, answers);
    const k = tcpConv(t1 + rf(0.001, 0.004), ip, 443, ri(50000, 64000), { ttl, rtt });
    k.open();
    k.c(0.0003, PSH | ACK, clientHello(host));
    k.s(rtt, ACK);
    k.s(rf(0.001, 0.004), PSH | ACK, cat(serverHello(), ccs(), appData(ri(1100, 1250))));
    k.s(0.0002, PSH | ACK, appData(ri(900, 1380)));
    k.c(0.0004, ACK);
    k.c(0.003, PSH | ACK, cat(ccs(), appData(53)));
    for (let i = 0; i < requests; i++) {
      k.c(i ? rf(gap[0], gap[1]) : 0.0005, PSH | ACK, appData(ri(90, 620)));
      k.s(rtt + rf(0.002, 0.03), PSH | ACK, appData(ri(150, 1380)));
      if (rnd() < 0.5) k.s(0.0003, PSH | ACK, appData(ri(200, 1380)));
      k.c(0.0004, ACK);
    }
    k.close(rf(0.5, 2));
  }

  // ---- HTTP
  const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
  const HTML = '<!doctype html>\n<html>\n<head>\n    <title>Example Domain</title>\n    <meta charset="utf-8" />\n    <meta name="viewport" content="width=device-width, initial-scale=1" />\n    <style type="text/css">\n    body { background-color: #f0f0f2; margin: 0; padding: 0; font-family: -apple-system, system-ui, sans-serif; }\n    div { width: 600px; margin: 5em auto; padding: 2em; background-color: #fdfdff; border-radius: 0.5em; }\n    a:link, a:visited { color: #38488f; text-decoration: none; }\n    </style>\n</head>\n<body>\n<div>\n    <h1>Example Domain</h1>\n    <p>This domain is for use in illustrative examples in documents. You may use this\n    domain in literature without prior coordination or asking for permission.</p>\n    <p><a href="https://www.iana.org/domains/example">More information...</a></p>\n</div>\n</body>\n</html>\n';

  function build() {
    seed = 0x5eed2026; ipid = 0x3a10; ev = [];

    // DHCP DORA
    const xid = r32();
    const dhcp = (op, type, yi, extra) => cat(op, 1, 6, 0, u32(xid), u16(0), u16(op === 1 ? 0x8000 : 0), [0, 0, 0, 0], ipB(yi), ipB(op === 2 ? GW.ip : '0.0.0.0'), [0, 0, 0, 0],
      macB(H.mac), Array(10).fill(0), Array(64).fill(0), Array(128).fill(0), [99, 130, 83, 99], [53, 1, type], extra, 255);
    const cliOpts = cat([61, 7, 1], macB(H.mac), [12, 11], 'workstation', [55, 6, 1, 3, 6, 15, 51, 54]);
    const srvOpts = cat([54, 4], ipB(GW.ip), [51, 4], u32(86400), [58, 4], u32(43200), [1, 4, 255, 255, 255, 0], [3, 4], ipB(GW.ip), [6, 8], ipB('1.1.1.1'), ipB('8.8.8.8'), [15, 3], 'lan');
    const bcast = (p, src) => eth(BC, src, 0x0800, p);
    at(0.000000, bcast(ip4('0.0.0.0', '255.255.255.255', 17, udpSeg('0.0.0.0', '255.255.255.255', 68, 67, dhcp(1, 1, '0.0.0.0', cliOpts)), 64, false), H.mac));
    at(0.002104, bcast(ip4(GW.ip, '255.255.255.255', 17, udpSeg(GW.ip, '255.255.255.255', 67, 68, dhcp(2, 2, H.ip, srvOpts)), 64, false), GW.mac));
    at(0.015733, bcast(ip4('0.0.0.0', '255.255.255.255', 17, udpSeg('0.0.0.0', '255.255.255.255', 68, 67, dhcp(1, 3, '0.0.0.0', cat([50, 4], ipB(H.ip), [54, 4], ipB(GW.ip), cliOpts))), 64, false), H.mac));
    at(0.018902, bcast(ip4(GW.ip, '255.255.255.255', 17, udpSeg(GW.ip, '255.255.255.255', 67, 68, dhcp(2, 5, H.ip, srvOpts)), 64, false), GW.mac));

    // ARP: gratuitous + resolve gateway
    const arp = (op, sha, spa, tha, tpa) => cat(u16(1), u16(0x0800), 6, 4, u16(op), macB(sha), ipB(spa), macB(tha), ipB(tpa));
    at(0.031, eth(BC, H.mac, 0x0806, arp(1, H.mac, H.ip, '00:00:00:00:00:00', H.ip)));
    at(0.052, eth(BC, H.mac, 0x0806, arp(1, H.mac, H.ip, '00:00:00:00:00:00', GW.ip)));
    at(0.0526, eth(H.mac, GW.mac, 0x0806, arp(2, GW.mac, GW.ip, H.mac, H.ip)));

    // IPv6 neighbour discovery
    at(0.081, eth('33:33:ff:9a:41:07', H.mac, 0x86dd, icmp6('::', 'ff02::1:ff9a:4107', 135, 0, cat(u32(0), ip6B(H.g6)))));
    at(0.094, eth('33:33:00:00:00:02', H.mac, 0x86dd, icmp6(H.ll, 'ff02::2', 133, 0, cat(u32(0), [1, 1], macB(H.mac)))));
    at(0.0978, eth('33:33:00:00:00:01', GW.mac, 0x86dd, icmp6(GW.ll, 'ff02::1', 134, 0, cat(64, 0, u16(1800), u32(0), u32(0), [1, 1], macB(GW.mac), [5, 1, 0, 0], u32(1500), [3, 4, 64, 0xc0], u32(86400), u32(14400), u32(0), ip6B('2001:db8:1::')))));

    // NTP
    const BASE = Date.UTC(2026, 10, 24, 9, 41, 7) / 1000 + 0.123456;
    const ntpTs = s => { const x = s + 2208988800; const sec = Math.floor(x); return cat(u32(sec), u32(Math.floor((x - sec) * 4294967296))); };
    const nc = ri(40000, 60000);
    const ntpReq = cat(0x23, 0, 6, 0xe9, u32(0), u32(0), u32(0), Array(24).fill(0), ntpTs(BASE + 0.41));
    at(0.41, toNet(ip4(H.ip, '162.159.200.123', 17, udpSeg(H.ip, '162.159.200.123', nc, 123, ntpReq))));
    const ntpResp = cat(0x24, 3, 6, 0xe7, u32(0x190), u32(0x45c), ipB('10.43.8.1'), ntpTs(BASE - 812.4), ntpTs(BASE + 0.41), ntpTs(BASE + 0.4192), ntpTs(BASE + 0.4193));
    at(0.4285, fromNet(ip4('162.159.200.123', H.ip, 17, udpSeg('162.159.200.123', H.ip, 123, nc, ntpResp), 58)));

    // HTTP to example.com
    const ex = '93.184.215.14';
    let t = dnsLookup(1.104, 'example.com', T.A, [A(ex, 3412)]);
    const h = tcpConv(t + 0.0011, ex, 80, ri(50000, 64000), { ttl: 54, rtt: 0.0213 });
    h.open();
    h.c(0.0004, PSH | ACK, `GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: ${UA}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: identity\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\n\r\n`);
    h.s(0.0213, ACK);
    h.s(0.0011, PSH | ACK, `HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: ${HTML.length}\r\nCache-Control: max-age=604800\r\nDate: Tue, 24 Nov 2026 09:41:08 GMT\r\nEtag: "3147526947+ident"\r\nServer: ECAcc (nyd/D184)\r\nConnection: keep-alive\r\n\r\n${HTML}`);
    h.c(0.0003, ACK);
    h.c(0.092, PSH | ACK, `GET /favicon.ico HTTP/1.1\r\nHost: example.com\r\nUser-Agent: ${UA}\r\nAccept: image/avif,image/webp,image/*,*/*;q=0.8\r\nReferer: http://example.com/\r\nConnection: keep-alive\r\n\r\n`);
    h.s(0.0224, PSH | ACK, 'HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 0\r\nDate: Tue, 24 Nov 2026 09:41:08 GMT\r\nServer: ECAcc (nyd/D184)\r\n\r\n');
    h.c(0.0004, ACK);
    h.close(4.6);

    // SSDP + mDNS discovery
    const ssdp = `M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: urn:dial-multiscreen-org:service:dial:1\r\nUSER-AGENT: Chromium/131.0.0.0 Windows\r\n\r\n`;
    const ssp = ri(50000, 60000);
    for (const tt of [2.51, 2.62, 7.53]) at(tt, eth('01:00:5e:7f:ff:fa', H.mac, 0x0800, ip4(H.ip, '239.255.255.250', 17, udpSeg(H.ip, '239.255.255.250', ssp, 1900, ssdp), 4)));
    at(2.71, eth('01:00:5e:00:00:fb', H.mac, 0x0800, ip4(H.ip, '224.0.0.251', 17, udpSeg(H.ip, '224.0.0.251', 5353, 5353, dnsQ(0, '_googlecast._tcp.local', T.PTR, 0)), 255)));
    const castName = 'Living-Room-TV-4f1c._googlecast._tcp.local';
    const mresp = cat(u16(0), u16(0x8400), u16(0), u16(1), u16(0), u16(0), dname('_googlecast._tcp.local'), u16(T.PTR), u16(1), u32(120), u16(dname(castName).length), dname(castName));
    at(2.7342, eth('01:00:5e:00:00:fb', TV.mac, 0x0800, ip4(TV.ip, '224.0.0.251', 17, udpSeg(TV.ip, '224.0.0.251', 5353, 5353, mresp), 255)));

    // TLS sessions (interleave with everything else)
    tlsSession(3.02, 'api.github.com', '140.82.112.6', { requests: 9, ttl: 52, rtt: 0.031, gap: [0.6, 3.2] });
    tlsSession(4.48, 'www.google.com', '142.250.80.36', { requests: 5, ttl: 117, rtt: 0.012, gap: [0.3, 1.8] });
    tlsSession(14.2, 'cdn.jsdelivr.net', '151.101.1.229', { requests: 4, ttl: 57, rtt: 0.009, cname: 'jsdelivr.map.fastly.net', gap: [0.1, 0.8] });
    dnsLookup(3.0, 'api.github.com', T.AAAA, []);

    // Ping 8.8.8.8
    const pingData = cat('abcdefghijklmnopqrstuvwabcdefghi');
    for (let i = 1; i <= 4; i++) {
      const tt = 6.0 + (i - 1) * 1.0013, rtt = rf(0.0105, 0.0142);
      at(tt, toNet(ip4(H.ip, '8.8.8.8', 1, icmp4(8, 0, cat(u16(1), u16(i)), pingData), 128, false)));
      at(tt + rtt, fromNet(ip4('8.8.8.8', H.ip, 1, icmp4(0, 0, cat(u16(1), u16(i)), pingData), 117, false)));
    }
    // IPv6 ping to Cloudflare DNS
    at(8.2, eth(GW.mac, H.mac, 0x86dd, icmp6(H.g6, '2606:4700:4700::1111', 128, 0, cat(u16(0x1a2b), u16(1), rb(32)), 64)));
    at(8.2148, eth(H.mac, GW.mac, 0x86dd, icmp6('2606:4700:4700::1111', H.g6, 129, 0, cat(u16(0x1a2b), u16(1), rb(32)), 57)));

    // traceroute-style probes → ICMP time exceeded / port unreachable
    const hops = [['192.168.1.1', 64, 0.0011], ['100.64.0.1', 254, 0.0062], ['8.8.8.8', 117, 0.0119]];
    hops.forEach(([hop, httl, rtt], i) => {
      const tt = 9.1 + i * 0.05, sp = 54321 + i;
      const probe = ip4(H.ip, '8.8.8.8', 17, udpSeg(H.ip, '8.8.8.8', sp, 33434 + i, Array(24).fill(0x40)), i + 1, false);
      at(tt, toNet(probe));
      const quoted = probe.slice(0, 28); quoted[8] = 1;
      const last = i === hops.length - 1;
      at(tt + rtt, fromNet(ip4(hop, H.ip, 1, icmp4(last ? 3 : 11, last ? 3 : 0, u32(0), quoted), httl, false)));
    });

    // Port probes against the router (refused + open)
    for (const [port, open] of [[23, false], [22, true], [8443, false]]) {
      const k = tcpConv(10.6 + port / 10000, GW.ip, port, ri(50000, 64000), { ttl: 64, rtt: 0.0006 });
      k.c(0, SYN, [], [2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2]);
      if (open) { k.s(0.0006, SYN | ACK, [], [2, 4, 0x05, 0xb4]); k.c(0.0002, RST); }
      else k.s(0.0005, RST | ACK);
    }

    // NXDOMAIN + misc lookups
    dnsLookup(11.4, 'printer.lan', T.A, [], 3, 0.0021);
    dnsLookup(13.9, 'fonts.gstatic.com', T.A, [A('142.250.72.99', 251)]);
    dnsLookup(16.8, 'telemetry.nas.lan', T.A, [A(NAS.ip, 600)], 0, 0.0018);

    // HTTP POST to a LAN service on port 8080
    const body = JSON.stringify({ device: 'workstation', cpu: 23.4, mem: 61.2, uptime: 812, ts: '2026-11-24T09:41:24Z' });
    const k = tcpConv(16.82, NAS.ip, 8080, ri(50000, 64000), { ttl: 64, rtt: 0.0009, mac: NAS.mac });
    k.open();
    k.c(0.0002, PSH | ACK, `POST /api/v1/metrics HTTP/1.1\r\nHost: ${NAS.ip}:8080\r\nUser-Agent: metrics-agent/2.3\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nAuthorization: Bearer demo-token-not-real\r\n\r\n${body}`);
    k.s(0.0031, PSH | ACK, 'HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 27\r\nLocation: /api/v1/metrics/8841\r\n\r\n{"id":8841,"status":"ok"}\n\n');
    k.c(0.0002, ACK);
    k.close(0.05);
    // ARP from NAS resolving us
    at(16.79, eth(BC, NAS.mac, 0x0806, arp(1, NAS.mac, NAS.ip, '00:00:00:00:00:00', H.ip)));
    at(16.7903, eth(NAS.mac, H.mac, 0x0806, arp(2, H.mac, H.ip, NAS.mac, NAS.ip)));

    // ---- serialise
    ev.sort((a, b) => a[0] - b[0]);
    const recs = ev.map(([tt, f]) => ({ ts: BASE + tt, len: f.length, d: Uint8Array.from(f) }));
    return PcapParser.write(recs, 1);
  }

  global.SampleCapture = { build };
})(window);
