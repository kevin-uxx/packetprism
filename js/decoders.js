/* PacketPrism — protocol dissectors.
 * Each dissector appends a "layer" ({key,name,sum,o,l,fields}) to the packet context.
 * Fields are {n:name, v:value, o:offset, l:length, c:children, bits:bitmask-string}.
 * Offsets are absolute within the frame so the UI can highlight bytes.
 * Flat filter values are written to P.f for the display-filter engine.
 */
(function (global) {
  'use strict';

  // ---------------------------------------------------------------- tables
  const ETHERTYPES = { 0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x8100: '802.1Q VLAN', 0x88a8: '802.1ad', 0x88cc: 'LLDP', 0x8863: 'PPPoE Discovery', 0x8864: 'PPPoE Session', 0x893a: 'IEEE 1905.1' };
  const IPPROTO = { 0: 'HOPOPT', 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP' };
  const SERVICES = { 20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain', 67: 'bootps', 68: 'bootpc', 80: 'http', 110: 'pop3', 123: 'ntp', 137: 'netbios-ns', 143: 'imap', 161: 'snmp', 443: 'https', 445: 'microsoft-ds', 465: 'smtps', 587: 'submission', 993: 'imaps', 995: 'pop3s', 1900: 'ssdp', 3306: 'mysql', 3389: 'rdp', 5353: 'mdns', 5432: 'postgresql', 6379: 'redis', 8080: 'http-alt', 8443: 'https-alt', 33434: 'traceroute' };
  const ICMP_TYPES = { 0: 'Echo (ping) reply', 3: 'Destination unreachable', 4: 'Source quench', 5: 'Redirect', 8: 'Echo (ping) request', 9: 'Router advertisement', 10: 'Router solicitation', 11: 'Time-to-live exceeded', 12: 'Parameter problem', 13: 'Timestamp', 14: 'Timestamp reply' };
  const UNREACH = { 0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable', 3: 'Port unreachable', 4: 'Fragmentation needed', 9: 'Network administratively prohibited', 10: 'Host administratively prohibited', 13: 'Communication administratively filtered' };
  const ICMP6_TYPES = { 1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded', 4: 'Parameter problem', 128: 'Echo (ping) request', 129: 'Echo (ping) reply', 133: 'Router Solicitation', 134: 'Router Advertisement', 135: 'Neighbor Solicitation', 136: 'Neighbor Advertisement', 137: 'Redirect', 143: 'Multicast Listener Report v2' };
  const ND_OPTS = { 1: 'Source link-layer address', 2: 'Target link-layer address', 3: 'Prefix information', 5: 'MTU', 25: 'Recursive DNS Server' };
  const DNS_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 41: 'OPT', 47: 'NSEC', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY' };
  const DNS_RCODE = { 0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'No such name', 4: 'Not implemented', 5: 'Refused' };
  const DNS_OPCODE = { 0: 'Standard query', 1: 'Inverse query', 2: 'Server status', 4: 'Notify', 5: 'Update' };
  const DHCP_MSG = { 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform' };
  const DHCP_OPT = { 0: 'Pad', 1: 'Subnet Mask', 3: 'Router', 6: 'Domain Name Server', 12: 'Host Name', 15: 'Domain Name', 28: 'Broadcast Address', 50: 'Requested IP Address', 51: 'IP Address Lease Time', 53: 'DHCP Message Type', 54: 'DHCP Server Identifier', 55: 'Parameter Request List', 57: 'Maximum DHCP Message Size', 58: 'Renewal Time Value', 59: 'Rebinding Time Value', 60: 'Vendor class identifier', 61: 'Client identifier', 81: 'Client FQDN', 119: 'Domain Search', 255: 'End' };
  const TLS_CT = { 20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data', 24: 'Heartbeat' };
  const TLS_HS = { 0: 'Hello Request', 1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 8: 'Encrypted Extensions', 11: 'Certificate', 12: 'Server Key Exchange', 13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify', 16: 'Client Key Exchange', 20: 'Finished' };
  const TLS_VER = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
  const CIPHERS = { 0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256', 0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256', 0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA', 0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA' };
  const TLS_EXT = { 0: 'server_name', 5: 'status_request', 10: 'supported_groups', 11: 'ec_point_formats', 13: 'signature_algorithms', 16: 'application_layer_protocol_negotiation', 18: 'signed_certificate_timestamp', 21: 'padding', 23: 'extended_master_secret', 27: 'compress_certificate', 35: 'session_ticket', 41: 'pre_shared_key', 43: 'supported_versions', 45: 'psk_key_exchange_modes', 51: 'key_share', 65037: 'encrypted_client_hello', 65281: 'renegotiation_info' };
  const GROUPS = { 0x001d: 'x25519', 0x0017: 'secp256r1', 0x0018: 'secp384r1', 0x0019: 'secp521r1', 0x0100: 'ffdhe2048', 0x11ec: 'X25519MLKEM768' };
  const TLS_ALERT = { 0: 'Close Notify', 10: 'Unexpected Message', 20: 'Bad Record MAC', 40: 'Handshake Failure', 42: 'Bad Certificate', 48: 'Unknown CA', 70: 'Protocol Version', 80: 'Internal Error', 112: 'Unrecognized Name' };
  const NTP_MODE = { 0: 'reserved', 1: 'symmetric active', 2: 'symmetric passive', 3: 'client', 4: 'server', 5: 'broadcast', 6: 'control', 7: 'private' };

  /** Field registry: used for filter validation + autocomplete. */
  const FIELDS = {
    'frame.number': 'Frame number', 'frame.len': 'Bytes on wire', 'frame.cap_len': 'Bytes captured', 'frame.time_relative': 'Seconds since first packet', 'frame.time_delta': 'Seconds since previous packet',
    'eth.src': 'Source MAC', 'eth.dst': 'Destination MAC', 'eth.addr': 'Either MAC', 'eth.type': 'EtherType', 'vlan.id': 'VLAN ID',
    'arp.opcode': 'ARP opcode (1=request, 2=reply)', 'arp.src.hw_mac': 'Sender MAC', 'arp.src.proto_ipv4': 'Sender IP', 'arp.dst.proto_ipv4': 'Target IP',
    'ip.src': 'IPv4 source', 'ip.dst': 'IPv4 destination', 'ip.addr': 'Either IPv4 address', 'ip.ttl': 'Time to live', 'ip.proto': 'IP protocol number', 'ip.id': 'Identification', 'ip.len': 'Total length', 'ip.flags.df': "Don't fragment bit", 'ip.flags.mf': 'More fragments bit', 'ip.checksum.bad': 'Bad IPv4 header checksum',
    'ipv6.src': 'IPv6 source', 'ipv6.dst': 'IPv6 destination', 'ipv6.addr': 'Either IPv6 address', 'ipv6.nxt': 'Next header', 'ipv6.hlim': 'Hop limit', 'ipv6.flow': 'Flow label',
    'tcp.srcport': 'TCP source port', 'tcp.dstport': 'TCP destination port', 'tcp.port': 'Either TCP port', 'tcp.stream': 'TCP stream index', 'tcp.seq': 'Relative sequence number', 'tcp.ack': 'Relative ack number', 'tcp.len': 'TCP payload length', 'tcp.window_size': 'Window', 'tcp.flags': 'TCP flags (numeric)',
    'tcp.flags.syn': 'SYN flag', 'tcp.flags.ack': 'ACK flag', 'tcp.flags.fin': 'FIN flag', 'tcp.flags.rst': 'RST flag', 'tcp.flags.push': 'PSH flag', 'tcp.flags.urg': 'URG flag', 'tcp.options.mss': 'MSS option value', 'tcp.checksum.bad': 'Bad TCP checksum',
    'udp.srcport': 'UDP source port', 'udp.dstport': 'UDP destination port', 'udp.port': 'Either UDP port', 'udp.stream': 'UDP stream index', 'udp.length': 'UDP length',
    'icmp.type': 'ICMP type', 'icmp.code': 'ICMP code', 'icmp.ident': 'Echo identifier', 'icmp.seq': 'Echo sequence', 'icmpv6.type': 'ICMPv6 type',
    'dns.id': 'Transaction ID', 'dns.flags.response': '1 for responses', 'dns.flags.rcode': 'Reply code', 'dns.qry.name': 'Queried name', 'dns.qry.type': 'Query type (A, AAAA…)', 'dns.a': 'A record address', 'dns.aaaa': 'AAAA record address', 'dns.cname': 'CNAME target', 'dns.ptr': 'PTR target', 'dns.count.answers': 'Answer count',
    'http.request': 'Is an HTTP request', 'http.response': 'Is an HTTP response', 'http.request.method': 'HTTP method', 'http.request.uri': 'Request URI', 'http.host': 'Host header', 'http.user_agent': 'User-Agent', 'http.response.code': 'Status code', 'http.content_type': 'Content-Type', 'http.content_length': 'Content-Length',
    'tls.record.content_type': 'Record content type', 'tls.handshake.type': 'Handshake type (1=ClientHello)', 'tls.sni': 'Server Name Indication', 'tls.alpn': 'ALPN protocol', 'tls.cipher': 'Selected cipher suite',
    'dhcp.type': 'DHCP message type', 'dhcp.hostname': 'Client host name', 'dhcp.yiaddr': "'Your' IP address", 'dhcp.xid': 'Transaction ID',
    'ntp.mode': 'NTP mode', 'ntp.stratum': 'Stratum',
    'port': 'Any TCP/UDP port', 'addr': 'Any IPv4/IPv6 address', 'mac': 'Any MAC address'
  };
  const PROTOCOLS = ['frame', 'eth', 'vlan', 'sll', 'arp', 'ip', 'ipv6', 'icmp', 'icmpv6', 'tcp', 'udp', 'dns', 'mdns', 'http', 'ssdp', 'tls', 'dhcp', 'ntp', 'data', 'malformed'];

  // ---------------------------------------------------------------- byte helpers
  function trunc(o) { return new RangeError(`Packet truncated (needed byte ${o})`); }
  function u8(d, o) { if (o < 0 || o >= d.length) throw trunc(o); return d[o]; }
  function u16(d, o) { if (o + 2 > d.length) throw trunc(o + 1); return (d[o] << 8) | d[o + 1]; }
  function u24(d, o) { if (o + 3 > d.length) throw trunc(o + 2); return (d[o] << 16) | (d[o + 1] << 8) | d[o + 2]; }
  function u32(d, o) { if (o + 4 > d.length) throw trunc(o + 3); return ((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0; }
  const hx = (n, w = 4) => '0x' + (n >>> 0).toString(16).padStart(w, '0');
  function macStr(d, o) {
    if (o + 6 > d.length) throw trunc(o + 5);
    let s = ''; for (let i = 0; i < 6; i++) s += (i ? ':' : '') + d[o + i].toString(16).padStart(2, '0');
    return s;
  }
  function macLabel(m) {
    if (m === 'ff:ff:ff:ff:ff:ff') return 'Broadcast';
    if (m.startsWith('01:00:5e')) return 'IPv4mcast_' + m.slice(9).replace(/:/g, '');
    if (m.startsWith('33:33')) return 'IPv6mcast_' + m.slice(6).replace(/:/g, '');
    return m;
  }
  function ip4Str(d, o) { if (o + 4 > d.length) throw trunc(o + 3); return `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`; }
  function ip6Str(d, o) {
    if (o + 16 > d.length) throw trunc(o + 15);
    const g = [];
    for (let i = 0; i < 8; i++) g.push(((d[o + 2 * i] << 8) | d[o + 2 * i + 1]).toString(16));
    let bs = -1, bl = 0;
    for (let i = 0; i < 8;) {
      if (g[i] === '0') { let j = i; while (j < 8 && g[j] === '0') j++; if (j - i > bl && j - i > 1) { bs = i; bl = j - i; } i = j; } else i++;
    }
    if (bs < 0) return g.join(':');
    return g.slice(0, bs).join(':') + '::' + g.slice(bs + bl).join(':');
  }
  function latin1(d, o, l) {
    if (o + l > d.length) throw trunc(o + l - 1);
    let s = ''; for (let i = 0; i < l; i++) s += String.fromCharCode(d[o + i]);
    return s;
  }
  function hexStr(d, o, l, max = 24) {
    const n = Math.min(l, max, d.length - o); let s = '';
    for (let i = 0; i < n; i++) s += d[o + i].toString(16).padStart(2, '0');
    return s + (l > n ? '…' : '');
  }
  function bitStr(val, mask, width) {
    let s = '';
    for (let i = width - 1; i >= 0; i--) {
      const b = 2 ** i;
      s += (mask & b) ? ((val & b) ? '1' : '0') : '.';
      if (i && i % 4 === 0) s += ' ';
    }
    return s;
  }
  function sum16(d, o, len, s = 0) {
    for (let i = 0; i + 1 < len; i += 2) s += (d[o + i] << 8) | d[o + i + 1];
    if (len & 1) s += d[o + len - 1] << 8;
    return s;
  }
  function fold(s) { while (s > 0xffff) s = (s & 0xffff) + Math.floor(s / 65536); return (~s) & 0xffff; }
  const svc = p => SERVICES[p] ? `${p} (${SERVICES[p]})` : String(p);
  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

  // ---------------------------------------------------------------- builders
  function F(n, v, o, l, c) { const f = { n, v: v == null ? '' : String(v), o: o | 0, l: l | 0 }; if (c && c.length) f.c = c; return f; }
  function B(name, val, mask, width, text, o, l) { const f = F(name, text, o, l); f.bits = bitStr(val, mask, width); return f; }
  function addLayer(P, key, name, o, l) { const L = { key, name, sum: '', o, l, fields: [] }; P.layers.push(L); P.f[key] = 1; return L; }
  function put(P, k, v) { const f = P.f; if (f[k] === undefined) f[k] = v; else if (Array.isArray(f[k])) f[k].push(v); else f[k] = [f[k], v]; }
  const yn = b => b ? 'Set' : 'Not set';

  // ---------------------------------------------------------------- entry
  function createState(t0) { return { t0, prev: null, tcp: new Map(), tcpN: 0, udp: new Map(), udpN: 0 }; }

  function decode(pkt, i, g) {
    const d = pkt.data;
    const P = { d, f: {}, layers: [], s: { src: '', dst: '', proto: 'Frame', info: '' }, g, warn: false };
    const rel = pkt.ts - g.t0, delta = g.prev == null ? 0 : pkt.ts - g.prev;
    g.prev = pkt.ts;
    const fr = addLayer(P, 'frame', `Frame ${i + 1}`, 0, d.length);
    fr.sum = `${pkt.orig} bytes on wire, ${d.length} bytes captured`;
    const dt = new Date(pkt.ts * 1000);
    fr.fields.push(
      F('Arrival Time', dt.toISOString().replace('T', ' ').replace('Z', ' UTC'), 0, 0),
      F('Epoch Time', pkt.ts.toFixed(6) + ' seconds', 0, 0),
      F('Time since first frame', rel.toFixed(6) + ' seconds', 0, 0),
      F('Time delta from previous frame', delta.toFixed(6) + ' seconds', 0, 0),
      F('Frame Number', i + 1, 0, 0),
      F('Frame Length', `${pkt.orig} bytes (${pkt.orig * 8} bits)`, 0, 0),
      F('Capture Length', `${d.length} bytes (${d.length * 8} bits)`, 0, 0)
    );
    if (d.length < pkt.orig) fr.fields.push(F('[Frame is truncated by snaplen]', `${pkt.orig - d.length} bytes missing`, 0, 0));
    Object.assign(P.f, { 'frame.number': i + 1, 'frame.len': pkt.orig, 'frame.cap_len': d.length, 'frame.time_relative': rel, 'frame.time_delta': delta });

    try {
      switch (pkt.linktype) {
        case 1: eth(P, 0); break;
        case 0: { // BSD loopback: 4-byte host-order family
          const fam = d.length >= 4 ? (d[0] || d[3]) : 0;
          const L = addLayer(P, 'null', 'Null/Loopback', 0, 4); L.sum = `Family: ${fam}`;
          L.fields.push(F('Family', fam === 2 ? 'IP (2)' : (fam >= 24 ? `IPv6 (${fam})` : fam), 0, 4));
          rawIp(P, 4); break;
        }
        case 12: case 14: case 101: case 228: case 229: rawIp(P, 0); break;
        case 113: sll(P); break;
        case 276: sll2(P); break;
        default: data(P, 0, d.length, `Unsupported link type ${pkt.linktype}`);
      }
    } catch (e) {
      const L = addLayer(P, 'malformed', 'Malformed Packet', 0, 0);
      L.sum = e.message; L.fields.push(F('Expert Info (Error)', e.message, 0, 0));
      P.s.info = (P.s.info ? P.s.info + ' ' : '') + '[Malformed Packet]';
      P.warn = true;
    }
    fr.fields.push(F('Protocols in frame', P.layers.slice(1).map(l => l.key).join(':'), 0, 0));
    if (!P.s.info) P.s.info = P.layers.length > 1 ? P.layers[P.layers.length - 1].sum : '';

    return {
      no: i + 1, ts: pkt.ts, rel, delta, len: pkt.orig, cap: d.length, d,
      layers: P.layers, f: P.f, src: P.s.src, dst: P.s.dst, sport: P.s.sport, dport: P.s.dport,
      proto: P.s.proto, info: P.s.info, flags: P.s.flags, stream: P.s.stream, skind: P.s.skind,
      payload: P.payload || null, warn: P.warn
    };
  }

  // ---------------------------------------------------------------- link layer
  function eth(P, o) {
    const d = P.d;
    const dst = macStr(d, o), src = macStr(d, o + 6);
    let type = u16(d, o + 12);
    const L = addLayer(P, 'eth', 'Ethernet II', o, 14);
    L.sum = `${macLabel(src)} → ${macLabel(dst)}`;
    const ig = (d[o] & 1), lg = (d[o] & 2) >> 1;
    L.fields.push(
      F('Destination', `${macLabel(dst)}${macLabel(dst) !== dst ? ` (${dst})` : ''}`, o, 6, [
        F('Address', dst, o, 6),
        B('LG bit', d[o], 2, 8, lg ? 'Locally administered address' : 'Globally unique address (factory default)', o, 1),
        B('IG bit', d[o], 1, 8, ig ? 'Group address (multicast/broadcast)' : 'Individual address (unicast)', o, 1)
      ]),
      F('Source', src, o + 6, 6),
      F('Type', `${ETHERTYPES[type] || 'Unknown'} (${hx(type)})`, o + 12, 2)
    );
    put(P, 'eth.src', src); put(P, 'eth.dst', dst); put(P, 'eth.addr', src); put(P, 'eth.addr', dst);
    put(P, 'mac', src); put(P, 'mac', dst); P.f['eth.type'] = type;
    P.s.src = src; P.s.dst = dst; P.s.proto = 'Ethernet';
    let p = o + 14;
    while ((type === 0x8100 || type === 0x88a8) && p + 4 <= d.length) {
      const tci = u16(d, p), inner = u16(d, p + 2);
      const V = addLayer(P, 'vlan', '802.1Q Virtual LAN', p, 4);
      V.sum = `PRI: ${tci >> 13}, ID: ${tci & 0xfff}`;
      V.fields.push(
        B('Priority', tci, 0xe000, 16, tci >> 13, p, 2),
        B('DEI', tci, 0x1000, 16, (tci >> 12) & 1, p, 2),
        B('ID', tci, 0x0fff, 16, tci & 0xfff, p, 2),
        F('Type', `${ETHERTYPES[inner] || 'Unknown'} (${hx(inner)})`, p + 2, 2)
      );
      put(P, 'vlan.id', tci & 0xfff);
      type = inner; p += 4;
    }
    if (type <= 1500) return data(P, p, Math.min(d.length, p + type), 'IEEE 802.3 LLC frame');
    etherType(P, type, p);
  }
  function sll(P) {
    const d = P.d;
    const ptype = u16(d, 0), alen = u16(d, 4), proto = u16(d, 14);
    const L = addLayer(P, 'sll', 'Linux cooked capture v1', 0, 16);
    const PT = { 0: 'Unicast to us', 1: 'Broadcast', 2: 'Multicast', 3: 'Unicast to another host', 4: 'Sent by us' };
    L.sum = PT[ptype] || ptype;
    L.fields.push(F('Packet type', `${PT[ptype] || 'Unknown'} (${ptype})`, 0, 2), F('Link-layer address type', u16(d, 2), 2, 2),
      F('Link-layer address length', alen, 4, 2), F('Source', alen === 6 ? macStr(d, 6) : hexStr(d, 6, Math.min(alen, 8)), 6, 8),
      F('Protocol', `${ETHERTYPES[proto] || 'Unknown'} (${hx(proto)})`, 14, 2));
    etherType(P, proto, 16);
  }
  function sll2(P) {
    const d = P.d, proto = u16(d, 0);
    const L = addLayer(P, 'sll', 'Linux cooked capture v2', 0, 20);
    L.sum = `Interface ${u32(d, 4)}`;
    L.fields.push(F('Protocol', `${ETHERTYPES[proto] || 'Unknown'} (${hx(proto)})`, 0, 2), F('Interface index', u32(d, 4), 4, 4),
      F('Packet type', u8(d, 10), 10, 1), F('Source', u8(d, 11) === 6 ? macStr(d, 12) : hexStr(d, 12, 8), 12, 8));
    etherType(P, proto, 20);
  }
  function rawIp(P, o) {
    const v = u8(P.d, o) >> 4;
    if (v === 4) ipv4(P, o); else if (v === 6) ipv6(P, o); else data(P, o, P.d.length, 'Unknown IP version');
  }
  function etherType(P, type, o) {
    switch (type) {
      case 0x0800: return ipv4(P, o);
      case 0x86dd: return ipv6(P, o);
      case 0x0806: return arp(P, o);
      default: return data(P, o, P.d.length, `${ETHERTYPES[type] || 'Unknown EtherType ' + hx(type)} payload`);
    }
  }

  // ---------------------------------------------------------------- ARP
  function arp(P, o) {
    const d = P.d;
    const htype = u16(d, o), ptype = u16(d, o + 2), hl = u8(d, o + 4), pl = u8(d, o + 5), op = u16(d, o + 6);
    const len = 8 + 2 * hl + 2 * pl;
    const L = addLayer(P, 'arp', 'Address Resolution Protocol', o, len);
    const sha = macStr(d, o + 8), spa = ip4Str(d, o + 14), tha = macStr(d, o + 18), tpa = ip4Str(d, o + 24);
    const gratuitous = spa === tpa;
    const opn = op === 1 ? 'request' : op === 2 ? 'reply' : `opcode ${op}`;
    L.sum = `(${opn}${gratuitous ? ', gratuitous' : ''})`;
    L.fields.push(
      F('Hardware type', htype === 1 ? 'Ethernet (1)' : htype, o, 2), F('Protocol type', `${ETHERTYPES[ptype] || ''} (${hx(ptype)})`, o + 2, 2),
      F('Hardware size', hl, o + 4, 1), F('Protocol size', pl, o + 5, 1), F('Opcode', `${opn} (${op})`, o + 6, 2),
      F('Sender MAC address', sha, o + 8, 6), F('Sender IP address', spa, o + 14, 4),
      F('Target MAC address', tha, o + 18, 6), F('Target IP address', tpa, o + 24, 4)
    );
    Object.assign(P.f, { 'arp.opcode': op, 'arp.src.hw_mac': sha, 'arp.src.proto_ipv4': spa, 'arp.dst.proto_ipv4': tpa });
    P.s.proto = 'ARP';
    if (gratuitous) P.s.info = `Gratuitous ARP for ${spa} (${op === 1 ? 'Request' : 'Reply'})`;
    else if (op === 1) P.s.info = `Who has ${tpa}? Tell ${spa}`;
    else if (op === 2) P.s.info = `${spa} is at ${sha}`;
    else P.s.info = `ARP opcode ${op}`;
  }

  // ---------------------------------------------------------------- IPv4
  function ipv4(P, o) {
    const d = P.d;
    const vihl = u8(d, o), ver = vihl >> 4, ihl = (vihl & 15) * 4;
    if (ihl < 20) throw new RangeError(`Bogus IPv4 header length (${ihl})`);
    const tos = u8(d, o + 1), tlen = u16(d, o + 2), id = u16(d, o + 4), ff = u16(d, o + 6), ttl = u8(d, o + 8), proto = u8(d, o + 9), ck = u16(d, o + 10);
    const src = ip4Str(d, o + 12), dst = ip4Str(d, o + 16);
    u8(d, o + ihl - 1);
    const valid = fold(sum16(d, o, ihl)) === 0;
    const expected = fold(sum16(d, o, ihl) - ck);
    const df = (ff >> 14) & 1, mf = (ff >> 13) & 1, foff = (ff & 0x1fff) * 8;
    const L = addLayer(P, 'ip', 'Internet Protocol Version 4', o, ihl);
    L.sum = `${src} → ${dst}`;
    const dscp = tos >> 2, ecn = tos & 3;
    L.fields.push(
      B('Version', vihl, 0xf0, 8, ver, o, 1),
      B('Header Length', vihl, 0x0f, 8, `${ihl} bytes (${ihl / 4})`, o, 1),
      F('Differentiated Services Field', `${hx(tos, 2)} (DSCP: ${dscpName(dscp)}, ECN: ${['Not-ECT', 'ECT(1)', 'ECT(0)', 'CE'][ecn]})`, o + 1, 1, [
        B('Differentiated Services Codepoint', tos, 0xfc, 8, `${dscpName(dscp)} (${dscp})`, o + 1, 1),
        B('Explicit Congestion Notification', tos, 0x03, 8, ['Not ECN-Capable Transport', 'ECN-Capable Transport ECT(1)', 'ECN-Capable Transport ECT(0)', 'Congestion Experienced'][ecn] + ` (${ecn})`, o + 1, 1)
      ]),
      F('Total Length', tlen, o + 2, 2),
      F('Identification', `${hx(id)} (${id})`, o + 4, 2),
      F('Flags', `${hx(ff >> 13, 1)}${df ? ", Don't fragment" : ''}${mf ? ', More fragments' : ''}`, o + 6, 1, [
        B('Reserved bit', ff >> 8, 0x80, 8, yn(ff & 0x8000), o + 6, 1),
        B("Don't fragment", ff >> 8, 0x40, 8, yn(df), o + 6, 1),
        B('More fragments', ff >> 8, 0x20, 8, yn(mf), o + 6, 1)
      ]),
      B('Fragment Offset', ff, 0x1fff, 16, foff, o + 6, 2),
      F('Time to Live', ttl, o + 8, 1),
      F('Protocol', `${IPPROTO[proto] || 'Unknown'} (${proto})`, o + 9, 1),
      F('Header Checksum', `${hx(ck)} ${valid ? '[correct]' : `[incorrect, should be ${hx(expected)}]`}`, o + 10, 2),
      F('Source Address', src, o + 12, 4),
      F('Destination Address', dst, o + 16, 4)
    );
    if (ihl > 20) L.fields.push(F('Options', `${ihl - 20} bytes`, o + 20, ihl - 20));
    Object.assign(P.f, { 'ip.src': src, 'ip.dst': dst, 'ip.ttl': ttl, 'ip.proto': proto, 'ip.id': id, 'ip.len': tlen, 'ip.flags.df': df, 'ip.flags.mf': mf, 'ip.checksum.bad': valid ? 0 : 1 });
    put(P, 'ip.addr', src); put(P, 'ip.addr', dst); put(P, 'addr', src); put(P, 'addr', dst);
    if (!valid) P.warn = true;
    P.s.src = src; P.s.dst = dst; P.s.proto = 'IPv4'; P.s.info = `${IPPROTO[proto] || 'Proto ' + proto}`;
    const end = Math.min(d.length, o + Math.max(tlen, ihl));
    if (foff > 0) return data(P, o + ihl, end, `Fragmented IP protocol (proto=${IPPROTO[proto] || proto}, off=${foff}, ID=${hx(id)})`);
    transport(P, proto, o + ihl, end, { src, dst, v: 4, pseudoSrc: o + 12, pseudoLen: 4 });
  }
  function dscpName(v) { return ({ 0: 'CS0', 8: 'CS1', 10: 'AF11', 16: 'CS2', 18: 'AF21', 24: 'CS3', 26: 'AF31', 32: 'CS4', 34: 'AF41', 40: 'CS5', 46: 'EF', 48: 'CS6', 56: 'CS7' })[v] || String(v); }

  // ---------------------------------------------------------------- IPv6
  function ipv6(P, o) {
    const d = P.d;
    const w = u32(d, o), plen = u16(d, o + 4), nh = u8(d, o + 6), hl = u8(d, o + 7);
    const src = ip6Str(d, o + 8), dst = ip6Str(d, o + 24);
    const tc = (w >>> 20) & 0xff, flow = w & 0xfffff;
    const L = addLayer(P, 'ipv6', 'Internet Protocol Version 6', o, 40);
    L.sum = `${src} → ${dst}`;
    L.fields.push(
      B('Version', d[o], 0xf0, 8, w >>> 28, o, 1),
      F('Traffic Class', `${hx(tc, 2)} (DSCP: ${dscpName(tc >> 2)}, ECN: ${tc & 3})`, o, 2),
      F('Flow Label', hx(flow, 5), o + 1, 3),
      F('Payload Length', plen, o + 4, 2),
      F('Next Header', `${IPPROTO[nh] || 'Unknown'} (${nh})`, o + 6, 1),
      F('Hop Limit', hl, o + 7, 1),
      F('Source Address', src, o + 8, 16),
      F('Destination Address', dst, o + 24, 16)
    );
    Object.assign(P.f, { 'ipv6.src': src, 'ipv6.dst': dst, 'ipv6.nxt': nh, 'ipv6.hlim': hl, 'ipv6.flow': flow });
    put(P, 'ipv6.addr', src); put(P, 'ipv6.addr', dst); put(P, 'addr', src); put(P, 'addr', dst);
    P.s.src = src; P.s.dst = dst; P.s.proto = 'IPv6'; P.s.info = IPPROTO[nh] || `Next header ${nh}`;
    const end = Math.min(d.length, o + 40 + plen);
    // skip simple extension headers (hop-by-hop, routing, dest opts)
    let p = o + 40, next = nh;
    while ((next === 0 || next === 43 || next === 60) && p + 2 <= end) {
      const elen = (u8(d, p + 1) + 1) * 8;
      L.fields.push(F(next === 0 ? 'Hop-by-Hop Options' : next === 43 ? 'Routing Header' : 'Destination Options', `${elen} bytes`, p, elen));
      next = u8(d, p); p += elen;
    }
    transport(P, next, p, end, { src, dst, v: 6, pseudoSrc: o + 8, pseudoLen: 16 });
  }

  function transport(P, proto, o, end, ip) {
    switch (proto) {
      case 6: return tcp(P, o, end, ip);
      case 17: return udp(P, o, end, ip);
      case 1: return icmp(P, o, end);
      case 58: return icmpv6(P, o, end, ip);
      default: return data(P, o, end, `${IPPROTO[proto] || 'IP protocol ' + proto} payload`);
    }
  }
  function l4Checksum(P, o, len, proto, ip) {
    const d = P.d;
    if (o + len > d.length) return null; // truncated — cannot verify
    let s = sum16(d, ip.pseudoSrc, ip.pseudoLen * 2); // src + dst are contiguous
    s += proto + (len & 0xffff) + Math.floor(len / 65536);
    s = sum16(d, o, len, s);
    return fold(s) === 0;
  }

  // ---------------------------------------------------------------- TCP
  const TCP_FLAGS = [[0x01, 'FIN'], [0x02, 'SYN'], [0x04, 'RST'], [0x08, 'PSH'], [0x10, 'ACK'], [0x20, 'URG'], [0x40, 'ECE'], [0x80, 'CWR']];
  const TCP_FLAG_NAMES = { 0x100: 'Accurate ECN', 0x80: 'Congestion Window Reduced', 0x40: 'ECN-Echo', 0x20: 'Urgent', 0x10: 'Acknowledgment', 0x08: 'Push', 0x04: 'Reset', 0x02: 'Syn', 0x01: 'Fin' };
  function flagStr(fl) { return TCP_FLAGS.filter(([b]) => fl & b).map(([, n]) => n).join(', '); }

  function tcp(P, o, end, ip) {
    const d = P.d;
    const sp = u16(d, o), dp = u16(d, o + 2), seq = u32(d, o + 4), ack = u32(d, o + 8);
    const doff = (u8(d, o + 12) >> 4) * 4;
    const fl = ((d[o + 12] & 1) << 8) | u8(d, o + 13);
    const win = u16(d, o + 14), ck = u16(d, o + 16), urg = u16(d, o + 18);
    if (doff < 20) throw new RangeError(`Bogus TCP header length (${doff})`);
    const plen = Math.max(0, end - o - doff);
    const segLen = end - o;

    // --- stream tracking & relative sequence numbers
    const me = `${ip.src}:${sp}`, peer = `${ip.dst}:${dp}`;
    const key = me < peer ? me + '|' + peer : peer + '|' + me;
    let st = P.g.tcp.get(key);
    if (!st || ((fl & 0x02) && !(fl & 0x10) && st.closed)) { st = { id: P.g.tcpN++, base: {}, closed: false }; P.g.tcp.set(key, st); }
    if (fl & 0x05) st.closed = true;
    if (st.base[me] === undefined) st.base[me] = seq;
    const rseq = (seq - st.base[me]) >>> 0;
    let rack = null;
    if (fl & 0x10) rack = st.base[peer] !== undefined ? (ack - st.base[peer]) >>> 0 : ack;

    const csOk = l4Checksum(P, o, segLen, 6, ip);
    const L = addLayer(P, 'tcp', 'Transmission Control Protocol', o, doff);
    const fs = flagStr(fl);
    L.sum = `Src Port: ${sp}, Dst Port: ${dp}, Seq: ${rseq}${rack != null ? `, Ack: ${rack}` : ''}, Len: ${plen}`;
    const flagKids = [];
    for (const b of [0x100, 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]) flagKids.push(B(TCP_FLAG_NAMES[b], fl, b, 12, yn(fl & b), o + 12, 2));
    L.fields.push(
      F('Source Port', svc(sp), o, 2),
      F('Destination Port', svc(dp), o + 2, 2),
      F('[Stream index]', st.id, 0, 0),
      F('[TCP Segment Len]', plen, 0, 0),
      F('Sequence Number', `${rseq}    (relative sequence number)`, o + 4, 4, [F('Sequence Number (raw)', seq, o + 4, 4)]),
      F('Acknowledgment Number', rack != null ? `${rack}    (relative ack number)` : '0', o + 8, 4, [F('Acknowledgment number (raw)', ack, o + 8, 4)]),
      B('Header Length', d[o + 12], 0xf0, 8, `${doff} bytes (${doff / 4})`, o + 12, 1),
      F('Flags', `${hx(fl, 3)} (${fs || 'none'})`, o + 12, 2, flagKids),
      F('Window', win, o + 14, 2),
      F('Checksum', `${hx(ck)} ${csOk == null ? '[unverified]' : csOk ? '[correct]' : '[incorrect]'}`, o + 16, 2),
      F('Urgent Pointer', urg, o + 18, 2)
    );
    let mss = null, wscale = null;
    if (doff > 20) {
      const opts = [], oe = o + doff;
      let p = o + 20;
      while (p < oe) {
        const kind = u8(d, p);
        if (kind === 0) { opts.push(F('End of Option List (EOL)', '', p, 1)); break; }
        if (kind === 1) { opts.push(F('No-Operation (NOP)', '', p, 1)); p++; continue; }
        const olen = u8(d, p + 1);
        if (olen < 2) break;
        if (kind === 2) { mss = u16(d, p + 2); opts.push(F('Maximum segment size', `${mss} bytes`, p, olen)); }
        else if (kind === 3) { wscale = u8(d, p + 2); opts.push(F('Window scale', `${wscale} (multiply by ${2 ** wscale})`, p, olen)); }
        else if (kind === 4) opts.push(F('SACK permitted', '', p, olen));
        else if (kind === 5) opts.push(F('SACK', `${(olen - 2) / 8} block(s)`, p, olen));
        else if (kind === 8) opts.push(F('Timestamps', `TSval ${u32(d, p + 2)}, TSecr ${u32(d, p + 6)}`, p, olen));
        else opts.push(F(`Option kind ${kind}`, `${olen} bytes`, p, olen));
        p += olen;
      }
      L.fields.push(F('Options', `(${doff - 20} bytes)${opts.filter(x => !x.n.startsWith('No-Op')).map(x => ', ' + x.n).join('')}`, o + 20, doff - 20, opts));
    }

    Object.assign(P.f, {
      'tcp.srcport': sp, 'tcp.dstport': dp, 'tcp.stream': st.id, 'tcp.seq': rseq, 'tcp.ack': rack == null ? 0 : rack, 'tcp.len': plen,
      'tcp.window_size': win, 'tcp.flags': fl, 'tcp.flags.syn': (fl >> 1) & 1, 'tcp.flags.ack': (fl >> 4) & 1, 'tcp.flags.fin': fl & 1,
      'tcp.flags.rst': (fl >> 2) & 1, 'tcp.flags.push': (fl >> 3) & 1, 'tcp.flags.urg': (fl >> 5) & 1, 'tcp.checksum.bad': csOk === false ? 1 : 0
    });
    if (mss != null) P.f['tcp.options.mss'] = mss;
    put(P, 'tcp.port', sp); put(P, 'tcp.port', dp); put(P, 'port', sp); put(P, 'port', dp);
    Object.assign(P.s, { proto: 'TCP', sport: sp, dport: dp, flags: fl, stream: st.id, skind: 'tcp' });
    if (fl & 0x04) P.warn = true;
    let info = `${sp} → ${dp} [${fs}] Seq=${rseq}${rack != null ? ` Ack=${rack}` : ''} Win=${win} Len=${plen}`;
    if (mss != null) info += ` MSS=${mss}`;
    if (wscale != null) info += ` WS=${2 ** wscale}`;
    P.s.info = info;
    if (plen > 0) {
      P.payload = { o: o + doff, l: plen, from: me };
      app(P, o + doff, end, sp, dp, 'tcp');
    }
  }

  // ---------------------------------------------------------------- UDP
  function udp(P, o, end, ip) {
    const d = P.d;
    const sp = u16(d, o), dp = u16(d, o + 2), ulen = u16(d, o + 4), ck = u16(d, o + 6);
    const me = `${ip.src}:${sp}`, peer = `${ip.dst}:${dp}`;
    const key = me < peer ? me + '|' + peer : peer + '|' + me;
    let id = P.g.udp.get(key);
    if (id === undefined) { id = P.g.udpN++; P.g.udp.set(key, id); }
    const uend = Math.min(end, o + Math.max(8, ulen));
    const csOk = ck === 0 ? null : l4Checksum(P, o, ulen, 17, ip);
    const L = addLayer(P, 'udp', 'User Datagram Protocol', o, 8);
    L.sum = `Src Port: ${sp}, Dst Port: ${dp}`;
    L.fields.push(
      F('Source Port', svc(sp), o, 2), F('Destination Port', svc(dp), o + 2, 2), F('Length', ulen, o + 4, 2),
      F('Checksum', `${hx(ck)} ${ck === 0 ? '[zero-value ignored]' : csOk == null ? '[unverified]' : csOk ? '[correct]' : '[incorrect]'}`, o + 6, 2),
      F('[Stream index]', id, 0, 0), F('UDP payload', `${Math.max(0, uend - o - 8)} bytes`, o + 8, Math.max(0, uend - o - 8))
    );
    Object.assign(P.f, { 'udp.srcport': sp, 'udp.dstport': dp, 'udp.length': ulen, 'udp.stream': id });
    put(P, 'udp.port', sp); put(P, 'udp.port', dp); put(P, 'port', sp); put(P, 'port', dp);
    Object.assign(P.s, { proto: 'UDP', sport: sp, dport: dp, stream: id, skind: 'udp', info: `${sp} → ${dp} Len=${Math.max(0, ulen - 8)}` });
    if (uend > o + 8) {
      P.payload = { o: o + 8, l: uend - o - 8, from: me };
      app(P, o + 8, uend, sp, dp, 'udp');
    }
  }

  // ---------------------------------------------------------------- application dispatch
  const HTTP_RE = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|M-SEARCH|NOTIFY) \S+ (HTTP|RTSP)\/\d|^HTTP\/\d(\.\d)? \d{3}/;
  function app(P, o, end, sp, dp, kind) {
    const d = P.d, has = p => sp === p || dp === p;
    if (kind === 'udp') {
      if (has(53)) return dns(P, o, end, 'dns');
      if (has(5353)) return dns(P, o, end, 'mdns');
      if (has(67) || has(68)) return dhcp(P, o, end);
      if (has(123)) return ntp(P, o, end);
      if (has(1900)) return http(P, o, end, 'ssdp');
      return data(P, o, end);
    }
    const head = latin1(d, o, Math.min(24, end - o));
    if (HTTP_RE.test(head)) return http(P, o, end, 'http');
    const ct = d[o], vmaj = d[o + 1];
    if (ct >= 20 && ct <= 24 && vmaj === 3 && end - o >= 5) return tls(P, o, end);
    if (has(53)) return dns(P, o + 2, end, 'dns', o);
    if (has(443) || has(8443)) return tls(P, o, end);
    if (has(80) || has(8080)) { const L = addLayer(P, 'http', 'Hypertext Transfer Protocol', o, end - o); L.sum = 'Continuation'; L.fields.push(F('Continuation data', `${end - o} bytes`, o, end - o)); P.s.proto = 'HTTP'; P.s.info = 'Continuation'; return; }
    return data(P, o, end);
  }

  function data(P, o, end, label) {
    const l = Math.max(0, end - o);
    if (l === 0) return;
    const L = addLayer(P, 'data', 'Data', o, l);
    L.sum = `${l} bytes`;
    L.fields.push(F('Data', hexStr(P.d, o, l, 32), o, l), F('[Length]', l, 0, 0));
    const txt = printable(P.d, o, Math.min(l, 64));
    if (txt) L.fields.push(F('[As text]', txt, o, Math.min(l, 64)));
    if (label) P.s.info = label;
  }
  function printable(d, o, l) {
    let s = '', ok = 0;
    for (let i = 0; i < l; i++) { const c = d[o + i]; if (c >= 32 && c < 127) { s += String.fromCharCode(c); ok++; } else s += '.'; }
    return ok / l > 0.7 ? s : '';
  }

  // ---------------------------------------------------------------- ICMP
  function icmp(P, o, end) {
    const d = P.d;
    const type = u8(d, o), code = u8(d, o + 1), ck = u16(d, o + 2);
    const ok = fold(sum16(d, o, end - o)) === 0;
    const L = addLayer(P, 'icmp', 'Internet Control Message Protocol', o, end - o);
    const tn = ICMP_TYPES[type] || `Type ${type}`;
    L.sum = tn;
    L.fields.push(F('Type', `${type} (${tn})`, o, 1), F('Code', type === 3 ? `${code} (${UNREACH[code] || 'Unknown'})` : code, o + 1, 1),
      F('Checksum', `${hx(ck)} ${ok ? '[correct]' : '[incorrect]'}`, o + 2, 2));
    Object.assign(P.f, { 'icmp.type': type, 'icmp.code': code });
    P.s.proto = 'ICMP';
    if (type === 0 || type === 8) {
      const id = u16(d, o + 4), seq = u16(d, o + 6);
      L.fields.push(F('Identifier (BE)', `${id} (${hx(id)})`, o + 4, 2), F('Sequence Number (BE)', `${seq} (${hx(seq)})`, o + 6, 2));
      if (end > o + 8) L.fields.push(F('Data', `${end - o - 8} bytes`, o + 8, end - o - 8, [F('Data', hexStr(d, o + 8, end - o - 8, 32), o + 8, end - o - 8)]));
      Object.assign(P.f, { 'icmp.ident': id, 'icmp.seq': seq });
      P.s.info = `${tn}  id=${hx(id)}, seq=${seq}, ttl=${P.f['ip.ttl']}`;
    } else if (type === 3 || type === 11 || type === 5) {
      P.warn = true;
      const io = o + 8;
      if (end - io >= 20) {
        const isrc = ip4Str(d, io + 12), idst = ip4Str(d, io + 16), ip = u8(d, io + 9), ihl = (d[io] & 15) * 4;
        const kids = [F('Source Address', isrc, io + 12, 4), F('Destination Address', idst, io + 16, 4), F('Protocol', `${IPPROTO[ip] || ip} (${ip})`, io + 9, 1), F('Time to Live', u8(d, io + 8), io + 8, 1)];
        let ports = '';
        if ((ip === 6 || ip === 17) && end - io >= ihl + 4) { const s = u16(d, io + ihl), t = u16(d, io + ihl + 2); kids.push(F('Source Port', s, io + ihl, 2), F('Destination Port', t, io + ihl + 2, 2)); ports = ` ${s}→${t}`; }
        L.fields.push(F('Original datagram', `${isrc} → ${idst} (${IPPROTO[ip] || ip}${ports})`, io, end - io, kids));
      }
      P.s.info = `${tn}${type === 3 ? ` (${UNREACH[code] || 'code ' + code})` : type === 11 ? ' in transit' : ''}`;
    } else P.s.info = tn;
  }

  function icmpv6(P, o, end, ip) {
    const d = P.d;
    const type = u8(d, o), code = u8(d, o + 1), ck = u16(d, o + 2);
    const ok = l4Checksum(P, o, end - o, 58, ip);
    const tn = ICMP6_TYPES[type] || `Type ${type}`;
    const L = addLayer(P, 'icmpv6', 'Internet Control Message Protocol v6', o, end - o);
    L.sum = tn;
    L.fields.push(F('Type', `${tn} (${type})`, o, 1), F('Code', code, o + 1, 1), F('Checksum', `${hx(ck)} ${ok == null ? '[unverified]' : ok ? '[correct]' : '[incorrect]'}`, o + 2, 2));
    P.f['icmpv6.type'] = type;
    P.s.proto = 'ICMPv6'; P.s.info = tn;
    let optStart = null;
    if (type === 128 || type === 129) {
      const id = u16(d, o + 4), seq = u16(d, o + 6);
      L.fields.push(F('Identifier', hx(id), o + 4, 2), F('Sequence', seq, o + 6, 2), F('Data', `${end - o - 8} bytes`, o + 8, end - o - 8));
      P.s.info = `${tn} id=${hx(id)}, seq=${seq}, hop limit=${P.f['ipv6.hlim']}`;
    } else if (type === 135 || type === 136) {
      const tgt = ip6Str(d, o + 8);
      if (type === 136) { const fl = u8(d, o + 4); L.fields.push(F('Flags', hx(fl, 2), o + 4, 4, [B('Router', fl, 0x80, 8, yn(fl & 0x80), o + 4, 1), B('Solicited', fl, 0x40, 8, yn(fl & 0x40), o + 4, 1), B('Override', fl, 0x20, 8, yn(fl & 0x20), o + 4, 1)])); }
      L.fields.push(F('Target Address', tgt, o + 8, 16));
      P.s.info = type === 135 ? `Neighbor Solicitation for ${tgt}${ip.src === '::' ? ' (DAD)' : ''}` : `Neighbor Advertisement ${tgt}`;
      optStart = o + 24;
    } else if (type === 133) { optStart = o + 8; P.s.info = 'Router Solicitation'; }
    else if (type === 134) {
      const hop = u8(d, o + 4), fl = u8(d, o + 5), life = u16(d, o + 6);
      L.fields.push(F('Cur hop limit', hop, o + 4, 1), F('Flags', hx(fl, 2), o + 5, 1, [B('Managed address configuration', fl, 0x80, 8, yn(fl & 0x80), o + 5, 1), B('Other configuration', fl, 0x40, 8, yn(fl & 0x40), o + 5, 1)]),
        F('Router lifetime (s)', life, o + 6, 2), F('Reachable time (ms)', u32(d, o + 8), o + 8, 4), F('Retrans timer (ms)', u32(d, o + 12), o + 12, 4));
      optStart = o + 16; P.s.info = 'Router Advertisement';
    }
    if (optStart != null) {
      let p = optStart;
      while (p + 2 <= end) {
        const t = u8(d, p), ln = u8(d, p + 1) * 8;
        if (!ln) break;
        let v = `${ln} bytes`;
        if ((t === 1 || t === 2) && ln >= 8) v = macStr(d, p + 2);
        if (t === 3 && ln >= 32) v = `${ip6Str(d, p + 16)}/${u8(d, p + 2)}`;
        if (t === 5 && ln >= 8) v = u32(d, p + 4);
        L.fields.push(F(`ICMPv6 Option (${ND_OPTS[t] || 'type ' + t})`, v, p, ln));
        if (t === 1 && type === 133) P.s.info += ` from ${v}`;
        if (t === 3) P.s.info += ` (prefix ${v})`;
        p += ln;
      }
    }
  }

  // ---------------------------------------------------------------- DNS / mDNS
  function dnsName(d, o, base) {
    const labels = [];
    let p = o, jumped = false, len = 0, hops = 0;
    for (;;) {
      const l = u8(d, p);
      if (l === 0) { if (!jumped) len = p + 1 - o; break; }
      if ((l & 0xc0) === 0xc0) {
        const ptr = ((l & 0x3f) << 8) | u8(d, p + 1);
        if (!jumped) len = p + 2 - o;
        jumped = true; p = base + ptr;
        if (++hops > 32) throw new RangeError('DNS compression pointer loop');
        continue;
      }
      labels.push(latin1(d, p + 1, l));
      p += l + 1;
      if (labels.length > 128) throw new RangeError('DNS name too long');
    }
    return { name: labels.join('.') || '<Root>', len };
  }
  function dns(P, o, end, key, lenPrefixAt) {
    const d = P.d, base = o;
    const id = u16(d, o), fl = u16(d, o + 2), qd = u16(d, o + 4), an = u16(d, o + 6), ns = u16(d, o + 8), ar = u16(d, o + 10);
    const qr = fl >> 15, opcode = (fl >> 11) & 15, rcode = fl & 15;
    const L = addLayer(P, key, key === 'mdns' ? 'Multicast Domain Name System' : 'Domain Name System', lenPrefixAt != null ? lenPrefixAt : o, end - (lenPrefixAt != null ? lenPrefixAt : o));
    L.sum = `(${qr ? 'response' : 'query'})`;
    if (lenPrefixAt != null) L.fields.push(F('Length', u16(d, lenPrefixAt), lenPrefixAt, 2));
    const fkids = [B('Response', fl, 0x8000, 16, qr ? 'Message is a response' : 'Message is a query', o + 2, 2), B('Opcode', fl, 0x7800, 16, `${DNS_OPCODE[opcode] || opcode} (${opcode})`, o + 2, 2)];
    if (qr) fkids.push(B('Authoritative', fl, 0x0400, 16, yn(fl & 0x400), o + 2, 2));
    fkids.push(B('Truncated', fl, 0x0200, 16, yn(fl & 0x200), o + 2, 2), B('Recursion desired', fl, 0x0100, 16, yn(fl & 0x100), o + 2, 2));
    if (qr) fkids.push(B('Recursion available', fl, 0x0080, 16, yn(fl & 0x80), o + 2, 2), B('Reply code', fl, 0x000f, 16, `${DNS_RCODE[rcode] || rcode} (${rcode})`, o + 2, 2));
    L.fields.push(F('Transaction ID', hx(id), o, 2), F('Flags', `${hx(fl)} ${DNS_OPCODE[opcode] || 'Opcode ' + opcode}${qr ? ' response, ' + (DNS_RCODE[rcode] || rcode) : ''}`, o + 2, 2, fkids),
      F('Questions', qd, o + 4, 2), F('Answer RRs', an, o + 6, 2), F('Authority RRs', ns, o + 8, 2), F('Additional RRs', ar, o + 10, 2));
    Object.assign(P.f, { 'dns.id': id, 'dns.flags.response': qr, 'dns.flags.rcode': rcode, 'dns.count.answers': an });
    P.s.proto = key === 'mdns' ? 'MDNS' : 'DNS';
    let p = o + 12;
    const qs = [], qsum = [];
    for (let i = 0; i < qd; i++) {
      const n = dnsName(d, p, base), t = u16(d, p + n.len), c = u16(d, p + n.len + 2);
      const tn = DNS_TYPES[t] || `TYPE${t}`;
      qs.push(F(`${n.name}`, `type ${tn}, class ${(c & 0x7fff) === 1 ? 'IN' : c & 0x7fff}`, p, n.len + 4, [F('Name', n.name, p, n.len), F('Type', `${tn} (${t})`, p + n.len, 2), F('Class', `${(c & 0x7fff) === 1 ? 'IN' : ''} (${hx(c)})`, p + n.len + 2, 2)]));
      put(P, 'dns.qry.name', n.name); put(P, 'dns.qry.type', tn);
      qsum.push(`${tn} ${n.name}`);
      p += n.len + 4;
    }
    if (qs.length) L.fields.push(F('Queries', '', o + 12, p - o - 12, qs));
    const asum = [];
    const section = (count, title) => {
      if (!count) return;
      const start = p, rrs = [];
      for (let i = 0; i < count && p < end; i++) {
        const rr = dnsRR(P, p, base);
        rrs.push(rr.field);
        if (title === 'Answers') asum.push(rr.short);
        p = rr.end;
      }
      L.fields.push(F(title, '', start, p - start, rrs));
    };
    section(an, 'Answers'); section(ns, 'Authoritative nameservers'); section(ar, 'Additional records');
    const op = DNS_OPCODE[opcode] || 'Query';
    if (!qr) P.s.info = `${op} ${hx(id)} ${qsum.join(', ')}`;
    else {
      P.s.info = `${op} response ${hx(id)}${rcode ? ' ' + (DNS_RCODE[rcode] || 'rcode ' + rcode) : ''} ${qsum.join(', ')} ${asum.join(' ')}`.trim();
      if (rcode) P.warn = true;
    }
  }
  function dnsRR(P, p, base) {
    const d = P.d;
    const n = dnsName(d, p, base);
    const q = p + n.len;
    const t = u16(d, q), c = u16(d, q + 2), ttl = u32(d, q + 4), rl = u16(d, q + 8), r = q + 10;
    if (r + rl > d.length) throw trunc(r + rl);
    const tn = DNS_TYPES[t] || `TYPE${t}`;
    let val = hexStr(d, r, rl), short = tn;
    if (t === 1 && rl === 4) { val = ip4Str(d, r); put(P, 'dns.a', val); }
    else if (t === 28 && rl === 16) { val = ip6Str(d, r); put(P, 'dns.aaaa', val); }
    else if (t === 5 || t === 2 || t === 12) { val = dnsName(d, r, base).name; put(P, t === 5 ? 'dns.cname' : t === 12 ? 'dns.ptr' : 'dns.ns', val); }
    else if (t === 15) val = `${u16(d, r)} ${dnsName(d, r + 2, base).name}`;
    else if (t === 16) { const parts = []; let x = r; while (x < r + rl) { const l = d[x]; parts.push(latin1(d, x + 1, l)); x += l + 1; } val = parts.map(s => `"${s}"`).join(' '); }
    else if (t === 33) val = `${dnsName(d, r + 6, base).name}:${u16(d, r + 4)} (prio ${u16(d, r)}, weight ${u16(d, r + 2)})`;
    else if (t === 6) val = `${dnsName(d, r, base).name} …`;
    else if (t === 41) val = `UDP payload size ${c}`;
    short = `${tn} ${val}`;
    const cls = t === 41 ? `${c}` : (c & 0x7fff) === 1 ? 'IN' : String(c & 0x7fff);
    const field = F(`${n.name}`, `type ${tn}, class ${cls}, ${t === 41 ? '' : `ttl ${ttl}, `}${val}`, p, r + rl - p, [
      F('Name', n.name, p, n.len), F('Type', `${tn} (${t})`, q, 2), F('Class', `${cls} (${hx(c)})${c & 0x8000 && t !== 41 ? ', cache flush' : ''}`, q + 2, 2),
      F('Time to live', t === 41 ? '-' : `${ttl} (${fmtTtl(ttl)})`, q + 4, 4), F('Data length', rl, q + 8, 2), F(tn === 'A' ? 'Address' : tn === 'AAAA' ? 'AAAA Address' : 'Data', val, r, rl)
    ]);
    return { field, short, end: r + rl };
  }
  function fmtTtl(s) { if (s < 60) return `${s} seconds`; if (s < 3600) return `${Math.floor(s / 60)} minutes, ${s % 60} seconds`; if (s < 86400) return `${Math.floor(s / 3600)} hours, ${Math.floor(s % 3600 / 60)} minutes`; return `${Math.floor(s / 86400)} days`; }

  // ---------------------------------------------------------------- DHCP
  function dhcp(P, o, end) {
    const d = P.d;
    const op = u8(d, o), xid = u32(d, o + 4), secs = u16(d, o + 8), flags = u16(d, o + 10);
    const ci = ip4Str(d, o + 12), yi = ip4Str(d, o + 16), si = ip4Str(d, o + 20), gi = ip4Str(d, o + 24), ch = macStr(d, o + 28);
    const L = addLayer(P, 'dhcp', 'Dynamic Host Configuration Protocol', o, end - o);
    L.fields.push(
      F('Message type', op === 1 ? 'Boot Request (1)' : 'Boot Reply (2)', o, 1), F('Hardware type', u8(d, o + 1) === 1 ? 'Ethernet (0x01)' : u8(d, o + 1), o + 1, 1),
      F('Hardware address length', u8(d, o + 2), o + 2, 1), F('Hops', u8(d, o + 3), o + 3, 1), F('Transaction ID', hx(xid, 8), o + 4, 4),
      F('Seconds elapsed', secs, o + 8, 2), F('Bootp flags', `${hx(flags)} (${flags & 0x8000 ? 'Broadcast' : 'Unicast'})`, o + 10, 2, [B('Broadcast flag', flags, 0x8000, 16, flags & 0x8000 ? 'Broadcast' : 'Unicast', o + 10, 2)]),
      F('Client IP address', ci, o + 12, 4), F('Your (client) IP address', yi, o + 16, 4), F('Next server IP address', si, o + 20, 4),
      F('Relay agent IP address', gi, o + 24, 4), F('Client MAC address', ch, o + 28, 6), F('Server host name', 'not given', o + 44, 64), F('Boot file name', 'not given', o + 108, 128)
    );
    Object.assign(P.f, { 'dhcp.xid': xid, 'dhcp.yiaddr': yi });
    P.s.proto = 'DHCP';
    let mtype = null, p = o + 236;
    if (u32(d, p) === 0x63825363) {
      L.fields.push(F('Magic cookie', 'DHCP', p, 4)); p += 4;
      while (p < end) {
        const t = u8(d, p);
        if (t === 0) { p++; continue; }
        if (t === 255) { L.fields.push(F('Option: (255) End', '', p, 1)); break; }
        const l = u8(d, p + 1), v = p + 2;
        u8(d, v + l - 1);
        let val = hexStr(d, v, l);
        if (t === 53) { mtype = d[v]; val = `DHCP: ${DHCP_MSG[mtype] || mtype} (${mtype})`; }
        else if ([1, 3, 28, 50, 54].includes(t) && l >= 4) val = ip4Str(d, v);
        else if (t === 6) { const a = []; for (let k = 0; k + 4 <= l; k += 4) a.push(ip4Str(d, v + k)); val = a.join(', '); }
        else if ([51, 58, 59].includes(t)) { const s = u32(d, v); val = `${s}s (${fmtTtl(s)})`; }
        else if (t === 12 || t === 15 || t === 60) { val = latin1(d, v, l); if (t === 12) P.f['dhcp.hostname'] = val; }
        else if (t === 55) val = Array.from(d.subarray(v, v + l)).map(x => DHCP_OPT[x] || x).join(', ');
        else if (t === 61 && l === 7) val = `Ethernet ${macStr(d, v + 1)}`;
        L.fields.push(F(`Option: (${t}) ${DHCP_OPT[t] || 'Unknown'}`, val, p, l + 2));
        p = v + l;
      }
    }
    const tn = DHCP_MSG[mtype] || 'BOOTP';
    if (mtype) P.f['dhcp.type'] = mtype;
    L.sum = `${tn} — Transaction ID ${hx(xid, 8)}`;
    P.s.info = `DHCP ${tn}${tn.length < 6 ? ' ' : ''} - Transaction ID ${hx(xid, 8)}${yi !== '0.0.0.0' ? ` (offer ${yi})` : ''}`;
  }

  // ---------------------------------------------------------------- NTP
  function ntpTs(d, o) {
    const s = u32(d, o), f = u32(d, o + 4);
    if (!s && !f) return '(not set)';
    const ms = (s - 2208988800) * 1000 + f / 4294967.296;
    return new Date(ms).toISOString().replace('T', ' ').replace('Z', ' UTC');
  }
  function ntp(P, o, end) {
    const d = P.d;
    const b = u8(d, o), li = b >> 6, vn = (b >> 3) & 7, mode = b & 7, stratum = u8(d, o + 1), poll = u8(d, o + 2), prec = (u8(d, o + 3) << 24) >> 24;
    const L = addLayer(P, 'ntp', 'Network Time Protocol', o, end - o);
    const mn = NTP_MODE[mode];
    L.sum = `NTP Version ${vn}, ${mn}`;
    const refid = stratum === 1 ? latin1(d, o + 12, 4).replace(/\0/g, '') : ip4Str(d, o + 12);
    L.fields.push(
      F('Flags', `${hx(b, 2)}, Leap Indicator: ${li === 3 ? 'unsynchronized' : 'no warning'}, Version: ${vn}, Mode: ${mn}`, o, 1, [B('Leap Indicator', b, 0xc0, 8, li, o, 1), B('Version number', b, 0x38, 8, `NTP Version ${vn}`, o, 1), B('Mode', b, 0x07, 8, `${mn} (${mode})`, o, 1)]),
      F('Peer Clock Stratum', `${stratum}${stratum === 0 ? ' (unspecified)' : stratum === 1 ? ' (primary reference)' : ' (secondary reference)'}`, o + 1, 1),
      F('Peer Polling Interval', `${poll} (${2 ** poll} seconds)`, o + 2, 1), F('Peer Clock Precision', `${(2 ** prec).toExponential(3)} seconds`, o + 3, 1),
      F('Root Delay', `${(u32(d, o + 4) / 65536).toFixed(6)} seconds`, o + 4, 4), F('Root Dispersion', `${(u32(d, o + 8) / 65536).toFixed(6)} seconds`, o + 8, 4),
      F('Reference ID', refid || '(none)', o + 12, 4), F('Reference Timestamp', ntpTs(d, o + 16), o + 16, 8), F('Origin Timestamp', ntpTs(d, o + 24), o + 24, 8),
      F('Receive Timestamp', ntpTs(d, o + 32), o + 32, 8), F('Transmit Timestamp', ntpTs(d, o + 40), o + 40, 8)
    );
    Object.assign(P.f, { 'ntp.mode': mode, 'ntp.stratum': stratum });
    P.s.proto = 'NTP'; P.s.info = `NTP Version ${vn}, ${mn}`;
  }

  // ---------------------------------------------------------------- HTTP / SSDP (text)
  function http(P, o, end, key) {
    const d = P.d;
    const text = latin1(d, o, end - o);
    const hEnd = text.indexOf('\r\n\r\n');
    const headLen = hEnd >= 0 ? hEnd + 4 : text.length;
    const L = addLayer(P, key, key === 'ssdp' ? 'Simple Service Discovery Protocol' : 'Hypertext Transfer Protocol', o, end - o);
    P.s.proto = key === 'ssdp' ? 'SSDP' : 'HTTP';
    let p = 0, first = true, ctype = '', clen = null;
    const lines = text.slice(0, headLen).split('\r\n');
    for (const line of lines) {
      if (!line) { p += 2; continue; }
      if (first) {
        first = false;
        const m = line.match(/^(\S+) (\S+) (\S+)$/), r = line.match(/^(HTTP\/\d(?:\.\d)?) (\d{3}) ?(.*)$/);
        const kids = [];
        if (r) {
          kids.push(F('Response Version', r[1], o, r[1].length), F('Status Code', `${r[2]}`, o + r[1].length + 1, 3), F('Response Phrase', r[3], o + r[1].length + 5, r[3].length));
          P.f['http.response'] = 1; P.f['http.response.code'] = +r[2];
          if (+r[2] >= 400) P.warn = true;
        } else if (m) {
          kids.push(F('Request Method', m[1], o, m[1].length), F('Request URI', m[2], o + m[1].length + 1, m[2].length), F('Request Version', m[3], o + m[1].length + m[2].length + 2, m[3].length));
          P.f['http.request'] = 1; P.f['http.request.method'] = m[1]; P.f['http.request.uri'] = m[2];
        }
        L.fields.push(F(line, '', o + p, line.length + 2, kids));
        P.s.info = line;
        L.sum = line;
      } else {
        const ci = line.indexOf(':');
        const name = ci > 0 ? line.slice(0, ci) : line, val = ci > 0 ? line.slice(ci + 1).trim() : '';
        L.fields.push(F(name, val, o + p, line.length + 2));
        const ln = name.toLowerCase();
        if (ln === 'host') P.f['http.host'] = val;
        else if (ln === 'user-agent') P.f['http.user_agent'] = val;
        else if (ln === 'content-type') { P.f['http.content_type'] = val; ctype = val; }
        else if (ln === 'content-length') { clen = +val; P.f['http.content_length'] = clen; }
      }
      p += line.length + 2;
    }
    const bodyLen = end - o - headLen;
    if (hEnd >= 0 && bodyLen > 0) {
      const body = text.slice(headLen);
      const kids = [];
      if (/json|text|html|xml|javascript/i.test(ctype) || printable(d, o + headLen, Math.min(bodyLen, 200)))
        kids.push(F('Preview', body.slice(0, 160).replace(/\s+/g, ' ') + (body.length > 160 ? '…' : ''), o + headLen, Math.min(bodyLen, 160)));
      L.fields.push(F('File Data', `${bodyLen} bytes${ctype ? ` (${ctype.split(';')[0]})` : ''}`, o + headLen, bodyLen, kids));
      if (clen != null && bodyLen < clen) L.fields.push(F('[Body continues]', `${clen - bodyLen} more bytes expected`, 0, 0));
    }
    if (P.f['http.response.code'] && ctype) P.s.info += `  (${ctype.split(';')[0]})`;
  }

  // ---------------------------------------------------------------- TLS
  function tls(P, o, end) {
    const d = P.d;
    const L = addLayer(P, 'tls', 'Transport Layer Security', o, end - o);
    P.s.proto = 'TLS';
    const infos = [];
    let p = o;
    while (p + 5 <= end) {
      const ct = u8(d, p), ver = u16(d, p + 1), len = u16(d, p + 3);
      if (!TLS_CT[ct] || (ver >> 8) !== 3) {
        L.fields.push(F('Continuation Data', `${end - p} bytes`, p, end - p));
        if (!infos.length) infos.push('Continuation Data');
        break;
      }
      const avail = Math.min(len, end - p - 5), b = p + 5;
      const rec = F(`${TLS_VER[ver] || hx(ver)} Record Layer`, `${TLS_CT[ct]} Protocol${ct === 22 ? '' : ''}`, p, 5 + avail, []);
      rec.c = [F('Content Type', `${TLS_CT[ct]} (${ct})`, p, 1), F('Version', `${TLS_VER[ver] || ''} (${hx(ver)})`, p + 1, 2), F('Length', len, p + 3, 2)];
      put(P, 'tls.record.content_type', ct);
      if (ct === 22) {
        let h = b;
        while (h + 4 <= b + avail) {
          const ht = u8(d, h), hl = u24(d, h + 1);
          if (!TLS_HS[ht] || hl > len - 4 || (ht === 20 && infos.includes('Change Cipher Spec'))) {
            rec.c.push(F('Handshake Protocol', 'Encrypted Handshake Message', h, b + avail - h)); infos.push('Encrypted Handshake Message'); break;
          }
          const hs = F('Handshake Protocol', TLS_HS[ht], h, Math.min(4 + hl, b + avail - h), [F('Handshake Type', `${TLS_HS[ht]} (${ht})`, h, 1), F('Length', hl, h + 1, 3)]);
          put(P, 'tls.handshake.type', ht);
          let label = TLS_HS[ht];
          try {
            if (ht === 1 || ht === 2) label = hello(P, h + 4, Math.min(h + 4 + hl, end), ht, hs.c);
          } catch (e) { hs.c.push(F('[Malformed or segmented hello]', e.message, 0, 0)); }
          rec.c.push(hs);
          infos.push(label);
          h += 4 + hl;
        }
      } else if (ct === 23) { rec.c.push(F('Encrypted Application Data', hexStr(d, b, avail, 20), b, avail)); infos.push('Application Data'); }
      else if (ct === 20) { rec.c.push(F('Change Cipher Spec Message', '', b, avail)); infos.push('Change Cipher Spec'); }
      else if (ct === 21) {
        if (len === 2 && avail === 2) { const lv = d[b], ds = d[b + 1]; rec.c.push(F('Alert Message', `Level: ${lv === 2 ? 'Fatal' : 'Warning'} (${lv}), Description: ${TLS_ALERT[ds] || ds}`, b, 2)); infos.push(`Alert (Level: ${lv === 2 ? 'Fatal' : 'Warning'}, Description: ${TLS_ALERT[ds] || ds})`); }
        else { rec.c.push(F('Alert Message', 'Encrypted Alert', b, avail)); infos.push('Encrypted Alert'); }
      } else { rec.c.push(F('Data', `${avail} bytes`, b, avail)); infos.push(TLS_CT[ct]); }
      if (len > avail) rec.c.push(F('[Record continues in next segment]', `${len - avail} bytes missing`, 0, 0));
      L.fields.push(rec);
      p = b + len;
    }
    const uniq = infos.filter((x, i) => infos.indexOf(x) === i);
    P.s.info = uniq.join(', ');
    L.sum = P.s.info;
    if (infos.some(x => x.startsWith('Alert (Level: Fatal'))) P.warn = true;
  }
  function hello(P, o, end, ht, out) {
    const d = P.d;
    const ver = u16(d, o);
    out.push(F('Version', `${TLS_VER[ver] || ''} (${hx(ver)})`, o, 2), F('Random', hexStr(d, o + 2, 32, 32), o + 2, 32));
    let p = o + 34;
    const sl = u8(d, p);
    out.push(F('Session ID Length', sl, p, 1));
    if (sl) out.push(F('Session ID', hexStr(d, p + 1, sl, 32), p + 1, sl));
    p += 1 + sl;
    let label = TLS_HS[ht], realVer = ver;
    if (ht === 1) {
      const cl = u16(d, p), cs = [];
      for (let i = 0; i < cl; i += 2) { const c = u16(d, p + 2 + i); cs.push(F('Cipher Suite', `${CIPHERS[c] || (((c & 0x0f0f) === 0x0a0a) ? 'Reserved (GREASE)' : 'Unknown')} (${hx(c)})`, p + 2 + i, 2)); }
      out.push(F('Cipher Suites', `${cl / 2} suites`, p, 2 + cl, cs));
      p += 2 + cl;
      const ml = u8(d, p); out.push(F('Compression Methods', `${ml} method(s)`, p, 1 + ml)); p += 1 + ml;
    } else {
      const c = u16(d, p);
      out.push(F('Cipher Suite', `${CIPHERS[c] || 'Unknown'} (${hx(c)})`, p, 2), F('Compression Method', u8(d, p + 2), p + 2, 1));
      P.f['tls.cipher'] = CIPHERS[c] || hx(c);
      p += 3;
    }
    if (p + 2 <= end) {
      const el = u16(d, p), ee = Math.min(end, p + 2 + el), exts = [];
      let q = p + 2;
      while (q + 4 <= ee) {
        const t = u16(d, q), l = u16(d, q + 2), v = q + 4;
        const name = TLS_EXT[t] || (((t & 0x0f0f) === 0x0a0a) ? 'Reserved (GREASE)' : 'Unknown');
        const kids = [F('Type', `${name} (${t})`, q, 2), F('Length', l, q + 2, 2)];
        let summary = `len=${l}`;
        if (t === 0 && l >= 5) {
          const nl = u16(d, v + 3), sni = latin1(d, v + 5, nl);
          kids.push(F('Server Name', sni, v + 5, nl));
          P.f['tls.sni'] = sni; summary = sni; label = `Client Hello (SNI=${sni})`;
        } else if (t === 16 && l >= 2) {
          const a = []; let x = v + 2; while (x < v + l) { const n = d[x]; a.push(latin1(d, x + 1, n)); x += n + 1; }
          a.forEach(s => put(P, 'tls.alpn', s)); summary = a.join(', '); kids.push(F('ALPN Protocols', summary, v, l));
        } else if (t === 43) {
          if (ht === 1) { const a = []; for (let x = v + 1; x + 2 <= v + l; x += 2) a.push(TLS_VER[u16(d, x)] || hx(u16(d, x))); summary = a.join(', '); }
          else { realVer = u16(d, v); summary = TLS_VER[realVer] || hx(realVer); }
          kids.push(F('Supported Versions', summary, v, l));
        } else if (t === 10 && l >= 2) {
          const a = []; for (let x = v + 2; x + 2 <= v + l; x += 2) a.push(GROUPS[u16(d, x)] || hx(u16(d, x))); summary = a.join(', '); kids.push(F('Supported Groups', summary, v, l));
        } else if (t === 51 && l >= 2) {
          const g = ht === 1 ? u16(d, v + 2) : u16(d, v); summary = `Key share: ${GROUPS[g] || hx(g)}`; kids.push(F('Key Share', summary, v, l));
        }
        exts.push(F(`Extension: ${name}`, summary, q, 4 + l, kids));
        q = v + l;
      }
      out.push(F('Extensions', `${exts.length} extensions, ${el} bytes`, p, 2 + el, exts));
    }
    if (ht === 2) label = `Server Hello${realVer === 0x0304 ? ' (TLS 1.3)' : ''}`;
    return label;
  }

  global.Decoder = { decode, createState, FIELDS, PROTOCOLS, SERVICES, flagStr, TCP_FLAGS };
})(window);
