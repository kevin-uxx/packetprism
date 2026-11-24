/* PacketPrism — libpcap / pcapng reader (pure JS, no dependencies) */
(function (global) {
  'use strict';

  const LINKTYPES = {
    0: 'BSD loopback', 1: 'Ethernet', 12: 'Raw IP', 14: 'Raw IP', 101: 'Raw IP',
    105: 'IEEE 802.11', 113: 'Linux cooked (SLL)', 127: '802.11 + radiotap',
    228: 'Raw IPv4', 229: 'Raw IPv6', 276: 'Linux cooked v2 (SLL2)'
  };

  function parse(buffer) {
    if (!(buffer instanceof ArrayBuffer)) throw new Error('Expected an ArrayBuffer.');
    if (buffer.byteLength < 24) throw new Error('File is too small to be a capture file.');
    const dv = new DataView(buffer);
    const magic = dv.getUint32(0, false);
    if (magic === 0x0a0d0d0a) return parsePcapng(buffer, dv);

    let le, nano;
    switch (magic) {
      case 0xa1b2c3d4: le = false; nano = false; break;
      case 0xd4c3b2a1: le = true; nano = false; break;
      case 0xa1b23c4d: le = false; nano = true; break;
      case 0x4d3cb2a1: le = true; nano = true; break;
      default: throw new Error('Unrecognised file format — expected a libpcap (.pcap) or pcapng file.');
    }
    const vmaj = dv.getUint16(4, le), vmin = dv.getUint16(6, le);
    const snaplen = dv.getUint32(16, le);
    const linktype = dv.getUint32(20, le) & 0xffff;
    const div = nano ? 1e9 : 1e6;
    const packets = [];
    const len = buffer.byteLength;
    let off = 24, truncated = false;
    while (off + 16 <= len) {
      const sec = dv.getUint32(off, le), sub = dv.getUint32(off + 4, le);
      const incl = dv.getUint32(off + 8, le), orig = dv.getUint32(off + 12, le);
      off += 16;
      if (incl > len - off || incl > 0x4000000) { truncated = true; break; }
      packets.push({ ts: sec + sub / div, orig, linktype, data: new Uint8Array(buffer, off, incl) });
      off += incl;
    }
    if (off < len && !truncated) truncated = true;
    return {
      format: nano ? 'pcap (nanosecond)' : 'pcap', version: `${vmaj}.${vmin}`,
      snaplen, linktype, linkName: LINKTYPES[linktype] || `Link type ${linktype}`, packets, truncated
    };
  }

  function parsePcapng(buffer, dv) {
    const len = buffer.byteLength;
    const ifaces = [], packets = [];
    let off = 0, le = true, truncated = false, snaplen = 0;
    while (off + 12 <= len) {
      let type = dv.getUint32(off, le);
      if (dv.getUint32(off, false) === 0x0a0d0d0a) {
        const bom = dv.getUint32(off + 8, true);
        if (bom === 0x1a2b3c4d) le = true;
        else if (bom === 0x4d3c2b1a) le = false;
        else throw new Error('Corrupt pcapng section header.');
        type = 0x0a0d0d0a;
        ifaces.length = 0;
      }
      const blen = dv.getUint32(off + 4, le);
      if (blen < 12 || off + blen > len) { truncated = true; break; }
      const body = off + 8, end = off + blen - 4;

      if (type === 1) { // Interface Description Block
        const lt = dv.getUint16(body, le);
        snaplen = dv.getUint32(body + 4, le);
        let res = 1e-6, p = body + 8;
        while (p + 4 <= end) {
          const code = dv.getUint16(p, le), olen = dv.getUint16(p + 2, le);
          if (code === 0) break;
          if (code === 9 && olen >= 1) {
            const v = dv.getUint8(p + 4);
            res = (v & 0x80) ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v);
          }
          p += 4 + ((olen + 3) & ~3);
        }
        ifaces.push({ linktype: lt, res });
      } else if (type === 6 || type === 2) { // Enhanced / obsolete Packet Block
        const id = type === 6 ? dv.getUint32(body, le) : dv.getUint16(body, le);
        const hi = dv.getUint32(body + 4, le), lo = dv.getUint32(body + 8, le);
        const cl = dv.getUint32(body + 12, le), ol = dv.getUint32(body + 16, le);
        const iface = ifaces[id] || { linktype: 1, res: 1e-6 };
        const dl = Math.max(0, Math.min(cl, blen - 32));
        packets.push({ ts: (hi * 4294967296 + lo) * iface.res, orig: ol, linktype: iface.linktype, data: new Uint8Array(buffer, body + 20, dl) });
      } else if (type === 3) { // Simple Packet Block (no timestamp)
        const ol = dv.getUint32(body, le);
        const iface = ifaces[0] || { linktype: 1 };
        const dl = Math.max(0, Math.min(ol, blen - 16));
        const ts = packets.length ? packets[packets.length - 1].ts : 0;
        packets.push({ ts, orig: ol, linktype: iface.linktype, data: new Uint8Array(buffer, body + 4, dl) });
      }
      off += blen;
    }
    const lt = ifaces[0] ? ifaces[0].linktype : (packets[0] ? packets[0].linktype : 1);
    return { format: 'pcapng', version: '1.0', snaplen, linktype: lt, linkName: LINKTYPES[lt] || `Link type ${lt}`, packets, truncated };
  }

  /** Serialise records ({ts, len, d}) back to a classic little-endian pcap. */
  function write(records, linktype) {
    let total = 24;
    for (const r of records) total += 16 + r.d.length;
    const buf = new ArrayBuffer(total), dv = new DataView(buf), u8 = new Uint8Array(buf);
    dv.setUint32(0, 0xa1b2c3d4, true); dv.setUint16(4, 2, true); dv.setUint16(6, 4, true);
    dv.setUint32(16, 262144, true); dv.setUint32(20, linktype, true);
    let off = 24;
    for (const r of records) {
      let sec = Math.floor(r.ts), usec = Math.round((r.ts - sec) * 1e6);
      if (usec >= 1e6) { sec++; usec -= 1e6; }
      dv.setUint32(off, sec, true); dv.setUint32(off + 4, usec, true);
      dv.setUint32(off + 8, r.d.length, true); dv.setUint32(off + 12, r.len, true);
      u8.set(r.d, off + 16);
      off += 16 + r.d.length;
    }
    return u8;
  }

  global.PcapParser = { parse, write, LINKTYPES };
})(window);
