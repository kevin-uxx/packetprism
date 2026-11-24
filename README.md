# PacketPrism — browser-based packet capture viewer

A dependency-free, 100% client-side `.pcap` / `.pcapng` analyzer. Nothing is uploaded — files are parsed in the browser.

## Run

Serve the folder over HTTP (some browsers block local scripts on `file://`):

```
cd packetprism
python -m http.server 5173      # or: npx serve .
```

Open http://localhost:5173 and click **Load sample capture**, or drop your own capture file.
`http://localhost:5173/?sample` opens the demo capture directly.

## Features

- **Parsers**: libpcap (µs/ns, both byte orders) and pcapng (SHB/IDB/EPB/SPB, `if_tsresol`).
  Link types: Ethernet, 802.1Q VLAN, Raw IP, Linux SLL/SLL2, BSD loopback.
- **Dissectors**: ARP, IPv4 (checksum verification), IPv6 (+ext headers), TCP (relative seq/ack, stream index,
  options, checksum), UDP, ICMP (incl. quoted datagram), ICMPv6/ND, DNS & mDNS (name compression), DHCP, NTP,
  HTTP/SSDP, TLS (records, Client/Server Hello, SNI, ALPN, cipher suites, supported versions).
- **Packet list**: virtualised (smooth with 100k+ rows), sortable columns, protocol colour coding, warning rows
  (RST, NXDOMAIN, ICMP errors, bad checksums), relative / delta / clock time.
- **Filtering**: protocol chips (multi-select) + Wireshark-style display filters with autocomplete:
  `tcp.port == 443 && !(ip.addr == 10.0.0.1)`, `dns.qry.name contains github`, `frame.len > 1000`, `http.request.method ~ "^P"`.
- **Detail view**: route summary, TCP flag chips, key-field cards, collapsible layer tree with bit-level fields,
  hex/ASCII dump linked both ways (field → bytes and byte → owning field).
- **Follow TCP/UDP stream** (ASCII / hex), **Insights** (protocol mix, timeline, top talkers, services, TCP flags,
  frame sizes, DNS lookups) and **Conversations** table — every chart row is clickable to filter.
- **Export** displayed packets as `.pcap`, `.csv` or full-dissection `.json`.
- Keyboard: `↑/↓` or `j/k` navigate, `/` filter, `F` follow stream, `Esc` clear, right-click a row for actions.

## Layout

```
index.html
css/styles.css
js/pcap.js       pcap/pcapng reader + writer
js/decoders.js   protocol dissectors (layers, fields with byte offsets, filter values)
js/filter.js     display-filter tokenizer/parser/compiler
js/sample.js     deterministic generator for the demo capture (valid checksums)
js/app.js        UI: table, detail tree, hex view, insights, conversations, streams, export
```
