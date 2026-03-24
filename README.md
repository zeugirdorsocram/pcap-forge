# ⬡ PCAP-Forge

**Packet capture generator for detection engineers.**

PCAP-Forge is a self-contained, browser-based tool that generates valid libpcap `.pcap` and PCAP-NG `.pcapng` files from structured input or pasted protocol data — no server, no install, no dependencies beyond a modern web browser. Open the HTML file and start generating.

It bridges the gap between having a threat intelligence report describing a specific protocol exchange and actually being able to test a detection rule against realistic traffic.

---

## Quick Start

1. Download `pcap-forge.html`
2. Open it in any modern browser (Chrome, Firefox, Edge, Safari)
3. Click an example button or paste protocol data into the input area
4. Click **⬡ GENERATE PCAP**
5. Open the result in Wireshark, replay with `tcpreplay`, or feed it to Zeek/Suricata

> **Note:** Open the file locally by double-clicking it. Do not serve it through a CDN or cloud proxy — some CDN edge networks (e.g. Cloudflare) will rewrite the file contents.

---

## Features

### 34 Protocol Generators

Every protocol generates a complete, realistic session with correct checksums (IPv4, TCP, UDP, ICMPv6 pseudo-header) that opens cleanly in Wireshark with no warnings.

| Category | Protocols |
|---|---|
| **Web / Application** | HTTP/TCP, SMTP, POP3, FTP, IMAP, WebSocket |
| **Directory & Auth** | SMB3 (NTLMSSP), LDAP, Kerberos, RADIUS |
| **Infrastructure** | DNS, ICMP, ICMPv6, ARP, DHCP, NTP, SNMP, BGP |
| **Remote Access** | SSH, Telnet, RDP, WinRM |
| **Tunnelling & Proxy** | SOCKS5, GRE, QUIC |
| **Security / C2** | TLS (JA3-fingerprintable), IRC, DoH |
| **Database** | MySQL, Redis |
| **IoT / OT / ICS** | MQTT, Modbus TCP, DNP3 |
| **Raw** | UDP |

Each generator produces the full protocol lifecycle — TCP handshake and teardown, authentication sequences, application data, and graceful close — not just a single packet.

### Detection Rule Generation

After generating a PCAP, three rule formats are produced automatically from the session's parsed fields:

- **Sigma** — Structured detection rule targeting protocol-specific observables (DNS QNAME, TLS SNI, SMB share path, LDAP filter, Kerberos SPN, etc.) with correct `logsource` for Zeek, `tags` with ATT&CK technique IDs, and `falsepositives`/`level` stubs
- **Suricata** — `alert` rule with correct protocol keyword, `flow` direction, `content` matches (hex patterns for binary protocols, text matches for cleartext), sticky buffers (`dns.query`, `tls.sni`, `http.host`), and full `metadata` block
- **Snort** — Same content in Snort 3 format with `metadata:service` field
- **YARA** — `rule` block with wire-format hex signatures, text protocol command strings, and session-specific field values; if a file payload was injected, the file's magic bytes are extracted as a `$file_magic` hex string

All three formats include MITRE ATT&CK technique IDs and can be copied to clipboard or downloaded directly.

### MITRE ATT&CK Mapping

Every session displays the relevant ATT&CK technique and tactic in the INFO tab — linked directly to the ATT&CK website. All 34 protocols are mapped.

### PCAP Import & Parse

Drag a real `.pcap` file onto the import zone to parse and display it in the same packet summary view. Supports:

- libpcap 2.4 magic number validation
- Ethernet II and Raw IP link types
- IPv4 → TCP/UDP/ICMP/ARP frame parsing
- Application protocol detection from port numbers and payload signatures (HTTP, TLS with SNI extraction, SMTP, SMB2, DNS with QNAME parsing, DHCP message type, NTP, SNMP, and more)
- Hex dump of the full raw file

### PCAP Diff

Load two `.pcap` files side by side. Frames unique to Capture A are highlighted in red, frames unique to Capture B in green, matching frames dimmed. Useful for isolating exactly what changed between a baseline and a variant when tuning detection rules.

### Multi-Session Builder

Construct a single PCAP containing multiple independent protocol sessions in sequence. Each session card has:

- Independent protocol selection with per-protocol configuration fields
- Per-session file payload attachment
- Optional anomaly mode per session
- Configurable source/destination IPs and ports

All sessions are concatenated under a single libpcap global header with 1-second inter-session gaps and proper sequential timestamps. The packet summary labels each frame `[S1]`, `[S2]`, etc.

### Noise Injection

Toggle realistic background traffic around the generated session — DNS lookups to known-good resolvers, NTP syncs, HTTP GETs to CDN hosts, ICMP echo pairs, and ARP broadcasts. Three intensity levels: Low (5 frames), Medium (15), High (40). Makes captures look like real network slices rather than isolated lab traffic.

### Anomaly Mode

Introduce protocol-specific wire-format malformations into the generated PCAP — invalid TCP data offsets, URG flags on SMTP, TTL=1 on POP3, corrupted SMB2 magic bytes, invalid DNS QTYPE 0xFFFF, SSL2 version bytes in a TLS record, and more. Useful for testing whether IDS/IPS parsers handle edge cases gracefully.

### Session Templates

Six built-in detection scenarios load with one click:

| Template | Description |
|---|---|
| Phishing Campaign | SMTP with HTML body and spoofed EHLO domain |
| Lateral Movement | SMB3 with NTLMSSP auth and C$ tree connect |
| Kerberoasting | Kerberos TGS-REQ for a service SPN |
| DNS Exfiltration | DNS TXT query with base64-encoded payload in QNAME |
| ICS Recon | Modbus READ_HOLDING_REGISTERS bulk enumeration |
| Web C2 | HTTP POST beacon with custom headers |

Save your own templates by name — they persist across sessions via `localStorage`.

### Export

From the packet summary panel:

- **CSV** — Frame list with No, Time, Source, Destination, Protocol, Info columns
- **JSON** — Same data as a typed JSON array
- **PCAP-NG** — Full PCAP Next Generation format with Section Header Block, Interface Description Block, and Enhanced Packet Blocks. If a session note is entered in the INFO tab, it is embedded as an EPB `opt_comment` in every frame.

### Protocol Explainer

A collapsible panel below the results explains what each packet in the generated session means to an analyst — overview of the protocol, frame-by-frame security relevance ("this is where the NTLMSSP challenge is captured for offline cracking"), and threat hunting notes with specific IOCs and patterns to look for. All 34 protocols have full explainer content.

### File Payload Injection

Attach any file to a session and it will be embedded as a protocol-appropriate payload:

| Protocol | Injection Method |
|---|---|
| HTTP/TCP | File bytes as request body; Content-Type auto-detected from extension |
| SMTP | Base64-encoded MIME attachment (RFC 2045) |
| POP3 | Rebuilt as multipart MIME in RETR response |
| SMB3 | SMB2 WRITE request (FC 0x0009) injected after CREATE response |
| UDP | File bytes replace the raw payload |

---

## PCAP Format

| Field | Value |
|---|---|
| Format | libpcap 2.4 (magic `0xa1b2c3d4`, little-endian) |
| Link Type | LINKTYPE_ETHERNET (1) |
| Snap Length | 65535 |
| IP Version | IPv4 (all protocols), IPv6 (ICMPv6) |
| Checksums | IPv4 header, TCP pseudo-header, UDP pseudo-header, ICMPv6 pseudo-header |

PCAP-NG export uses Section Header Block + Interface Description Block + Enhanced Packet Blocks (RFC compliant).

---

## Use Cases

- **SIEM rule validation** — Generate a PCAP matching the protocol exchange described in a threat intel report, import into your SIEM lab, and verify your detection rule fires
- **Suricata / Snort testing** — `suricata -r capture.pcap` or `snort -r capture.pcap` to verify signature match against correct wire-format traffic
- **Zeek script development** — Generate multi-session captures and run `zeek -r multi.pcap` to produce structured logs for script development
- **JA3 fingerprint testing** — The TLS generator produces a JA3-fingerprintable ClientHello; vary cipher suites and extensions to test JA3-based detection rules
- **Kerberoasting / AS-REP roasting simulation** — Generate Kerberos TGS-REQ traffic targeting specific SPNs for detection rule testing
- **Lateral movement kill chain** — Multi-session builder: ICMP ping sweep → RDP connection → SMB3 with file write → LDAP enumeration in one PCAP
- **ICS/SCADA baseline profiling** — Modbus and DNP3 generators for testing OT detection rules and anomaly baselines
- **Analyst training** — Protocol explainer panel provides Wireshark-style context without requiring a full lab environment

---

## System Requirements

| Component | Requirement |
|---|---|
| Browser | Chrome 90+, Firefox 88+, Edge 90+, Safari 15+ |
| Network | Not required (fully offline after initial load) |
| Storage | ~430 KB (single HTML file) |
| Analysis tool | Wireshark 3.x+ recommended |

The tool uses Google Fonts for the Orbitron and Share Tech Mono typefaces. If running fully air-gapped, these will fall back to Courier New — all functionality is unaffected.

---

## Roadmap

### Shipped

| Version | Feature |
|---|---|
| v2.3 | PCAP import & parse |
| v2.3 | Suricata / Snort rule stubs |
| v2.3 | YARA rule stubs |
| v2.4 | PCAP diff mode |
| v2.4 | MITRE ATT&CK mapping |
| v2.4 | Session templates |
| v2.4 | PCAP annotation (PCAP-NG with embedded comments) |
| v2.4 | Export to CSV / JSON |
| v2.4 | Protocol explainer panel |
| v2.4 | PCAP-NG format |
| v2.5 | IPv6 support (ICMPv6 with correct pseudo-header checksums) |
| v2.5 | Additional protocols: SSH, MQTT, Redis, BGP, RADIUS, WebSocket, GRE, QUIC |

### Planned

- **Additional protocols** — NFS, PostgreSQL, CoAP, EtherNet/IP, BACnet, OSPF, VXLAN, gRPC/HTTP2, HTTP/3
- **IPv6 generators for existing protocols** — TCP/UDP sessions over IPv6 addresses for all existing protocol generators
- **PCAP-NG only output option** — Write all captures as PCAP-NG by default with interface metadata
- **Collaborative mode** — Real-time session sharing for red/blue team exercises

---

## Limitations

| Limitation | Notes |
|---|---|
| No encryption | TLS and SMB3 generate structurally correct handshakes but application data frames contain placeholder bytes |
| Simplified auth responses | NTLMSSP hashes (NTHash, LMHash, MIC) use placeholder byte arrays — sufficient for structural dissection but will not pass cryptographic validation |
| Single-segment TCP streams | Application data fits in one PSH+ACK frame; no TCP segmentation or reassembly |
| No VLAN / 802.1Q tagging | Ethernet frames do not include VLAN tags |
| IPv6 partial | ICMPv6 generator uses full IPv6 headers; existing TCP/UDP protocol generators use IPv4 only |
| Browser memory limits | Very large multi-session captures with large file attachments may be slow in memory-constrained environments |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

Issues and pull requests are welcome. When adding a new protocol generator, please ensure:

1. The generator is wired into `detectProto`, `parseInput`, default ports, `handleGenerate` dispatch, `msBuild` dispatch, `msReadConfig`, `msSessionToParsed`, `msProtoFields`, `msCardTitle`, `MS_PROTO_DEFAULTS`, `MS_PROTO_LABELS`, `ATTACK_MAP`, `ATTACK_TACTIC_MAP`, `LOGSOURCE_MAP`, `CONTENT_SIGS`, `IDS_PROTO_MAP`, and `FLOW_MAP`
2. A `buildSummary` case returns a frame-by-frame packet summary
3. An `EXPLAINER_DATA` entry provides analyst context
4. All checksums are correctly computed (use the existing `onesComplementChecksum`, `ipv6Hdr`, `icmpv6Checksum` helpers)
5. The PCAP opens in Wireshark without checksum warnings

---

*Built for the detection engineering community.*
