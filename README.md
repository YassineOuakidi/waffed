# Waffer — High-Performance Layer-7 Web Application Firewall & Reverse Proxy in C

**Waffer** is a high-performance Layer-7 Web Application Firewall and reverse proxy written in C.

It was developed by **Yassine Ouakidi**, 3rd-year Cybersecurity Engineering student at **UIR — Université Internationale de Rabat**, as a final summer project supervised by **Prof. Noufel**.

Waffer was built around a clear research problem: traditional WAFs, especially RegEx-heavy systems such as ModSecurity with large rule sets, can suffer from asymmetric resource exhaustion when crafted HTTP requests force expensive inspection paths.

Instead of relying only on regular expressions, Waffer uses a deterministic inspection pipeline based on:

- non-blocking `epoll` networking,
- HTTP framing and deep normalization,
- Aho-Corasick signature pre-filtering,
- a zero-allocation span-based lexer,
- DFA state machines for SQL Injection and XSS detection,
- a local PHP management dashboard,
- and an EVE-NG lab for realistic network validation.

---

## Project Summary

Waffer runs as a Layer-7 reverse proxy between clients and a vulnerable backend application.

```text
Client / Kali
      |
      v
Waffer C Reverse Proxy
      |
      v
DVWA Backend
```

In the EVE-NG lab, the validated topology is:

```text
Kali / Client
      |
pfSense Firewall
      |
WAF/Zorin Machine
  - Waffer C engine on 10.10.10.10:3333
  - PHP dashboard local only on localhost:8081
      |
DVWA Ubuntu Server on 10.10.20.20:8000
```

The client does not access DVWA directly. It accesses the backend only through Waffer:

```text
http://10.10.10.10:3333/
```

---

## The Problem

Traditional Web Application Firewalls often depend heavily on large RegEx rule sets. This approach is flexible, but it can create performance and resilience issues under hostile traffic.

### RegEx Backtracking

Some regular expressions can trigger expensive backtracking. A short malicious request may force the WAF to spend disproportionate CPU time during inspection.

This creates an asymmetric situation:

```text
Low attacker cost  ->  High defender cost
```

For a WAF, this is dangerous because the defensive layer itself can become the target.

### Memory Pressure

Complex inspection pipelines may repeatedly allocate temporary buffers, decoded strings, or parser objects. Under high request volume, this can increase memory pressure, allocator overhead, and fragmentation.

A WAF should protect the backend application. It should not become the easiest component to exhaust.

### Signature-Only Detection

SQL Injection and XSS payloads are not only suspicious strings. They are structured inputs.

For example:

```sql
' OR '1'='1
UNION SELECT
```

These payloads contain meaningful token sequences. Waffer treats them as grammar-like structures and checks them using deterministic finite automata.

---

## The Solution

Waffer uses a deterministic Layer-7 inspection pipeline:

```text
TCP accept
   |
epoll event loop
   |
HTTP framing
   |
HTTP parsing and normalization
   |
Aho-Corasick pre-filter scoring
   |
zero-allocation lexer
   |
SQLi / XSS DFA engines
   |
ALLOW -> forward to backend
DROP  -> return 403 and log
```

The design goal is:

```text
Normalize first.
Scan quickly.
Parse semantically.
Avoid RegEx backtracking.
Keep memory behavior predictable.
```

---

## Main Features

### Non-blocking epoll Event Loop

Waffer uses non-blocking sockets and `epoll` to process client and backend sockets through an explicit connection state machine.

Main states include:

```text
STATE_READ_CLIENT
STATE_INSPECT_REQUEST
STATE_CONNECT_BACKEND
STATE_SEND_BACKEND
STATE_READ_BACKEND
STATE_SEND_CLIENT
```

This makes the engine closer to a real reverse proxy than a simple blocking HTTP server.

---

### Deep HTTP Normalization

Before detection, Waffer normalizes request data to reduce evasion attempts.

The normalizer handles:

- repeated URL decoding,
- lowercase conversion,
- `+` to space conversion,
- backslash-to-slash replacement,
- duplicate slash merging,
- URI, body, and header normalization.

Example:

```text
%27%20OR%20%271%27=%271
```

becomes:

```text
' or '1'='1
```

---

### Aho-Corasick Pre-filter

Waffer loads weighted signatures from the rule file.

Example:

```text
9009|100|URI|' OR '1'='1
9011|75|BODY|UNION SELECT
905|100|HEADER:User-Agent|sqlmap
```

The Aho-Corasick engine scans normalized request zones and accumulates anomaly scores.

If the score reaches the configured threshold, the request is blocked early.

---

### Zero-Allocation Lexer

The lexer does not allocate a new string for every token. It uses spans into the normalized buffer.

```c
typedef struct token {
    const char *start;
    int len;
    token_kind_t kind;
    waf_zone_t zone;
} token_t;
```

This makes tokenization predictable and avoids per-token heap allocation.

---

### DFA-Based SQL Injection Detection

The SQLi DFA classifies tokens into semantic categories such as:

```text
SQL_C_BOOL_OP
SQL_C_COMPARE_OP
SQL_C_UNION
SQL_C_SELECT
SQL_C_TIME_FUNC
SQL_C_METADATA
SQL_C_DANGEROUS_STMT
```

Then it follows deterministic state transitions to detect malicious grammar.

Example:

```sql
' OR '1'='1
```

can be interpreted as:

```text
QUOTE -> BOOL_OP -> LHS -> COMPARE_OP -> RHS -> ACCEPT
```

---

### DFA-Based XSS Detection

The XSS DFA detects structures such as:

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
javascript:
document.cookie
```

It recognizes dangerous tags, event handlers, JavaScript schemes, dangerous functions, and DOM-related sinks.

---

### Local PHP Dashboard

Waffer includes a lightweight PHP dashboard for local administration.

The dashboard is intentionally run only on the WAF/Zorin machine:

```bash
php -S localhost:8081 -t dashboard/public
```

Open it locally on Zorin:

```text
http://localhost:8081
```

The dashboard is not exposed to Kali or the attacker network.

---

## Tech Stack

| Component | Technology |
|---|---|
| Core engine | C |
| Network I/O | Linux sockets, non-blocking I/O, `epoll` |
| HTTP parsing | Custom C parser |
| Normalization | Custom normalization layer |
| Signature pre-filter | Aho-Corasick |
| Semantic detection | Lexer + DFA state machines |
| Dashboard | Vanilla PHP, HTML, CSS, JavaScript |
| Lab environment | EVE-NG |
| Firewall/router | pfSense |
| Backend target | DVWA |

---

## Repository Structure

```text
waf/
├── engine/
│   ├── include/
│   ├── src/
│   └── Makefile
├── config/
│   └── waf.conf
├── rules/
│   └── disabled/
│       └── experimental.rules
├── dashboard/
│   ├── public/
│   ├── config/
│   └── README.md
├── docs/
│   ├── architecture/
│   └── reports/
└── eve-ng/
    ├── *.md
    └── assets/
```

---

## Build Instructions

From the project root:

```bash
cd engine
make clean
make
```

Expected result:

```text
build/waf
```

Verify:

```bash
ls -lh build/waf
file build/waf
```

---

## Configuration

The main configuration file is:

```text
config/waf.conf
```

Example EVE-NG configuration:

```conf
listen_port=3333

backend_host=10.10.20.20
backend_port=8000

rules_file=../rules/disabled/experimental.rules
block_threshold=100

enable_sql_dfa=1
enable_xss_dfa=1

log_file=../logs/waf.log
log_allow=1

max_request_size=8192
max_body_size=8192
max_headers=100
```

Important: the current engine loads the config from a fixed relative path:

```text
../config/waf.conf
```

So run the binary from inside the `engine/` directory.

---

## Run the WAF Engine

From the project root:

```bash
cd engine
./build/waf
```

Verify that it is listening:

```bash
ss -lntp | grep 3333
```

Expected:

```text
LISTEN ... 0.0.0.0:3333 ... waf
```

---

## Run the Dashboard Locally

From the project root:

```bash
php -S localhost:8081 -t dashboard/public
```

Open locally from the WAF/Zorin browser:

```text
http://localhost:8081
```

---

## Test Clean Traffic

From Kali:

```bash
curl -i http://10.10.10.10:3333/
```

Expected result:

```text
HTTP response from DVWA through Waffer.
```

---

## Test SQL Injection Blocking

From Kali:

```bash
curl -i "http://10.10.10.10:3333/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit"
```

Expected result:

```text
HTTP/1.1 403 Forbidden
Access Denied.
```

Check logs on the WAF/Zorin machine:

```bash
tail -n 30 logs/waf.log
```

---

## Test Backend Isolation

From Kali:

```bash
curl -I --connect-timeout 3 http://10.10.20.20:8000/
```

Expected result:

```text
Connection blocked, unreachable, or timed out.
```

This confirms that clients cannot bypass Waffer and directly access DVWA.

---

## Academic Context

Waffer was developed as a summer cybersecurity engineering project.

It demonstrates:

- C systems programming,
- event-driven networking,
- secure parsing,
- deterministic attack detection,
- WAF design,
- EVE-NG network simulation,
- and dashboard-based operational visibility.

---

## Final Result

Waffer demonstrates a deterministic WAF architecture based on:

```text
network segmentation
+ Layer-7 reverse proxying
+ HTTP normalization
+ Aho-Corasick pre-filtering
+ zero-allocation tokenization
+ DFA-based SQLi/XSS detection
```

The result is a functional research prototype that blocks malicious HTTP requests before they reach a vulnerable backend.