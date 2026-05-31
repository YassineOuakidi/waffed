# Waffer Technical Architecture

## 1. Purpose

This document explains the internal architecture of **Waffer**, a Layer-7 Web Application Firewall and reverse proxy written in C.

Waffer was designed to reduce dependence on RegEx-heavy inspection by using a deterministic pipeline:

```text
epoll event loop
HTTP framing
HTTP parsing
normalization
Aho-Corasick scoring
zero-allocation lexical analysis
DFA semantic detection
backend forwarding
```

The objective is to inspect malicious HTTP requests before they reach the backend application.

---

## 2. High-Level Request Pipeline

A request passing through Waffer follows this path:

```text
Client socket
    |
    v
epoll event loop
    |
    v
connection_t state machine
    |
    v
HTTP request buffer
    |
    v
HTTP parser
    |
    v
deep normalization
    |
    v
Aho-Corasick pre-filter
    |
    v
Lexer + SQLi/XSS DFA engines
    |
    +---- malicious ----> 403 Forbidden + log
    |
    +---- clean --------> backend socket -> DVWA
```

Each stage is separated to keep the engine understandable and modular.

---

## 3. TCP Acceptance Through epoll

The listener socket is created in:

```text
engine/src/net/socket.c
```

The listener creation function creates an IPv4 TCP socket, enables socket reuse, sets the socket to non-blocking mode, binds it, and starts listening.

The event loop is implemented in:

```text
engine/src/core/event_loop.c
```

The engine creates an epoll instance with:

```c
epoll_create1(0);
```

The listener socket is registered for:

```text
EPOLLIN
```

When the listener becomes readable, Waffer accepts the incoming client socket, makes it non-blocking, creates a connection object, and registers the new socket in epoll.

---

## 4. Connection State Machine

Each connection is represented by a `connection_t` structure.

It stores:

- client socket file descriptor,
- backend socket file descriptor,
- current connection state,
- client request buffer,
- backend response buffer,
- send progress counters.

Main states:

```text
STATE_READ_CLIENT
STATE_INSPECT_REQUEST
STATE_CONNECT_BACKEND
STATE_SEND_BACKEND
STATE_READ_BACKEND
STATE_SEND_CLIENT
STATE_CLOSED
STATE_LISTENER
```

Normal flow:

```text
STATE_READ_CLIENT
      |
      v
STATE_INSPECT_REQUEST
      |
      +---- DROP ----> 403 Forbidden
      |
      +---- ALLOW ---> STATE_CONNECT_BACKEND
                         |
                         v
                      STATE_SEND_BACKEND
                         |
                         v
                      STATE_READ_BACKEND
                         |
                         v
                      STATE_SEND_CLIENT
```

This model allows Waffer to process network events without blocking on a single client or backend connection.

---

## 5. HTTP Framing

Before parsing and inspection, Waffer checks whether the full HTTP request has arrived.

The framing logic checks:

- request-line presence,
- header terminator `\r\n\r\n`,
- header syntax,
- `Content-Length`,
- unsupported `Transfer-Encoding`,
- maximum request buffer size.

If the request is incomplete, Waffer waits for more data.

If the request is malformed, Waffer returns:

```text
HTTP/1.1 400 Bad Request
```

If the request is complete, the connection moves to:

```text
STATE_INSPECT_REQUEST
```

---

## 6. HTTP Parsing

The HTTP parser is implemented in:

```text
engine/src/http/http_parser.c
```

It extracts:

```text
method
URI
HTTP version
headers
body
```

The parsed request is stored in an `http_request_t` object.

This parsed object becomes the input for the normalization and rule inspection stages.

---

## 7. Deep Normalization

Normalization is implemented in:

```text
engine/src/http/normalizer.c
```

The purpose is to reduce evasion before detection.

Normalization includes:

- repeated URL decoding,
- lowercasing,
- converting `+` into spaces,
- converting backslashes to slashes,
- merging repeated slashes,
- normalizing URI, body, and header values.

Example:

```text
%27%20OR%20%271%27=%271
```

becomes:

```text
' or '1'='1
```

This makes later detection more reliable.

---

## 8. Aho-Corasick Pre-filter

The Aho-Corasick pre-filter is implemented in:

```text
engine/src/rules/aho_corasick.c
engine/src/rules/rule_loader.c
```

Rules are loaded from the configured rule file.

Example:

```text
9011|75|BODY|UNION SELECT
```

Rule fields:

| Field | Meaning |
|---|---|
| Rule ID | Unique identifier |
| Score | Anomaly score |
| Zone | URI, BODY, HEADER, or specific header |
| Pattern | Signature pattern |

The trie is built at startup. Failure links allow Waffer to scan input in linear time while detecting multiple signatures.

---

## 9. Zone-Aware Scoring

Waffer scans multiple zones:

```text
URI
BODY
HEADER
HEADER:User-Agent
```

Each matching rule adds its score to the request score.

If the score reaches:

```conf
block_threshold=100
```

the request is blocked without needing deeper DFA inspection.

This pre-filter is useful for known signatures and scanner indicators.

---

## 10. Zero-Allocation Lexer

The lexer is implemented in:

```text
engine/include/rules/lexer.h
engine/src/rules/lexer.c
```

It produces tokens such as:

```text
TOK_WORD
TOK_NUMBER
TOK_QUOTE
TOK_EQUALS
TOK_OTHER
TOK_EOF
```

The token structure is span-based:

```c
typedef struct token {
    const char *start;
    int len;
    token_kind_t kind;
    waf_zone_t zone;
} token_t;
```

This means Waffer does not allocate a new string for each token.

The token simply points to a region in the normalized input buffer. This is the key zero-allocation design choice in the grammar engine.

---

## 11. DFA Routing

The DFA dispatcher is implemented in:

```text
engine/src/dfa/dfa_common.c
```

Waffer runs DFA checks on:

- URI,
- body,
- header values.

For each inspected buffer:

```text
initialize lexer
run SQLi DFA
reinitialize lexer
run XSS DFA
```

If any DFA reports a detection, the request is dropped.

---

## 12. SQL Injection DFA

The SQLi DFA is implemented in:

```text
engine/src/dfa/sql_dfa.c
```

The SQL classifier maps tokens into semantic SQL classes:

```text
SQL_C_QUOTE
SQL_C_BOOL_OP
SQL_C_COMPARE_OP
SQL_C_UNION
SQL_C_SELECT
SQL_C_TIME_FUNC
SQL_C_METADATA
SQL_C_DANGEROUS_STMT
```

The DFA then moves through states such as:

```text
SQL_S_START
SQL_S_SAW_BOUNDARY
SQL_S_SAW_BOOL
SQL_S_SAW_LHS
SQL_S_SAW_COMPARE
SQL_S_SAW_UNION
SQL_S_SAW_SELECT
SQL_S_ACCEPT
```

### Boolean Tautology Example

Payload:

```sql
' OR '1'='1
```

Simplified path:

```text
QUOTE
  -> BOOL_OP
  -> LHS
  -> COMPARE_OP
  -> RHS
  -> ACCEPT
```

### UNION Injection Example

Payload:

```sql
UNION SELECT
```

Simplified path:

```text
UNION
  -> SELECT
  -> ACCEPT
```

### Time-Based Injection Example

Indicators include:

```text
WAITFOR
DELAY
SLEEP
PG_SLEEP
BENCHMARK
```

These patterns are important because they may trigger backend delays and resource consumption.

---

## 13. XSS DFA

The XSS DFA is implemented in:

```text
engine/src/dfa/js_dfa.c
```

It detects structures such as:

```text
<script>
onerror=
javascript:
document.cookie
alert
eval
```

The XSS engine looks for dangerous HTML/JavaScript grammar, including:

- script tag injection,
- dangerous HTML tags,
- event-handler execution,
- JavaScript URI schemes,
- DOM object and sink usage.

Example:

```html
<img src=x onerror=alert(1)>
```

This is detected as an event-handler execution pattern.

---

## 14. Verdict Engine

The central inspection function is implemented in:

```text
engine/src/rules/rule_engine.c
```

The inspection function returns:

```text
VERDICT_ALLOW
VERDICT_DROP
VERDICT_BAD_REQ
```

Decision flow:

```text
Parse HTTP request
   |
Normalize request
   |
Aho-Corasick scoring
   |
Score >= threshold?
   | yes -> DROP
   | no
   v
Run SQLi/XSS DFA engines
   |
Detection?
   | yes -> DROP
   | no
   v
ALLOW
```

---

## 15. Backend Forwarding

If the verdict is `VERDICT_ALLOW`, Waffer opens a backend connection using the configured backend host and port.

Example configuration:

```conf
backend_host=10.10.20.20
backend_port=8000
```

The original request is then forwarded to DVWA, and the backend response is returned to the client.

---

## 16. Logging

Waffer writes security events to:

```text
logs/waf.log
```

Typical events include:

```text
AC score threshold exceeded
SQLi DFA detection
XSS DFA detection
Malformed HTTP request
```

The local PHP dashboard reads this log file to display blocked requests.

---

## 17. EVE-NG Deployment

The EVE-NG topology is:

```text
Kali attacker
      |
pfSense firewall/router
      |
WAF/Zorin
  ens3 = 10.10.10.10/24
  ens4 = 10.10.20.10/24
      |
DVWA Ubuntu Server
  ens3 = 10.10.20.20/24
```

Runtime path:

```text
Kali -> 10.10.10.10:3333 -> Waffer -> 10.10.20.20:8000 -> DVWA
```

Dashboard path:

```text
Zorin browser -> http://localhost:8081
```

---

## 18. Architecture Conclusion

Waffer combines:

```text
non-blocking network I/O
+ bounded buffers
+ HTTP normalization
+ linear-time Aho-Corasick scanning
+ zero-allocation lexical analysis
+ DFA-based semantic detection
```

This architecture was designed to reduce reliance on expensive RegEx backtracking and to make WAF inspection more deterministic under hostile traffic.