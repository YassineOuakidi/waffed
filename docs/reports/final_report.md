# Final Project Report

## Waffer: High-Performance Layer-7 Web Application Firewall and Reverse Proxy in C

**Student:** Yassine Ouakidi  
**Program:** 3rd-Year Cybersecurity Engineering  
**University:** UIR — Université Internationale de Rabat  
**Supervisor:** Prof. Noufel  
**Project Type:** Final Summer Cybersecurity Engineering Project  

---

## Abstract

This project presents **Waffer**, a high-performance Layer-7 Web Application Firewall and reverse proxy written in C.

The project was motivated by research into asymmetric resource exhaustion vulnerabilities in traditional Web Application Firewall architectures, especially WAFs that rely heavily on complex regular expressions. In these systems, a small malicious request may trigger expensive inspection behavior, creating disproportionate CPU or memory cost for the defender.

Waffer addresses this problem using a deterministic inspection pipeline based on non-blocking `epoll` networking, HTTP normalization, Aho-Corasick pre-filtering, a zero-allocation span-based lexer, and DFA-based semantic detection for SQL Injection and XSS payloads.

The project also includes a local PHP dashboard and an EVE-NG virtual lab using Kali, pfSense, Zorin/Ubuntu, and DVWA. The final result demonstrates a complete defensive architecture where clean traffic is proxied to the backend and malicious Layer-7 requests are blocked before reaching the vulnerable application.

---

## 1. Introduction

Web applications are among the most exposed components of modern information systems. Attacks such as SQL Injection, Cross-Site Scripting, scanner probes, and malformed HTTP requests remain common because they target weaknesses in input validation and backend logic.

Web Application Firewalls are used to inspect HTTP traffic before it reaches the application. However, many WAFs depend heavily on large RegEx-based rule sets. This makes detection flexible, but it can also create performance problems under hostile input.

This project explores a different approach: a deterministic WAF engine written in C, using state machines and bounded memory behavior instead of relying mainly on regular expressions.

---

## 2. Problem Statement

### 2.1 Limitations of RegEx-Heavy WAFs

Traditional WAFs often use regular expressions for attack detection. While effective for many known signatures, this approach has limitations.

First, complex regular expressions may trigger expensive backtracking. A carefully crafted input can require large CPU time to evaluate.

Second, repeated decoding, parsing, and temporary allocations can create memory pressure when many requests are processed.

Third, pure string matching does not always understand attack grammar. SQL Injection and XSS payloads are structured inputs, not only suspicious substrings.

---

### 2.2 Asymmetric Resource Exhaustion

The main research motivation of Waffer is asymmetric resource exhaustion.

This occurs when:

```text
The attacker sends a cheap request,
but the defender spends expensive resources processing it.
```

In the WAF context, this is a serious problem. A WAF should protect backend applications, but if its inspection engine is too expensive, the WAF itself can become the attack target.

---

### 2.3 DDoS and ReDoS Context

DDoS attacks attempt to exhaust resources through traffic volume. ReDoS attacks attempt to exploit inefficient regular expression evaluation.

A RegEx-heavy WAF may be affected by both:

- high request volume increases the number of inspections,
- malicious input structure increases per-request CPU cost,
- dynamic allocations increase memory pressure,
- backend protection weakens if the WAF becomes saturated.

Waffer was designed to avoid catastrophic RegEx behavior by using deterministic automata and bounded buffers.

---

## 3. Project Objectives

The objectives of Waffer were:

1. Build a functional Layer-7 reverse proxy in C.
2. Use non-blocking sockets and `epoll` for event-driven I/O.
3. Normalize HTTP traffic before inspection.
4. Use Aho-Corasick for linear-time signature pre-filtering.
5. Implement a zero-allocation lexer using span-based token tracking.
6. Build DFA engines for SQLi and XSS detection.
7. Provide a PHP dashboard for local management and log visibility.
8. Validate the system in EVE-NG using a segmented topology.

---

## 4. Methodology

### 4.1 Why C

C was chosen because this project is focused on cybersecurity systems engineering.

Using C provides direct control over:

- sockets,
- non-blocking I/O,
- memory layout,
- fixed-size buffers,
- parser implementation,
- and state-machine behavior.

This made it possible to understand the WAF at the system level instead of hiding the core logic behind a high-level framework.

---

### 4.2 Why epoll

`epoll` was chosen because Waffer is a Linux-based network proxy.

It allows the engine to monitor multiple sockets and react only when a socket becomes ready. This avoids blocking the entire process on one connection.

The connection state machine tracks the progress of each request:

```text
read client
inspect request
connect backend
send to backend
read backend response
send response to client
```

---

### 4.3 Why Aho-Corasick

Aho-Corasick was chosen for the pre-filter because it can scan many signatures in one pass.

Instead of checking each rule independently, Waffer builds a trie and uses failure links to scan normalized request data efficiently.

This makes it suitable for weighted WAF signatures.

---

### 4.4 Why Lexer and DFA

SQL Injection and XSS payloads have language-like structure.

For example:

```sql
' OR '1'='1
```

contains:

```text
quote
boolean operator
left operand
comparison operator
right operand
```

A DFA can model this sequence directly.

The lexer creates tokens without allocating new strings. The DFA consumes those tokens and decides whether the sequence reaches an accept/block state.

---

### 4.5 Why EVE-NG

EVE-NG was used to validate the project in a realistic virtual network.

The lab includes:

- Kali as attacker/client,
- pfSense as firewall/router,
- Zorin/Ubuntu as Waffer host,
- DVWA Ubuntu server as vulnerable backend.

The important requirement was:

```text
Kali must access DVWA only through Waffer.
Direct access to DVWA must be blocked or unreachable.
```

---

## 5. System Architecture

The deployed lab architecture is:

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

Clients send requests to:

```text
10.10.10.10:3333
```

Waffer forwards clean traffic to:

```text
10.10.20.20:8000
```

The dashboard is local only:

```text
localhost:8081
```

This keeps the administration interface away from the attacker network.

---

## 6. Implementation

### 6.1 Event Loop

Waffer uses an `epoll` event loop and non-blocking sockets.

Each connection progresses through explicit states:

```text
STATE_READ_CLIENT
STATE_INSPECT_REQUEST
STATE_CONNECT_BACKEND
STATE_SEND_BACKEND
STATE_READ_BACKEND
STATE_SEND_CLIENT
```

This provides a structured reverse-proxy model.

---

### 6.2 HTTP Framing

Before inspection, Waffer checks whether a complete HTTP request has arrived.

The framing logic validates:

- request line,
- header terminator,
- header format,
- `Content-Length`,
- unsupported transfer encoding,
- maximum request size.

Malformed requests receive a `400 Bad Request`.

---

### 6.3 Normalization

The normalization layer reduces evasion attempts.

It performs:

- repeated URL decoding,
- lowercase conversion,
- `+` to space conversion,
- slash normalization,
- header, URI, and body normalization.

This ensures that encoded payloads are inspected in a canonical form.

---

### 6.4 Aho-Corasick Pre-filter

The rule engine loads weighted signatures such as:

```text
9009|100|URI|' OR '1'='1
9011|75|BODY|UNION SELECT
905|100|HEADER:User-Agent|sqlmap
```

Matches add to an anomaly score. If the score reaches the configured threshold, the request is blocked.

---

### 6.5 Grammar Engine

The grammar engine is composed of:

```text
Lexer -> Semantic Classifier -> DFA
```

The lexer produces span-based tokens:

```c
typedef struct token {
    const char *start;
    int len;
    token_kind_t kind;
    waf_zone_t zone;
} token_t;
```

This avoids per-token heap allocation.

---

### 6.6 SQL Injection DFA

The SQLi DFA detects patterns such as:

```sql
' OR '1'='1
UNION SELECT
WAITFOR DELAY
SELECT ... FROM information_schema
```

It does this by classifying tokens and following deterministic transitions until a malicious accept state is reached.

---

### 6.7 XSS DFA

The XSS DFA detects payload families such as:

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
javascript:
document.cookie
```

It recognizes dangerous tags, event handlers, JavaScript schemes, and DOM-related sinks.

---

### 6.8 Logging

Waffer writes block events to:

```text
logs/waf.log
```

Example event types include:

```text
SQLi DFA detection
XSS DFA detection
Aho-Corasick score threshold exceeded
Malformed HTTP request
```

The dashboard reads this file to show live detection activity.

---

### 6.9 PHP Dashboard

The dashboard is used for local operations:

- view configuration,
- edit rule files,
- toggle DFA flags in the config,
- monitor logs.

It is started locally on the WAF/Zorin machine:

```bash
php -S localhost:8081 -t dashboard/public
```

This prevents the attacker network from accessing the management interface.

---

## 7. Testing Environment

The project was tested in EVE-NG.

Main validation tests:

| Test | Expected Result |
|---|---|
| Kali to Waffer engine | Works |
| Waffer to DVWA | Works |
| Kali directly to DVWA | Blocked or unreachable |
| Clean request through Waffer | Allowed |
| SQLi request through Waffer | Blocked |
| XSS request through Waffer | Blocked |
| Dashboard log visibility | Works locally |

---

## 8. Results

The project successfully demonstrates:

1. A working C reverse proxy.
2. Event-driven networking with `epoll`.
3. HTTP request framing and parsing.
4. Normalization of encoded payloads.
5. Linear-time signature pre-filtering with Aho-Corasick.
6. Zero-allocation tokenization.
7. DFA-based SQLi and XSS detection.
8. Local PHP dashboard operations.
9. EVE-NG network segmentation.

The most important result is that malicious requests can be blocked before reaching DVWA, while clean requests are forwarded.

---

## 9. Performance Benefits

Waffer provides several performance-oriented benefits:

### Deterministic Parsing

The lexer walks the input buffer and produces tokens without allocating new strings.

### Linear Signature Scanning

Aho-Corasick scans multiple signatures in one pass.

### Avoidance of RegEx Backtracking

The DFA engines rely on deterministic state transitions rather than backtracking.

### Bounded Buffers

The engine uses bounded request and response buffers.

### Event-Driven I/O

The `epoll` model prevents a single socket from blocking the entire process.

---

## 10. Limitations and Future Work

Waffer is an academic engineering prototype and can be improved.

Future improvements include:

- hot reload of rules without restarting the engine,
- stronger HTTP/1.1 handling,
- better persistent connection support,
- additional DFA modules for RCE, LFI, and SSRF,
- benchmark automation,
- TLS termination,
- dashboard authentication,
- and production-grade configuration validation.

---

## 11. Conclusion

Waffer demonstrates a deterministic Layer-7 WAF and reverse proxy architecture written in C.

The system was motivated by the limitations of RegEx-heavy WAF inspection under asymmetric resource exhaustion. By combining `epoll`, normalization, Aho-Corasick, a zero-allocation lexer, and DFA-based semantic detection, Waffer provides a practical alternative inspection model.

The EVE-NG lab validates the deployment: clients cannot directly reach DVWA, clean traffic is proxied through Waffer, and malicious SQLi/XSS payloads are blocked before reaching the backend.

This project strengthened my understanding of C systems programming, secure parsing, WAF architecture, network segmentation, and defensive cybersecurity engineering.