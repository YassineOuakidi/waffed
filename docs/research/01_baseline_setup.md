# Infrastructure & Baseline Definition

## 1. Topography & Architecture
* **Target Application:** DVWA (Isolated Docker Network)
* **WAF/Proxy:** Nginx + libmodsecurity3 (Listening on 8080)
* **Ruleset:** OWASP Core Rule Set v3.3 (Paranoia Level 2)

## 2. Configuration & Routing
[Document how the proxy bridges traffic to the target, including environment variables used in Docker.]

## 3. Sanity Check
[Provide the exact `curl` command and the raw HTTP 403 response proving the WAF is armed.]

