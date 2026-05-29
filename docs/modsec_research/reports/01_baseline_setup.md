
---

# Infrastructure & Baseline Definition

## 1. Topography & Architecture
* **Target Application:** DVWA (Isolated Docker Network)
* **WAF/Proxy:** Nginx + libmodsecurity3 (Listening on 8080)
* **Ruleset:** OWASP Core Rule Set v3.3 (Paranoia Level 2)

## 2. Configuration & Routing

```yaml
version: '3.8'
services:
  dvwa:
    image: vulnerables/web-dvwa
    container_name: dvwa_target
    restart: always
    networks:
      - waf_net

  modsec:
    image: owasp/modsecurity-crs:nginx
    container_name: modsec_proxy
    restart: always
    ports:
      - "8080:8080"
    environment:
      - PROXY_LOCATION=http://dvwa:80/
      - PORT=8080
      - SEC_RULE_ENGINE=On
      - BLOCKING_PARANOIA=2
    networks:
      - waf_net
    depends_on:
      - dvwa

networks:
  waf_net:
    driver: bridge
```

We placed the Two containers in the same bridge network, without exposing the DVWA container. So our real data path is:
- Browser / curl / postman
- ModSecurity + NGINX reverse Proxy: 127.0.0.1:8080
- Docker bridge network: waf_net
- DVWA internal service http://dvwa:80

![[Pasted image 20260526193602.png]]

## 3. Sanity Check

#### 1. Proving the proxy redirects data to DVWA:

![[Pasted image 20260526193913.png]]

But when trying to reach the DVWA directly we get a Failed to connect error:

![[Pasted image 20260526194026.png]]

So the Request has to go through the WAF.

Let's try and execute an SQLI attack (we ll try both Basic and Time Based):

![[Pasted image 20260526194253.png]]

Even the Time based one gets blocked instantly by the WAF.

So we pulled out the logs to see why exactly it is blocked :

```bash
sudo docker logs modsec_proxy | tail -n 3 > log
```

- First HTTP REQUEST(Simple SQL injection):

```json
"messages":[
{
"message":"SQL Injection Attack Detected via libinjection",
"details":
	{"match":"detected SQLi using libinjection.",
	"reference":"v853,16",
	"ruleId":"942100",
	"file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	"lineNumber":"46",
	"data":"Matched Data: s&1c found within ARGS:username: admin' OR 1=1 --",
	"severity":"2",
	"ver":"OWASP_CRS/4.25.0",
	"rev":"",
	"tags":["application-multi","language-multi","platform-multi","attack-sqli","paranoia-level/1","OWASP_CRS","OWASP_CRS/ATTACK-SQLI","capec/1000/152/248/66"],
	"maturity":"0",
	"accuracy":"0"
	}
}
```

- Time based SQL injection:

```json
{
"message":"Detects blind sqli tests using sleep() or benchmark()",
"details":
	{"match":"Matched \"Operator `Rx' with parameter `(?i:sleep\\s*?\\(.*?\\)|benchmark\\s*?\\(.*?\\,.*?\\))' against variable `ARGS:username' (Value: `'+2b(select*from(select(sleep(20)))a)+2b' )",
	"reference":"o24,9v854,40t:urlDecodeUni,t:replaceComments",
	"ruleId":"942160",
	"file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	"lineNumber":"154",
	"data":"Matched Data: sleep(20) found within ARGS:username: ' 2b(select*from(select(sleep(20)))a) 2b",
	"severity":"2",
	"ver":"OWASP_CRS/4.25.0",
	"rev":"",
	"tags":["modsecurity","application-multi","language-multi","platform-multi","attack-sqli","paranoia-level/1","OWASP_CRS","OWASP_CRS/ATTACK-SQLI","capec/1000/152/248/66"],
	"maturity":"0",
	"accuracy":"0"}}
```

let s check the rules:

```
# -=[ LibInjection Check ]=-
#
# There is a stricter sibling of this rule at 942101. It covers REQUEST_BASENAME and REQUEST_FILENAME.
#
# Ref: https://github.com/libinjection/libinjection
#
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/* "@detectSQLi" \
    "id:942100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,\
    msg:'SQL Injection Attack Detected via libinjection',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.25.0',\
    severity:'CRITICAL',\
    multiMatch,\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"
```

Also, after reviewing the rules file for sqli, it shows that modsecurity focuses a lot on Regular expressions:

```r
SecRule REQUEST_URI_RAW|ARGS|REQUEST_HEADERS|!REQUEST_HEADERS:Referer|FILES|XML:/* "@rx (?i)(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[56]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))(?:\.(?:%0[01]|\?)?|\?\.?|%(?:2(?:(?:5(?:2|c0%25a))?e|%45)|c0(?:\.|%[256aef]e)|u(?:(?:ff0|002)e|2024)|%32(?:%(?:%6|4)5|E)|(?:e|f(?:(?:8|c%80)%8)?0%8)0%80%ae)|0x2e){2,3}(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[56]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))" \
```

```r
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|REQUEST_FILENAME|XML:/* "@rx <(?:a(?:bbr|cronym|ddress|pplet|rea|udioscope)?|b(?:ase(?:front)?|do|gsound|ig|l(?:(?:ackfac|ockquot)e|ink)|ody|[qr]|utton)?|c(?:aption|enter|ite|o(?:de|l(?:group)?|mment))|d(?:[dt]|e?l|fn|i[rv])|em(?:bed)?|f(?:ieldset|n|o(?:nt|rm)|rame(?:set)?)|h(?:[1r]|ead|tml)|i(?:frame|layer|mg|n(?:put|s)|sindex)?|k(?:db|eygen)|l(?:a(?:bel|yer)|egend|i(?:mittext|nk|sting)?)|m(?:a(?:p|rquee)|e(?:nu|ta)|ulticol)|no(?:br|embed|frames|s(?:cript|martquotes))|o(?:bject|l|pt(?:group|ion))|p(?:aram|laintext|re)?|q|r(?:t|uby)|s(?:amp|cript|e(?:lect|rver)|hadow|idebar|mall|pa(?:cer|n)|t(?:r(?:ike|ong)|yle)|u[bp])?|t(?:(?:ab|it)le|body|[dr]|extarea|(?:foo)?t|h(?:ead)?)|ul?|(?:va|wb)r|xm[lp])[^0-9A-Z_a-z]" \
```

Heavy Regex => Heavy work on the CPU, so let's try and evade it using `PyTest` this WAF and see what happens.
