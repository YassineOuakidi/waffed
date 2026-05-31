# WAF Dashboard

Vanilla PHP control panel for the C WAF project.

## Run locally

From the project root:

```bash
php -S localhost:8081 -t dashboard/public
```

Then open:

```text
http://localhost:8081
```

## What it can edit

- `config/waf.conf`
- the rules file pointed to by `rules_file`
- DFA toggles: `enable_sql_dfa`, `enable_xss_dfa`
- log visibility through a live AJAX tail of `log_file`

## Important runtime note

The dashboard writes configuration and rule files to disk. The current C engine loads config/rules at startup, so restart the C WAF after changing rules or DFA toggles.

## Disabled rule format

Disabled rules are written as:

```text
#DISABLED|id|score|zone|match
```

The existing C rule loader skips comment lines, so disabled rules are not loaded.

## UI / reload fix

Static assets are now inside `dashboard/public/assets/`, so CSS and JavaScript load correctly when using PHP's built-in server with `-t dashboard/public`. The live log refresh uses `?ajax=logs` every 2 seconds and a manual refresh button.
