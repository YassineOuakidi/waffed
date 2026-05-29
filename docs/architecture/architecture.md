# Overall Architecture:

# Overall Architecture:

```
[ EPOLLIN EVENT: Read Buffer from Socket ]
        |
        v
[ 1. DEEP NORMALIZATION ] 
  (while-loop URL decodes until byte size is static)
        |
        v
[ 2. AHO-CORASICK PRE-FILTER ]
  (O(n) scan. Accumulates anomaly score based on weighted tokens)
        |
        +-- [Score < 100] ---> [ ROUTE TO BACKEND (Safe) ]
        |
        +-- [Score >= 100] --+
        |
        v
[ 3. THE STATE-MACHINE (DFA) ]
(Reads the buffer byte-by-byte to build an AST.
Checks if the string actually forms valid SQL/XSS logic)
        |
        +-- [Returns TRUE] ---> [ 403 FORBIDDEN (Blocked) ]
        |
        +-- [Returns FALSE] --+
        |
        v
[ 4. PCRE2 FALLBACK ]
(Runs only for protocol anomalies, 
header checks, or non-syntax rules)
        |
        +-- [Regex Match] -> [ 403 FORBIDDEN ]
        |
        +-- [No Match] ----> [ ROUTE TO BACKEND ]
```

