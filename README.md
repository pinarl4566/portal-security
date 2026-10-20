# portal-security

Parse an HTTP `Content-Security-Policy` header into a structured mapping of directive names to source token lists.

## Usage

```python
from portal_security import parse_policy, is_special_keyword

policy = parse_policy("default-src 'self'; script-src 'self' https://cdn.example 'unsafe-inline'")
print(policy["default-src"])   # ["'self'"]
print(policy["script-src"])    # ["'self'", "https://cdn.example", "'unsafe-inline'"]

for source in policy["script-src"]:
    if is_special_keyword(source):
        print(f"{source} is a CSP keyword")
```

The exported names are `parse_policy`, `normalize_directive_name`, and `is_special_keyword`.

## Why

Reading a CSP header off the wire and reasoning about it — for logging, auditing, or building a report-only dashboard — means dealing with semicolons, optional whitespace, case-insensitive directive names, and directives that carry no sources. This library exists to do exactly that parsing once, deterministically, with no third-party dependencies.

The trade-off: this library stops at *parsing*. It does not interpret hosts, schemes, or wildcards, and it does not decide whether two policies are "equivalent." If you need that, do it on the parsed output; encoding those rules here would force callers to adopt a specific notion of equivalence that the spec deliberately leaves open.

## Edge cases

- **Duplicate directives:** per the CSP spec, when a directive name appears more than once in a single header, only the *first* occurrence is kept and subsequent ones are ignored. This library implements that rule strictly — duplicates are dropped, not merged.
- **Source order:** tokens within a directive are preserved exactly as they appeared, including duplicates. The library does not sort or deduplicate.
- **Directives with no sources:** a bare directive name (e.g. `upgrade-insecure-requests`) parses to an empty source list.
- **Non-ASCII / non-string input:** `parse_policy` raises `TypeError` if given non-string input, and `normalize_directive_name` raises `ValueError` on malformed directive names.
