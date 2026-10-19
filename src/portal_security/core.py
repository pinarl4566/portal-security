from __future__ import annotations

import re
from typing import Dict, List

import sys
if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    TypedDict = dict


class CspPolicy(TypedDict):
    """Structured representation of a parsed Content-Security-Policy header.

    Keys are directive names normalized to lower case with dashes (e.g.
    "default-src"). Values are lists of source tokens in original order.
    """


_DIRECTIVE_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")

_SPECIAL_SOURCE_KEYWORDS = frozenset(
    {
        "'self'",
        "'none'",
        "'strict-dynamic'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'unsafe-hashes'",
        "'wasm-unsafe-eval'",
    }
)


def normalize_directive_name(raw: str) -> str:
    """Lower-case a directive name and strip leading/trailing whitespace.

    The CSP spec defines directive names case-insensitively, so we normalize to
    lower case once, up front, instead of on every lookup.
    """
    if not isinstance(raw, str):
        raise TypeError(f"directive name must be str, not {type(raw).__name__}")
    name = raw.strip().lower()
    if not name or not _DIRECTIVE_NAME_RE.match(name):
        raise ValueError(f"invalid directive name: {raw!r}")
    return name


def is_special_keyword(token: str) -> bool:
    """Return True if *token* is a CSP source keyword like 'self' or 'none'.

    These tokens are defined by the spec and never carry a scheme, host, or path,
    so they are matched literally (case-insensitively).
    """
    if not isinstance(token, str):
        raise TypeError(f"token must be str, not {type(token).__name__}")
    return token.strip().lower() in _SPECIAL_SOURCE_KEYWORDS


def _tokenize_policy(header: str) -> List[List[str]]:
    """Split a raw CSP header into a list of [directive, source, source, ...].

    A policy is a semicolon-delimited list of directives. We deliberately do
    not strip whitespace *inside* source tokens: per RFC 6454 and the CSP fetch
    spec, source expressions must not contain whitespace, so an interior space
    is treated as a token boundary, not preserved as part of a URL.
    """
    if not isinstance(header, str):
        raise TypeError(f"header must be str, not {type(header).__name__}")
    directives: List[List[str]] = []
    for segment in header.split(";"):
        segment = segment.strip()
        if not segment:
            continue
        tokens = segment.split()
        if not tokens:
            continue
        directives.append(tokens)
    return directives


def parse_policy(header: str) -> Dict[str, List[str]]:
    """Parse a Content-Security-Policy *header* into a mapping.

    Returns a dict whose keys are directive names (lower-case, dashes intact)
    and whose values are lists of source tokens, in the order they appeared.

    We deliberately model the output as a plain ``Dict[str, List[str]]`` rather
    than a richer AST because the library's scope is *parsing*: it answers
    "what did the server say?", not "is this policy secure?". A consumer who
    needs to reason about hosts, schemes, or wildcards can do so by inspecting
    the token strings directly; doing that interpretation here would force us to
    take a position on questions the spec leaves to callers (e.g. whether
    ``https:`` and ``https://*`` should be considered equivalent).

    Ambiguity resolved (see README): when the same directive name appears more
    than once in a single header, the CSP spec says only the *first* occurrence
    is honored and subsequent ones must be ignored. We implement that rule
    strictly — duplicates are dropped, not merged.
    """
    policy: Dict[str, List[str]] = {}
    for tokens in _tokenize_policy(header):
        raw_name = tokens[0]
        name = normalize_directive_name(raw_name)
        if name in policy:
            continue
        policy[name] = list(tokens[1:])
    return policy
