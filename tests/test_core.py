import unittest

from portal_security import parse_policy, normalize_directive_name, is_special_keyword


class TestParsePolicy(unittest.TestCase):
    def test_single_directive_single_source(self):
        result = parse_policy("default-src 'self'")
        self.assertEqual(result, {"default-src": ["'self'"]})

    def test_multiple_directives(self):
        result = parse_policy("default-src 'none'; script-src 'self'")
        self.assertEqual(
            result,
            {"default-src": ["'none'"], "script-src": ["'self'"]},
        )

    def test_multiple_sources_preserve_order(self):
        result = parse_policy("script-src 'self' https://cdn.example 'unsafe-inline'")
        self.assertEqual(
            result,
            {"script-src": ["'self'", "https://cdn.example", "'unsafe-inline'"]},
        )

    def test_empty_string_returns_empty_dict(self):
        self.assertEqual(parse_policy(""), {})

    def test_whitespace_only_returns_empty_dict(self):
        self.assertEqual(parse_policy("   \t  "), {})

    def test_repeated_semicolons_are_ignored(self):
        # Extra semicolons produce empty segments, which are skipped.
        result = parse_policy("default-src 'none';;script-src 'self'")
        self.assertEqual(result, {"default-src": ["'none'"], "script-src": ["'self'"]})

    def test_directive_with_no_sources_yields_empty_list(self):
        # A directive name with no following sources is syntactically valid and
        # means "no sources".
        result = parse_policy("upgrade-insecure-requests")
        self.assertEqual(result, {"upgrade-insecure-requests": []})

    def test_duplicate_directive_keeps_first_only(self):
        # Per CSP spec, only the first occurrence of a directive is honored.
        result = parse_policy(
            "script-src 'self'; script-src https://evil.example 'unsafe-inline'"
        )
        self.assertEqual(result, {"script-src": ["'self'"]})

    def test_case_insensitive_directive_names_normalized(self):
        result = parse_policy("DEFAULT-SRC 'self'; Script-Src 'none'")
        self.assertEqual(result, {"default-src": ["'self'"], "script-src": ["'none'"]})

    def test_extra_whitespace_around_tokens_is_stripped(self):
        result = parse_policy("  default-src    'self'   https://cdn.example  ")
        self.assertEqual(
            result,
            {"default-src": ["'self'", "https://cdn.example"]},
        )

    def test_non_string_input_raises_type_error(self):
        with self.assertRaises(TypeError):
            parse_policy(123)  # type: ignore[arg-type]


class TestNormalizeDirectiveName(unittest.TestCase):
    def test_lowercases_and_strips(self):
        self.assertEqual(normalize_directive_name("  DEFAULT-SRC "), "default-src")

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            normalize_directive_name("")

    def test_rejects_leading_dash(self):
        with self.assertRaises(ValueError):
            normalize_directive_name("-src")

    def test_rejects_non_string(self):
        with self.assertRaises(TypeError):
            normalize_directive_name(None)  # type: ignore[arg-type]


class TestIsSpecialKeyword(unittest.TestCase):
    def test_self_is_special(self):
        self.assertTrue(is_special_keyword("'self'"))

    def test_none_is_special(self):
        self.assertTrue(is_special_keyword("'none'"))

    def test_strict_dynamic_is_special(self):
        self.assertTrue(is_special_keyword("'strict-dynamic'"))

    def test_url_is_not_special(self):
        self.assertFalse(is_special_keyword("https://cdn.example"))

    def test_case_insensitive(self):
        self.assertTrue(is_special_keyword("'SELF'"))


if __name__ == "__main__":
    unittest.main()
