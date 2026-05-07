"""Tests for the Preprocessor class — comment stripping, line mapping,
loop/function body extraction."""
import pytest
from cpu_load_optimizer import Preprocessor


class TestStripComments:

    def test_single_line_comment_removed(self):
        src = "int x = 5; // this should disappear\n"
        cleaned, _ = Preprocessor.strip_comments(src)
        assert "//" not in cleaned
        assert "int x = 5;" in cleaned

    def test_multi_line_comment_removed(self):
        src = "/* block\ncomment */\nint x;\n"
        cleaned, _ = Preprocessor.strip_comments(src)
        assert "block" not in cleaned
        assert "comment" not in cleaned
        assert "int x;" in cleaned

    def test_code_after_single_line_comment_not_included(self):
        src = "int x = 1; // int y = 2;\n"
        cleaned, _ = Preprocessor.strip_comments(src)
        assert "int y" not in cleaned

    def test_inline_block_comment_removed(self):
        src = "int x /* foo */ = 5;\n"
        cleaned, _ = Preprocessor.strip_comments(src)
        assert "foo" not in cleaned
        assert "int x" in cleaned

    def test_multi_line_comment_preserves_newlines(self):
        # Newlines inside the comment must still produce blank lines so
        # subsequent line numbers stay aligned with the original.
        src = "int a;\n/* line1\nline2\nline3 */\nint b;\n"
        cleaned, _ = Preprocessor.strip_comments(src)
        # a and b must still be present
        assert "int a;" in cleaned
        assert "int b;" in cleaned
        # The three internal newlines should keep 'int b;' on line 5
        assert cleaned.count("\n") == src.count("\n")

    def test_comment_lookalike_inside_string_preserved(self):
        src = 'char *s = "/* not a comment */";\n'
        cleaned, _ = Preprocessor.strip_comments(src)
        assert "/* not a comment */" in cleaned

    def test_double_slash_url_inside_string_preserved(self):
        src = 'const char *url = "http://example.com";\n'
        cleaned, _ = Preprocessor.strip_comments(src)
        assert "http://example.com" in cleaned

    def test_escaped_quote_in_string_not_end_of_string(self):
        # The \" inside the string should not terminate it, so the
        # trailing comment must still be stripped.
        src = 'char *s = "say \\"hello\\""; // comment\n'
        cleaned, _ = Preprocessor.strip_comments(src)
        assert "comment" not in cleaned
        assert "hello" in cleaned

    def test_empty_source_returns_empty(self):
        cleaned, line_map = Preprocessor.strip_comments("")
        assert cleaned == ""

    def test_only_comments_leaves_blank_lines(self):
        src = "// comment\n/* block */\n"
        cleaned, _ = Preprocessor.strip_comments(src)
        assert cleaned.strip() == ""

    def test_adjacent_block_comments_both_removed(self):
        src = "int x; /* c1 */ /* c2 */ int y;\n"
        cleaned, _ = Preprocessor.strip_comments(src)
        assert "c1" not in cleaned
        assert "c2" not in cleaned
        assert "int x;" in cleaned
        assert "int y;" in cleaned

    def test_single_line_comment_at_start_of_line(self):
        src = "// entire line is a comment\nint z = 0;\n"
        cleaned, _ = Preprocessor.strip_comments(src)
        assert "entire line" not in cleaned
        assert "int z = 0;" in cleaned

    def test_nested_comment_look_alike_not_supported(self):
        # C does not support nested block comments; the first */ ends it.
        src = "/* outer /* inner */ still_comment\nint x;\n"
        cleaned, _ = Preprocessor.strip_comments(src)
        assert "outer" not in cleaned
        assert "inner" not in cleaned
        # "still_comment" depends on implementation; just check no crash.

    def test_line_map_built(self):
        src = "int a;\n// skip\nint b;\n"
        _, line_map = Preprocessor.strip_comments(src)
        assert isinstance(line_map, dict)
        assert len(line_map) > 0

    def test_line_map_values_are_original_line_numbers(self):
        src = "// skipped\nint x;\n// skipped\nint y;\n"
        _, line_map = Preprocessor.strip_comments(src)
        # All mapped-to values must be valid 1-based line numbers
        assert all(v >= 1 for v in line_map.values())

    def test_single_char_source(self):
        cleaned, _ = Preprocessor.strip_comments("x")
        assert cleaned == "x"

    def test_windows_crlf_handled(self):
        src = "int x;\r\n// comment\r\nint y;\r\n"
        cleaned, _ = Preprocessor.strip_comments(src)
        assert "int x;" in cleaned
        assert "int y;" in cleaned


class TestGetContext:

    LINES = ["alpha", "beta", "gamma", "delta", "epsilon"]

    def test_middle_line_has_marker(self):
        ctx = Preprocessor.get_context(self.LINES, 2)
        assert ">>>" in ctx
        assert "gamma" in ctx

    def test_surrounding_lines_included(self):
        ctx = Preprocessor.get_context(self.LINES, 2)
        assert "alpha" in ctx
        assert "epsilon" in ctx

    def test_first_line_no_crash(self):
        ctx = Preprocessor.get_context(self.LINES, 0)
        assert ">>>" in ctx
        assert "alpha" in ctx

    def test_last_line_no_crash(self):
        ctx = Preprocessor.get_context(self.LINES, 4)
        assert ">>>" in ctx
        assert "epsilon" in ctx

    def test_custom_window_size(self):
        ctx = Preprocessor.get_context(self.LINES, 2, window=1)
        assert "beta" in ctx
        assert "gamma" in ctx
        assert "delta" in ctx
        # With window=1, "alpha" and "epsilon" should be outside range
        assert "alpha" not in ctx
        assert "epsilon" not in ctx

    def test_single_line_source(self):
        ctx = Preprocessor.get_context(["only"], 0)
        assert "only" in ctx

    def test_empty_source_no_crash(self):
        ctx = Preprocessor.get_context([], 0)
        assert ctx == ""


class TestFindLoopBodies:

    def test_finds_for_loop(self):
        src = "for (int i = 0; i < 10; i++) {\n  x++;\n}\n"
        loops = Preprocessor.find_loop_bodies(src)
        assert len(loops) >= 1

    def test_finds_while_loop(self):
        src = "while (running) {\n  process();\n}\n"
        loops = Preprocessor.find_loop_bodies(src)
        assert len(loops) >= 1

    def test_nested_loops_both_detected(self):
        src = (
            "for (int i = 0; i < N; i++) {\n"
            "  for (int j = 0; j < M; j++) {\n"
            "    work();\n"
            "  }\n"
            "}\n"
        )
        loops = Preprocessor.find_loop_bodies(src)
        assert len(loops) >= 2

    def test_empty_source_returns_empty(self):
        assert Preprocessor.find_loop_bodies("") == []

    def test_no_loops_returns_empty(self):
        src = "int x = 5;\nreturn x;\n"
        assert Preprocessor.find_loop_bodies(src) == []

    def test_loop_start_end_tuple_order(self):
        src = "for (int i = 0; i < 3; i++) {\n  x++;\n}\n"
        loops = Preprocessor.find_loop_bodies(src)
        assert len(loops) >= 1
        start, end, body = loops[0]
        assert start <= end

    def test_loop_body_content_captured(self):
        src = "for (int i = 0; i < 3; i++) {\n  sqrt(x);\n}\n"
        loops = Preprocessor.find_loop_bodies(src)
        assert len(loops) >= 1
        _, _, body = loops[0]
        assert "sqrt" in body


class TestFindFunctionBodies:

    def test_finds_simple_function(self):
        src = "void myFunc(int x) {\n  return;\n}\n"
        funcs = Preprocessor.find_function_bodies(src)
        assert any(f["name"] == "myFunc" for f in funcs)

    def test_skips_control_keywords(self):
        src = "if (x > 0) {\n  y++;\n}\n"
        funcs = Preprocessor.find_function_bodies(src)
        assert not any(f["name"] == "if" for f in funcs)

    def test_skips_for_while(self):
        src = "for (int i = 0; i < 10; i++) {\n  x++;\n}\n"
        funcs = Preprocessor.find_function_bodies(src)
        assert not any(f["name"] == "for" for f in funcs)

    def test_multiple_functions_detected(self):
        src = (
            "void foo(void) {\n  return;\n}\n"
            "int bar(int x) {\n  return x;\n}\n"
        )
        funcs = Preprocessor.find_function_bodies(src)
        names = {f["name"] for f in funcs}
        assert "foo" in names
        assert "bar" in names

    def test_empty_source_returns_empty(self):
        assert Preprocessor.find_function_bodies("") == []

    def test_function_dict_has_required_keys(self):
        src = "void check(void) {\n  return;\n}\n"
        funcs = Preprocessor.find_function_bodies(src)
        assert len(funcs) >= 1
        f = funcs[0]
        assert "name" in f
        assert "start" in f
        assert "end" in f
        assert "body" in f
