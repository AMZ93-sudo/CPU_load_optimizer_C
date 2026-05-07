"""Integration tests for run_analysis() and discover_files()."""
import os
from unittest.mock import patch

import pytest

from conftest import write_c, rule_ids
from cpu_load_optimizer import (
    Severity,
    discover_files,
    run_analysis,
)


# ─────────────────────────────────────────────────────────────────────────────
# discover_files
# ─────────────────────────────────────────────────────────────────────────────

class TestDiscoverFiles:

    def test_single_c_file(self, tmp_dir):
        path = write_c(tmp_dir, "main.c", "")
        assert discover_files(path) == [path]

    def test_single_h_file(self, tmp_dir):
        path = os.path.join(tmp_dir, "header.h")
        open(path, "w").close()
        assert discover_files(path) == [path]

    def test_non_c_h_file_returns_empty(self, tmp_dir):
        path = os.path.join(tmp_dir, "script.py")
        open(path, "w").close()
        result = discover_files(path)
        assert result == []

    def test_directory_finds_c_and_h_files(self, tmp_dir):
        c = write_c(tmp_dir, "main.c", "")
        h = os.path.join(tmp_dir, "main.h")
        open(h, "w").close()
        py = os.path.join(tmp_dir, "script.py")
        open(py, "w").close()
        result = discover_files(tmp_dir)
        assert c in result
        assert h in result
        assert py not in result

    def test_directory_recursive_search(self, tmp_dir):
        subdir = os.path.join(tmp_dir, "src", "drivers")
        os.makedirs(subdir)
        nested = write_c(subdir, "uart.c", "")
        result = discover_files(tmp_dir)
        assert nested in result

    def test_empty_directory_returns_empty(self, tmp_dir):
        assert discover_files(tmp_dir) == []

    def test_nonexistent_path_returns_empty(self, tmp_dir):
        missing = os.path.join(tmp_dir, "does_not_exist.c")
        result = discover_files(missing)
        assert result == []

    def test_result_is_sorted(self, tmp_dir):
        write_c(tmp_dir, "zzz.c", "")
        write_c(tmp_dir, "aaa.c", "")
        result = discover_files(tmp_dir)
        assert result == sorted(result)

    def test_multiple_c_files_in_directory(self, tmp_dir):
        for name in ["a.c", "b.c", "c.c"]:
            write_c(tmp_dir, name, "")
        result = discover_files(tmp_dir)
        assert len(result) == 3

    def test_mixed_depths_all_found(self, tmp_dir):
        top = write_c(tmp_dir, "top.c", "")
        sub = os.path.join(tmp_dir, "sub")
        os.makedirs(sub)
        deep = write_c(sub, "deep.c", "")
        result = discover_files(tmp_dir)
        assert top in result
        assert deep in result


# ─────────────────────────────────────────────────────────────────────────────
# run_analysis — basic operation
# ─────────────────────────────────────────────────────────────────────────────

class TestRunAnalysisBasic:

    def _out(self, tmp_dir, name="report.html"):
        return os.path.join(tmp_dir, "Output", name)

    def test_empty_file_zero_findings(self, tmp_dir):
        path = write_c(tmp_dir, "empty.c", "")
        result = run_analysis([path], self._out(tmp_dir))
        assert result["total_findings"] == 0

    def test_findings_counted_correctly(self, tmp_dir):
        # Three separate CRITICAL issues
        src = "float a = 1;\nfloat b = 2;\nfloat c = 3;\n"
        path = write_c(tmp_dir, "test.c", src)
        result = run_analysis([path], self._out(tmp_dir))
        assert result["total_findings"] >= 3

    def test_return_dict_has_required_keys(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "")
        result = run_analysis([path], self._out(tmp_dir))
        for key in ("total_findings", "findings", "report_path", "by_severity", "mode"):
            assert key in result, f"Missing key: {key}"

    def test_mode_is_full_file(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "")
        result = run_analysis([path], self._out(tmp_dir))
        assert "Full File" in result["mode"] or "full" in result["mode"].lower()

    def test_report_html_created(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "float x = 5;\n")
        result = run_analysis([path], self._out(tmp_dir))
        assert os.path.isfile(result["report_path"])

    def test_report_html_valid_content(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "float x = 5;\n")
        result = run_analysis([path], self._out(tmp_dir))
        with open(result["report_path"], encoding="utf-8") as fh:
            content = fh.read()
        assert "<html" in content.lower()

    def test_output_dir_created_automatically(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "float x = 5;\n")
        deep_out = os.path.join(tmp_dir, "a", "b", "c", "report.html")
        result = run_analysis([path], deep_out)
        assert os.path.isfile(result["report_path"])

    def test_multiple_files_all_findings_included(self, tmp_dir):
        p1 = write_c(tmp_dir, "a.c", "float a = 1;\n")
        p2 = write_c(tmp_dir, "b.c", "void *p = malloc(10);\n")
        result = run_analysis([p1, p2], self._out(tmp_dir))
        file_paths = {f.file_path for f in result["findings"]}
        assert p1 in file_paths
        assert p2 in file_paths

    def test_by_severity_dict_populated(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "float x = 5;\nvoid *p = malloc(10);\n")
        result = run_analysis([path], self._out(tmp_dir))
        assert result["by_severity"].get("CRITICAL", 0) >= 2

    def test_findings_list_in_result(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "float x = 5;\n")
        result = run_analysis([path], self._out(tmp_dir))
        assert isinstance(result["findings"], list)

    def test_llm_export_none_when_not_requested(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "float x = 5;\n")
        result = run_analysis([path], self._out(tmp_dir), llm_export=False)
        assert result["llm_export_paths"] is None

    def test_llm_export_creates_six_files(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "float x = 5;\n")
        result = run_analysis([path], self._out(tmp_dir), llm_export=True)
        assert result["llm_export_paths"] is not None
        assert len(result["llm_export_paths"]) == 6
        for p in result["llm_export_paths"]:
            assert os.path.isfile(p), f"LLM export file missing: {p}"


# ─────────────────────────────────────────────────────────────────────────────
# run_analysis — severity filtering
# ─────────────────────────────────────────────────────────────────────────────

class TestRunAnalysisSeverity:

    def _out(self, tmp_dir):
        return os.path.join(tmp_dir, "Output", "report.html")

    def test_min_critical_filters_lower_severities(self, tmp_dir):
        src = "float speed = 5;\n"   # CRITICAL
        path = write_c(tmp_dir, "test.c", src)
        result = run_analysis([path], self._out(tmp_dir), min_severity="critical")
        for f in result["findings"]:
            assert f.severity == Severity.CRITICAL

    def test_min_high_includes_critical(self, tmp_dir):
        src = "float speed = 5;\nvoid *p = malloc(10);\n"
        path = write_c(tmp_dir, "test.c", src)
        result = run_analysis([path], self._out(tmp_dir), min_severity="high")
        assert any(f.severity == Severity.CRITICAL for f in result["findings"])

    def test_min_low_includes_everything(self, tmp_dir):
        src = "float speed = 5;\nextern uint32_t g;\n"
        path = write_c(tmp_dir, "test.c", src)
        result = run_analysis([path], self._out(tmp_dir), min_severity="low")
        sevs = {f.severity for f in result["findings"]}
        assert len(sevs) >= 2


# ─────────────────────────────────────────────────────────────────────────────
# run_analysis — staged mode
# ─────────────────────────────────────────────────────────────────────────────

class TestRunAnalysisStagedMode:

    def _out(self, tmp_dir):
        return os.path.join(tmp_dir, "Output", "staged.html")

    def test_staged_lines_filter_keeps_only_staged(self, tmp_dir):
        # Two CRITICAL findings on lines 1 and 2; only line 1 is "staged"
        src = "float a = 1;\nfloat b = 2;\n"
        path = write_c(tmp_dir, "test.c", src)
        staged_lines = {path: {1}}
        result = run_analysis(
            [path], self._out(tmp_dir),
            staged_mode=True, staged_lines=staged_lines,
        )
        assert all(f.line_number == 1 for f in result["findings"])

    def test_staged_lines_empty_set_zero_findings(self, tmp_dir):
        src = "float a = 1;\nfloat b = 2;\n"
        path = write_c(tmp_dir, "test.c", src)
        staged_lines = {path: set()}
        result = run_analysis(
            [path], self._out(tmp_dir),
            staged_mode=True, staged_lines=staged_lines,
        )
        assert result["total_findings"] == 0

    def test_staged_mode_without_staged_lines_returns_all(self, tmp_dir):
        src = "float a = 1;\nfloat b = 2;\n"
        path = write_c(tmp_dir, "test.c", src)
        result = run_analysis(
            [path], self._out(tmp_dir),
            staged_mode=True, staged_lines=None,
        )
        assert result["total_findings"] >= 2

    def test_staged_mode_mode_string(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "")
        result = run_analysis([path], self._out(tmp_dir), staged_mode=True)
        assert "Staged" in result["mode"] or "staged" in result["mode"].lower()

    def test_staged_mode_with_repo_path_reads_staged_content(self, tmp_dir):
        # Patch GitAnalyzer.get_staged_content so we don't need a real git repo
        src = "float x = 5;\n"
        path = write_c(tmp_dir, "test.c", src)
        fake_repo = tmp_dir

        with patch(
            "cpu_load_optimizer.GitAnalyzer.get_staged_content",
            return_value=src,
        ):
            result = run_analysis(
                [path], self._out(tmp_dir),
                staged_mode=True, repo_path=fake_repo,
            )
        assert result["total_findings"] >= 1

    def test_staged_mode_skips_file_when_staged_content_none(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "float x = 5;\n")
        with patch(
            "cpu_load_optimizer.GitAnalyzer.get_staged_content",
            return_value=None,
        ):
            result = run_analysis(
                [path], self._out(tmp_dir),
                staged_mode=True, repo_path=tmp_dir,
            )
        assert result["total_findings"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# run_analysis — edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestRunAnalysisEdgeCases:

    def _out(self, tmp_dir, name="report.html"):
        return os.path.join(tmp_dir, "Output", name)

    def test_log_callback_called(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "float x = 5;\n")
        messages = []
        run_analysis([path], self._out(tmp_dir), log_callback=messages.append)
        assert len(messages) > 0

    def test_file_with_only_comments_zero_findings(self, tmp_dir):
        src = "// entire file is comments\n/* block comment */\n"
        path = write_c(tmp_dir, "test.c", src)
        result = run_analysis([path], self._out(tmp_dir))
        assert result["total_findings"] == 0

    def test_unicode_source_file_no_crash(self, tmp_dir):
        src = "// こんにちは\nfloat x = 5;\n"
        path = write_c(tmp_dir, "test.c", src)
        result = run_analysis([path], self._out(tmp_dir))
        assert result["total_findings"] >= 1

    def test_no_findings_report_still_created(self, tmp_dir):
        path = write_c(tmp_dir, "clean.c", "")
        result = run_analysis([path], self._out(tmp_dir))
        assert os.path.isfile(result["report_path"])

    def test_large_file_no_crash(self, tmp_dir):
        # ~1000 lines with mixed patterns
        src = "float x = 5;\n" * 200 + "int ok = 0;\n" * 800
        path = write_c(tmp_dir, "big.c", src)
        result = run_analysis([path], self._out(tmp_dir))
        assert result["total_findings"] >= 200

    def test_findings_are_sorted_by_severity_desc(self, tmp_dir):
        src = "float speed = 5;\nvoid *p = malloc(10);\nint x = 5;\n"
        path = write_c(tmp_dir, "test.c", src)
        result = run_analysis([path], self._out(tmp_dir))
        sevs = [f.severity for f in result["findings"]]
        assert sevs == sorted(sevs, reverse=True)

    def test_report_contains_rule_id(self, tmp_dir):
        path = write_c(tmp_dir, "test.c", "float x = 5;\n")
        result = run_analysis([path], self._out(tmp_dir))
        with open(result["report_path"], encoding="utf-8") as fh:
            html = fh.read()
        assert "C01" in html

    def test_bad_file_path_does_not_crash(self, tmp_dir):
        missing = os.path.join(tmp_dir, "nonexistent.c")
        result = run_analysis([missing], self._out(tmp_dir))
        # Should handle the error gracefully
        assert "total_findings" in result
