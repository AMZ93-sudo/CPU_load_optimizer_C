"""Tests for ReportGenerator (CPU reduction estimates, HTML output)
and GitAnalyzer (using the live repo in /home/user/CPU_load_optimizer_C)."""
import os

import pytest

from conftest import make_finding
from cpu_load_optimizer import (
    GitAnalyzer,
    ReportGenerator,
    Severity,
)

REPO_PATH = "/home/user/CPU_load_optimizer_C"


# ─────────────────────────────────────────────────────────────────────────────
# ReportGenerator — CPU reduction estimates
# ─────────────────────────────────────────────────────────────────────────────

class TestCpuReductionEstimate:

    # The method returns:
    #   {"CRITICAL": {"count":…, "min_pct":…, "max_pct":…, "raw_pct":…},
    #    …, "TOTAL": {"min_pct":…, "max_pct":…}}

    def test_empty_findings_zero_reduction(self):
        result = ReportGenerator.estimate_cpu_reduction([])
        assert result["TOTAL"]["min_pct"] == 0.0
        assert result["TOTAL"]["max_pct"] == 0.0

    def test_single_critical_finding_positive_reduction(self):
        f = make_finding("C01", severity=Severity.CRITICAL, impact_score=90)
        result = ReportGenerator.estimate_cpu_reduction([f])
        assert result["TOTAL"]["max_pct"] > 0.0
        assert result["TOTAL"]["min_pct"] >= 0.0

    def test_min_less_than_or_equal_max(self):
        findings = [make_finding("C02", severity=Severity.CRITICAL, impact_score=85)]
        result = ReportGenerator.estimate_cpu_reduction(findings)
        assert result["TOTAL"]["min_pct"] <= result["TOTAL"]["max_pct"]

    def test_total_capped_at_thirty_percent(self):
        # Flood with many critical findings — total must stay ≤ 30 %
        findings = [
            make_finding(f"C0{i % 6 + 1}", severity=Severity.CRITICAL, impact_score=90)
            for i in range(50)
        ]
        result = ReportGenerator.estimate_cpu_reduction(findings)
        assert result["TOTAL"]["max_pct"] <= 30.0

    def test_low_severity_contributes_less_than_critical(self):
        critical_f = make_finding("C01", severity=Severity.CRITICAL, impact_score=90)
        low_f = make_finding("L01", severity=Severity.LOW, impact_score=20)
        r_crit = ReportGenerator.estimate_cpu_reduction([critical_f])
        r_low = ReportGenerator.estimate_cpu_reduction([low_f])
        assert r_crit["TOTAL"]["max_pct"] >= r_low["TOTAL"]["max_pct"]

    def test_per_severity_keys_present(self):
        f = make_finding("C01", severity=Severity.CRITICAL, impact_score=90)
        result = ReportGenerator.estimate_cpu_reduction([f])
        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "TOTAL"):
            assert key in result

    def test_unknown_rule_id_does_not_crash(self):
        f = make_finding("X99", severity=Severity.HIGH, impact_score=50)
        result = ReportGenerator.estimate_cpu_reduction([f])
        assert result["TOTAL"]["max_pct"] >= 0.0

    def test_mixed_severities_accumulate(self):
        findings = [
            make_finding("C01", severity=Severity.CRITICAL, impact_score=90),
            make_finding("H01", severity=Severity.HIGH, impact_score=70),
            make_finding("M03", severity=Severity.MEDIUM, impact_score=50),
        ]
        mixed = ReportGenerator.estimate_cpu_reduction(findings)
        single = ReportGenerator.estimate_cpu_reduction([findings[0]])
        assert mixed["TOTAL"]["max_pct"] >= single["TOTAL"]["max_pct"]


# ─────────────────────────────────────────────────────────────────────────────
# ReportGenerator — HTML output
# ─────────────────────────────────────────────────────────────────────────────

class TestReportGeneratorHtml:

    def test_creates_file(self, tmp_dir):
        out = os.path.join(tmp_dir, "report.html")
        path = ReportGenerator.generate([make_finding()], ["test.c"], None, out)
        assert os.path.isfile(path)

    def test_returns_output_path(self, tmp_dir):
        out = os.path.join(tmp_dir, "report.html")
        path = ReportGenerator.generate([], ["test.c"], None, out)
        assert path == out

    def test_html_contains_doctype(self, tmp_dir):
        out = os.path.join(tmp_dir, "report.html")
        ReportGenerator.generate([make_finding()], ["test.c"], None, out)
        with open(out, encoding="utf-8") as fh:
            content = fh.read()
        assert "<!DOCTYPE html>" in content or "<html" in content.lower()

    def test_html_contains_rule_id(self, tmp_dir):
        out = os.path.join(tmp_dir, "report.html")
        ReportGenerator.generate([make_finding("C01")], ["test.c"], None, out)
        with open(out, encoding="utf-8") as fh:
            content = fh.read()
        assert "C01" in content

    def test_html_contains_severity_label(self, tmp_dir):
        out = os.path.join(tmp_dir, "report.html")
        f = make_finding("C01", severity=Severity.CRITICAL)
        ReportGenerator.generate([f], ["test.c"], None, out)
        with open(out, encoding="utf-8") as fh:
            content = fh.read()
        assert "CRITICAL" in content

    def test_zero_findings_report_still_valid(self, tmp_dir):
        out = os.path.join(tmp_dir, "report.html")
        path = ReportGenerator.generate([], ["test.c"], None, out)
        assert os.path.isfile(path)
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        assert len(content) > 100

    def test_multiple_findings_all_in_report(self, tmp_dir):
        out = os.path.join(tmp_dir, "report.html")
        findings = [make_finding("C01"), make_finding("C06"), make_finding("H02")]
        ReportGenerator.generate(findings, ["test.c"], None, out)
        with open(out, encoding="utf-8") as fh:
            content = fh.read()
        assert "C01" in content
        assert "C06" in content
        assert "H02" in content

    def test_html_contains_file_name(self, tmp_dir):
        out = os.path.join(tmp_dir, "report.html")
        f = make_finding("C01")
        f = f.__class__(
            **{**f.__dict__, "file_path": "/some/path/mymodule.c"}
        )
        ReportGenerator.generate([f], ["/some/path/mymodule.c"], None, out)
        with open(out, encoding="utf-8") as fh:
            content = fh.read()
        assert "mymodule" in content


# ─────────────────────────────────────────────────────────────────────────────
# GitAnalyzer — tests against the live repository
# ─────────────────────────────────────────────────────────────────────────────

class TestGitAnalyzer:

    def test_is_git_repo_true_for_live_repo(self):
        assert GitAnalyzer.is_git_repo(REPO_PATH) is True

    def test_is_git_repo_false_for_tmp(self, tmp_dir):
        assert GitAnalyzer.is_git_repo(tmp_dir) is False

    def test_is_git_repo_false_for_nonexistent(self, tmp_dir):
        assert GitAnalyzer.is_git_repo(os.path.join(tmp_dir, "ghost")) is False

    def test_get_repo_root_returns_path(self):
        root = GitAnalyzer.get_repo_root(REPO_PATH)
        assert root is not None
        assert os.path.isdir(root)

    def test_get_repo_root_subdir_still_finds_root(self):
        subdir = os.path.join(REPO_PATH, "__pycache__")
        if os.path.isdir(subdir):
            root = GitAnalyzer.get_repo_root(subdir)
            assert root is not None

    def test_get_repo_root_none_for_non_repo(self, tmp_dir):
        assert GitAnalyzer.get_repo_root(tmp_dir) is None

    def test_get_staged_files_returns_list(self):
        result = GitAnalyzer.get_staged_files(REPO_PATH)
        assert isinstance(result, list)

    def test_get_staged_files_only_c_h(self):
        result = GitAnalyzer.get_staged_files(REPO_PATH)
        for f in result:
            assert f.endswith(".c") or f.endswith(".h"), \
                f"Non-.c/.h file in staged list: {f}"

    def test_get_staged_line_numbers_returns_set(self):
        # Use a known .c file in the repo; staged lines may be empty
        # if nothing is staged — that is fine.
        result = GitAnalyzer.get_staged_line_numbers(REPO_PATH, "bad_example.c")
        assert isinstance(result, set)

    def test_get_staged_line_numbers_all_positive(self):
        result = GitAnalyzer.get_staged_line_numbers(REPO_PATH, "bad_example.c")
        assert all(n > 0 for n in result)

    def test_get_staged_content_known_file(self):
        # cpu_load_optimizer.py exists; if not staged, returns None — acceptable.
        content = GitAnalyzer.get_staged_content(REPO_PATH, "cpu_load_optimizer.py")
        assert content is None or isinstance(content, str)

    def test_get_staged_summary_structure(self):
        # With no staged files the summary should still have expected keys.
        staged = GitAnalyzer.get_staged_files(REPO_PATH)
        summary = GitAnalyzer.get_staged_summary(REPO_PATH, staged)
        assert "total_files" in summary
        assert "files" in summary
        assert "total_changed_lines" in summary

    def test_get_staged_summary_total_files_matches(self):
        staged = GitAnalyzer.get_staged_files(REPO_PATH)
        summary = GitAnalyzer.get_staged_summary(REPO_PATH, staged)
        assert summary["total_files"] == len(staged)

    def test_get_staged_line_numbers_non_existent_file(self):
        # A file not in the repo should return an empty set, not crash.
        result = GitAnalyzer.get_staged_line_numbers(REPO_PATH, "no_such_file.c")
        assert isinstance(result, set)
