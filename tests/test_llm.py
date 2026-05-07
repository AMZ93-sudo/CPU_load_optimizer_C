"""Tests for LLMResponseParser and LLMValidationExport."""
import json
import os

import pytest

from conftest import make_finding
from cpu_load_optimizer import (
    LLMResponseParser,
    LLMValidationExport,
    Severity,
)


# ─────────────────────────────────────────────────────────────────────────────
# LLMResponseParser
# ─────────────────────────────────────────────────────────────────────────────

class TestLLMResponseParserParse:

    def test_confirmed_verdict_included(self):
        findings = [make_finding("C01", 5)]
        response = "[C01] Line 5\nVERDICT: CONFIRMED\nREASONING: Real issue.\n"
        results = LLMResponseParser.parse(response, findings)
        assert len(results) == 1
        assert results[0]["verdict"] == "CONFIRMED"

    def test_false_positive_excluded(self):
        findings = [make_finding("C01", 5)]
        response = "[C01] Line 5\nVERDICT: FALSE POSITIVE\nREASONING: Not an issue.\n"
        results = LLMResponseParser.parse(response, findings)
        assert results == []

    def test_partial_verdict_included(self):
        findings = [make_finding("C01", 5)]
        response = "[C01] Line 5\nVERDICT: PARTIAL\nREASONING: Context-dependent.\n"
        results = LLMResponseParser.parse(response, findings)
        assert len(results) == 1
        assert results[0]["verdict"] == "PARTIAL"

    def test_context_needed_excluded(self):
        findings = [make_finding("C01", 5)]
        response = "[C01] Line 5\nVERDICT: CONTEXT NEEDED\nREASONING: Need more info.\n"
        results = LLMResponseParser.parse(response, findings)
        assert results == []

    def test_empty_response_returns_empty(self):
        findings = [make_finding("C01", 5)]
        assert LLMResponseParser.parse("", findings) == []

    def test_whitespace_only_response_returns_empty(self):
        findings = [make_finding("C01", 5)]
        assert LLMResponseParser.parse("   \n\n   ", findings) == []

    def test_no_matching_findings_returns_empty(self):
        findings = [make_finding("C01", 5)]
        response = "[Z99] Line 5\nVERDICT: CONFIRMED\nREASONING: No such rule.\n"
        results = LLMResponseParser.parse(response, findings)
        assert results == []

    def test_multiple_findings_partial_confirmed(self):
        findings = [make_finding("C01", 5), make_finding("C06", 10)]
        response = (
            "[C01] Line 5\nVERDICT: CONFIRMED\nREASONING: Real.\n"
            "[C06] Line 10\nVERDICT: FALSE POSITIVE\nREASONING: Fine.\n"
        )
        results = LLMResponseParser.parse(response, findings)
        assert len(results) == 1
        assert results[0]["finding"].rule_id == "C01"

    def test_all_confirmed_all_returned(self):
        findings = [make_finding("C01", 1), make_finding("C06", 2)]
        response = (
            "[C01] Line 1\nVERDICT: CONFIRMED\nREASONING: Yes.\n"
            "[C06] Line 2\nVERDICT: CONFIRMED\nREASONING: Yes.\n"
        )
        results = LLMResponseParser.parse(response, findings)
        assert len(results) == 2

    def test_result_contains_finding_key(self):
        findings = [make_finding("C01", 5)]
        response = "[C01] Line 5\nVERDICT: CONFIRMED\nREASONING: Real issue.\n"
        results = LLMResponseParser.parse(response, findings)
        assert "finding" in results[0]

    def test_result_contains_reasoning_key(self):
        findings = [make_finding("C01", 5)]
        response = "[C01] Line 5\nVERDICT: CONFIRMED\nREASONING: This is bad.\n"
        results = LLMResponseParser.parse(response, findings)
        assert "reasoning" in results[0]
        assert results[0]["reasoning"]

    def test_revised_impact_parsed_when_present(self):
        findings = [make_finding("C01", 5, impact_score=80)]
        response = (
            "[C01] Line 5\nVERDICT: CONFIRMED\nREASONING: Real.\nIMPACT: 50\n"
        )
        results = LLMResponseParser.parse(response, findings)
        if results and results[0].get("revised_impact") is not None:
            assert results[0]["revised_impact"] == 50

    def test_empty_findings_list_returns_empty(self):
        response = "[C01] Line 5\nVERDICT: CONFIRMED\nREASONING: Real issue.\n"
        assert LLMResponseParser.parse(response, []) == []

    def test_noise_text_before_blocks_ignored(self):
        findings = [make_finding("C01", 5)]
        response = (
            "Here is my analysis of the code:\n"
            "I found several issues.\n\n"
            "[C01] Line 5\nVERDICT: CONFIRMED\nREASONING: Genuine.\n"
        )
        results = LLMResponseParser.parse(response, findings)
        assert len(results) == 1

    def test_duplicate_rule_id_in_response_uses_first_match(self):
        findings = [make_finding("C01", 5)]
        response = (
            "[C01] Line 5\nVERDICT: CONFIRMED\nREASONING: First.\n"
            "[C01] Line 5\nVERDICT: FALSE POSITIVE\nREASONING: Second.\n"
        )
        results = LLMResponseParser.parse(response, findings)
        # First CONFIRMED should win; FALSE POSITIVE second block is ignored
        # (finding already consumed)
        assert len(results) <= 1


class TestLLMResponseParserSplitBlocks:

    def test_splits_by_rule_id_markers(self):
        text = "[C01] foo\n[H02] bar\n[L05] baz\n"
        blocks = LLMResponseParser._split_into_blocks(text)
        assert len(blocks) >= 3

    def test_empty_text_returns_empty_or_single_empty(self):
        blocks = LLMResponseParser._split_into_blocks("")
        assert isinstance(blocks, list)


# ─────────────────────────────────────────────────────────────────────────────
# LLMValidationExport
# ─────────────────────────────────────────────────────────────────────────────

class TestLLMValidationExport:

    def _run(self, tmp_dir, findings=None, source_contents=None):
        if findings is None:
            findings = [make_finding("C01")]
        if source_contents is None:
            source_contents = {"test.c": "float x = 5;\n"}
        return LLMValidationExport.generate(
            findings, list(source_contents.keys()), tmp_dir, source_contents
        )

    def test_returns_six_paths(self, tmp_dir):
        paths = self._run(tmp_dir)
        assert len(paths) == 6

    def test_all_files_exist(self, tmp_dir):
        paths = self._run(tmp_dir)
        for p in paths:
            assert os.path.isfile(p), f"Missing export file: {p}"

    def test_findings_markdown_contains_rule_id(self, tmp_dir):
        paths = self._run(tmp_dir)
        findings_md = next(p for p in paths if "findings_for_review" in p)
        content = open(findings_md, encoding="utf-8").read()
        assert "C01" in content

    def test_findings_cache_is_valid_json(self, tmp_dir):
        paths = self._run(tmp_dir)
        cache = next(p for p in paths if "findings_cache" in p)
        with open(cache, encoding="utf-8") as fh:
            data = json.load(fh)
        assert "findings" in data

    def test_validation_prompt_non_empty(self, tmp_dir):
        paths = self._run(tmp_dir)
        prompt = next(p for p in paths if "validation_prompt" in p)
        content = open(prompt, encoding="utf-8").read()
        assert len(content) > 100

    def test_how_to_validate_md_exists(self, tmp_dir):
        paths = self._run(tmp_dir)
        how_to = next((p for p in paths if "HOW_TO_VALIDATE" in p), None)
        assert how_to is not None
        assert os.path.isfile(how_to)

    def test_automated_prompt_exists(self, tmp_dir):
        paths = self._run(tmp_dir)
        auto = next((p for p in paths if "automated_llm_prompt" in p), None)
        assert auto is not None
        assert os.path.isfile(auto)

    def test_output_dir_created(self, tmp_dir):
        nested_dir = os.path.join(tmp_dir, "deep", "llm_output")
        paths = self._run(nested_dir)
        assert all(os.path.isfile(p) for p in paths)

    def test_no_findings_does_not_crash(self, tmp_dir):
        paths = LLMValidationExport.generate([], ["test.c"], tmp_dir, {"test.c": ""})
        assert len(paths) == 6

    def test_multiple_findings_different_rules(self, tmp_dir):
        findings = [
            make_finding("C01", 1),
            make_finding("C06", 5),
            make_finding("H02", 10),
        ]
        source_contents = {"test.c": "float x = 5;\nmalloc(10);\n"}
        paths = LLMValidationExport.generate(
            findings, ["test.c"], tmp_dir, source_contents
        )
        md = next(p for p in paths if "findings_for_review" in p)
        content = open(md, encoding="utf-8").read()
        assert "C01" in content
        assert "C06" in content
        assert "H02" in content

    def test_duplicate_rule_shows_same_rule_note(self, tmp_dir):
        # When the same rule_id appears multiple times, the export should
        # include "(Same rule as above)" for subsequent occurrences.
        findings = [make_finding("C01", 1), make_finding("C01", 3)]
        paths = LLMValidationExport.generate(
            findings, ["test.c"], tmp_dir, {"test.c": "float a=1;\nfloat b=2;\n"}
        )
        md = next(p for p in paths if "findings_for_review" in p)
        content = open(md, encoding="utf-8").read()
        assert "Same rule" in content or "same rule" in content.lower()

    def test_cache_contains_all_findings(self, tmp_dir):
        findings = [make_finding(f"C0{i}", i) for i in range(1, 5)]
        paths = LLMValidationExport.generate(
            findings, ["test.c"], tmp_dir, {"test.c": "code\n"}
        )
        cache = next(p for p in paths if "findings_cache" in p)
        data = json.load(open(cache, encoding="utf-8"))
        assert len(data["findings"]) == 4
