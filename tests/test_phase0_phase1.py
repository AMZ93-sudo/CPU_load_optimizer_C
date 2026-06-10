"""Regression tests for the v2 improvement plan (Phase 0 + Phase 1).

Each new behaviour ships with at least one true-positive fixture (rule MUST
fire) and one false-positive fixture (rule MUST NOT fire) — the FTR guarantee.
"""
import json

import pytest

from cpu_load_optimizer import (
    RulesEngine,
    LLMResponseParser,
    Preprocessor,
    Severity,
    _gate_and_exit,
)
from conftest import make_finding


@pytest.fixture
def engine():
    return RulesEngine()


def ids(findings):
    return {f.rule_id for f in findings}


def fire_count(engine, src, rule_id):
    return sum(1 for f in engine.analyze(src, "t.c") if f.rule_id == rule_id)


# ─────────────────────────────────────────────────────────────────────────────
# P0.1 — multi-line rules actually fire now
# ─────────────────────────────────────────────────────────────────────────────

class TestP01MultilineRules:

    def test_m05_nested_loops_multiline(self, engine):
        src = (
            "void f(void){\n"
            "for(i=0;i<n;i++){\n"
            " for(j=0;j<n;j++){\n"
            "  for(k=0;k<n;k++){\n"
            "   for(l=0;l<n;l++){\n"
            "    x=1;\n"
            "   }\n  }\n }\n}\n}\n"
        )
        assert fire_count(engine, src, "M05") == 1

    def test_m05_three_levels_no_fire(self, engine):
        src = (
            "void f(void){\n"
            "for(i=0;i<n;i++){\n"
            " for(j=0;j<n;j++){\n"
            "  for(k=0;k<n;k++){\n"
            "   x=1;\n"
            "  }\n }\n}\n}\n"
        )
        assert fire_count(engine, src, "M05") == 0

    def test_m06_switch_without_default_multiline(self, engine):
        src = (
            "void f(void){\n"
            "switch(x){\n"
            " case 1: a=1; break;\n"
            " case 2: b=2; break;\n"
            "}\n}\n"
        )
        assert fire_count(engine, src, "M06") == 1

    def test_m06_switch_with_default_no_fire(self, engine):
        src = (
            "void f(void){\n"
            "switch(x){\n"
            " case 1: a=1; break;\n"
            " default: b=2; break;\n"
            "}\n}\n"
        )
        assert fire_count(engine, src, "M06") == 0

    def test_l02_long_if_else_chain_multiline(self, engine):
        src = "void f(void){\n" + "if(a){x=1;}\n" + \
              "".join("else if(a){x=1;}\n" for _ in range(5)) + "}\n"
        assert fire_count(engine, src, "L02") == 1

    def test_h04_function_call_in_multiline_loop(self, engine):
        src = (
            "void f(void){\n"
            "for(i=0;i<n;i++){\n"
            "  do_work(i);\n"
            "}\n}\n"
        )
        assert "H04" in ids(engine.analyze(src, "t.c"))


# ─────────────────────────────────────────────────────────────────────────────
# P0.2 — duplicate findings in nested loops are deduplicated
# ─────────────────────────────────────────────────────────────────────────────

class TestP02Dedup:

    def test_sqrtf_in_nested_loop_reported_once(self, engine):
        src = (
            "void f(void){\n"
            "for(i=0;i<n;i++){\n"
            " for(j=0;j<n;j++){\n"
            "  x = sqrtf(y);\n"
            " }\n}\n}\n"
        )
        assert fire_count(engine, src, "C05") == 1


# ─────────────────────────────────────────────────────────────────────────────
# P0.6 — brace counting ignores braces inside string/char literals
# ─────────────────────────────────────────────────────────────────────────────

class TestP06StringMasking:

    def test_mask_strings_blanks_content_preserves_length(self):
        src = 'x = "a{b}c"; y = 1;\n'
        masked = Preprocessor.mask_strings(src)
        assert len(masked) == len(src)
        assert "{" not in masked and "}" not in masked
        assert masked.count("\n") == src.count("\n")

    def test_loop_with_brace_in_string_detected(self, engine):
        src = (
            "void f(void){\n"
            "for(i=0;i<n;i++){\n"
            '  trace("{ start }");\n'
            "  x = sqrtf(y);\n"
            "}\n}\n"
        )
        assert fire_count(engine, src, "C05") == 1


# ─────────────────────────────────────────────────────────────────────────────
# P0.7 — literal / constant operands are not flagged (constant folding)
# ─────────────────────────────────────────────────────────────────────────────

class TestP07ConstantFolding:

    @pytest.mark.parametrize("src", [
        "int x = 100 / 4;",
        "int x = 512 % 8;",
        "int x = 0x40 / 16;",
    ])
    def test_literal_literal_no_fire(self, engine, src):
        assert "C02" not in ids(engine.analyze(src, "t.c"))
        assert "C03" not in ids(engine.analyze(src, "t.c"))

    def test_runtime_operand_fires(self, engine):
        assert "C02" in ids(engine.analyze("y = x / 4;", "t.c"))

    def test_macro_constant_no_fire(self, engine):
        src = "#define N 100\ny = N / 4;\n"
        assert "C02" not in ids(engine.analyze(src, "t.c"))

    def test_const_int_no_fire(self, engine):
        src = "static const int N = 100;\ny = N / 4;\n"
        assert "C02" not in ids(engine.analyze(src, "t.c"))

    def test_array_index_both_literals_no_fire(self, engine):
        assert "L03" not in ids(engine.analyze("z = arr[4 + 8];", "t.c"))

    def test_array_index_runtime_fires(self, engine):
        assert "L03" in ids(engine.analyze("z = arr[i + 8];", "t.c"))


# ─────────────────────────────────────────────────────────────────────────────
# P1.7 — array elements and struct members as operands
# ─────────────────────────────────────────────────────────────────────────────

class TestP17OperandShapes:

    @pytest.mark.parametrize("expr", ["buf[i] / 8", "cfg->scale / 8", "s.field / 8"])
    def test_member_array_operands_fire(self, engine, expr):
        assert "C02" in ids(engine.analyze(f"y = {expr};\n", "t.c"))


# ─────────────────────────────────────────────────────────────────────────────
# P1.1 — signed power-of-2 division demoted to MEDIUM
# ─────────────────────────────────────────────────────────────────────────────

class TestP11Signedness:

    def test_signed_division_demoted(self, engine):
        src = "int32_t x = -5;\nint32_t y = x / 8;\n"
        c02 = [f for f in engine.analyze(src, "t.c") if f.rule_id == "C02"]
        assert c02 and c02[0].severity == Severity.MEDIUM
        assert "SIGNED" in c02[0].recommendation.upper()

    def test_unsigned_division_stays_critical(self, engine):
        src = "uint32_t x = 5;\nuint32_t y = x / 8;\n"
        c02 = [f for f in engine.analyze(src, "t.c") if f.rule_id == "C02"]
        assert c02 and c02[0].severity == Severity.CRITICAL


# ─────────────────────────────────────────────────────────────────────────────
# P1.2 — implicit double promotion (C07 / C08)
# ─────────────────────────────────────────────────────────────────────────────

class TestC07DoublePromotion:

    def test_unsuffixed_literal_with_float_fires(self, engine):
        assert "C07" in ids(engine.analyze("float x = 1.0;\n", "t.c"))

    def test_double_target_no_fire(self, engine):
        assert "C07" not in ids(engine.analyze("double d = 3.14;\n", "t.c"))

    def test_suffixed_literal_no_fire(self, engine):
        assert "C07" not in ids(engine.analyze("float x = 1.0f;\n", "t.c"))


class TestC08DoubleLibm:

    def test_double_sqrt_float_arg_fires(self, engine):
        src = "float a = 2.0f;\nfloat b = sqrt(a);\n"
        assert "C08" in ids(engine.analyze(src, "t.c"))

    def test_double_sqrt_double_arg_no_fire(self, engine):
        src = "double a = 2.0;\ndouble b = sqrt(a);\n"
        assert "C08" not in ids(engine.analyze(src, "t.c"))

    def test_sqrtf_no_fire(self, engine):
        src = "float a = 2.0f;\nfloat b = sqrtf(a);\n"
        assert "C08" not in ids(engine.analyze(src, "t.c"))


# ─────────────────────────────────────────────────────────────────────────────
# P1.10 — new researched rules
# ─────────────────────────────────────────────────────────────────────────────

class TestC09ChainedDivision:

    def test_chained_division_fires(self, engine):
        assert "C09" in ids(engine.analyze("y = a / b / c;\n", "t.c"))

    def test_all_literal_chain_no_fire(self, engine):
        assert "C09" not in ids(engine.analyze("y = 100 / 2 / 5;\n", "t.c"))

    def test_single_division_no_fire(self, engine):
        assert "C09" not in ids(engine.analyze("y = a / b;\n", "t.c"))


class TestH09CountUpUnusedIndex:

    def test_unused_index_fires(self, engine):
        src = "for(i=0;i<10;i++){\n sum++;\n}\n"
        assert "H09" in ids(engine.analyze(src, "t.c"))

    def test_used_index_no_fire(self, engine):
        src = "for(i=0;i<10;i++){\n a[i]=0;\n}\n"
        assert "H09" not in ids(engine.analyze(src, "t.c"))


class TestH10MixedSignedness:

    def test_mixed_signed_unsigned_fires(self, engine):
        src = "int s = -1;\nuint32_t u = 2;\ny = s + u;\n"
        assert "H10" in ids(engine.analyze(src, "t.c"))

    def test_same_signedness_no_fire(self, engine):
        src = "uint32_t a = 1;\nuint32_t b = 2;\ny = a + b;\n"
        assert "H10" not in ids(engine.analyze(src, "t.c"))


class TestM09DoWhile:

    def test_guaranteed_first_iteration_fires(self, engine):
        src = "x = 1;\nwhile(x < 10){ x++; }\n"
        assert "M09" in ids(engine.analyze(src, "t.c"))


class TestM10ShortCircuit:

    def test_expensive_call_first_fires(self, engine):
        src = "if (compute(x) && flag) { y = 1; }\n"
        assert "M10" in ids(engine.analyze(src, "t.c"))


class TestM11PointerChase:

    def test_repeated_chase_fires(self, engine):
        src = "for(i=0;i<n;i++){\n a=p->f; b=p->f; c=p->f;\n}\n"
        assert "M11" in ids(engine.analyze(src, "t.c"))

    def test_two_chases_no_fire(self, engine):
        src = "for(i=0;i<n;i++){\n a=p->f; b=p->f;\n}\n"
        assert "M11" not in ids(engine.analyze(src, "t.c"))


class TestM12ConstTable:

    def test_non_const_table_fires(self, engine):
        assert "M12" in ids(engine.analyze("static uint8_t tab[3] = {1,2,3};\n", "t.c"))

    def test_const_table_no_fire(self, engine):
        assert "M12" not in ids(engine.analyze("static const uint8_t tab[3] = {1,2,3};\n", "t.c"))


# ─────────────────────────────────────────────────────────────────────────────
# P1.3 — typedef'd structs by value (H07)
# ─────────────────────────────────────────────────────────────────────────────

class TestP13TypedefStruct:

    @pytest.mark.parametrize("decl", [
        "void f(Dem_EventStatusType status) { return; }",
        "void f(Handle_st h) { return; }",
        "void f(struct Config data) { return; }",
    ])
    def test_struct_by_value_fires(self, engine, decl):
        assert "H07" in ids(engine.analyze(decl, "t.c"))

    @pytest.mark.parametrize("decl", [
        "void f(uint32_t x) { return; }",
        "void f(size_t n) { return; }",
        "void process(const struct Config *data) { return; }",
    ])
    def test_scalar_or_pointer_no_fire(self, engine, decl):
        assert "H07" not in ids(engine.analyze(decl, "t.c"))


# ─────────────────────────────────────────────────────────────────────────────
# P0.3 — LLM round-trip (JSON contract + legacy fallback)
# ─────────────────────────────────────────────────────────────────────────────

class TestP03LLMRoundtrip:

    def _findings(self, engine):
        from conftest import make_finding
        return [make_finding(rule_id="C02", line_number=145),
                make_finding(rule_id="H01", line_number=210)]

    def test_json_contract_confirms_true_positive(self, engine):
        findings = self._findings(engine)
        resp = (
            "preamble\n```json\n" + json.dumps({"verdicts": [
                {"finding_index": 1, "rule_id": "C02", "line": 145,
                 "verdict": "CONFIRMED", "reasoning": "real",
                 "revised_impact": 70},
                {"finding_index": 2, "rule_id": "H01", "line": 210,
                 "verdict": "FALSE POSITIVE", "reasoning": "fp"},
            ]}) + "\n```"
        )
        res = LLMResponseParser.parse(resp, findings)
        assert len(res) == 1
        assert res[0]["finding"].rule_id == "C02"
        assert res[0]["revised_impact"] == 70

    def test_legacy_text_format_still_parses(self, engine):
        findings = self._findings(engine)
        legacy = "[C02] div - Line 145\nVERDICT: CONFIRMED\nREASONING: ok"
        res = LLMResponseParser.parse(legacy, findings)
        assert len(res) == 1 and res[0]["finding"].rule_id == "C02"

    def test_finding_index_correlation(self, engine):
        findings = self._findings(engine)
        resp = "```json\n" + json.dumps({"verdicts": [
            {"finding_index": 2, "rule_id": "H01", "line": 999,
             "verdict": "CONFIRMED", "reasoning": "idx wins over line"}]}) + "\n```"
        res = LLMResponseParser.parse(resp, findings)
        assert len(res) == 1 and res[0]["finding"].rule_id == "H01"


# ─────────────────────────────────────────────────────────────────────────────
# P0.4 — sizeof is not flagged (regression guard at engine level)
# ─────────────────────────────────────────────────────────────────────────────

class TestP04SizeofExcluded:

    def test_sizeof_in_loop_no_fire(self, engine):
        src = "for(i=0;i<n;i++){ x = sizeof(buf); }\n"
        assert "H01" not in ids(engine.analyze(src, "t.c"))


# ─────────────────────────────────────────────────────────────────────────────
# P0.5 — CI exit-code gating
# ─────────────────────────────────────────────────────────────────────────────

class TestP05Gating:

    def _result(self, *severities):
        return {"findings": [make_finding(severity=s) for s in severities]}

    def test_no_gate_when_fail_on_none(self):
        # Must not raise SystemExit.
        _gate_and_exit(self._result(Severity.CRITICAL), None)

    def test_gate_fails_at_or_above_threshold(self):
        with pytest.raises(SystemExit) as exc:
            _gate_and_exit(self._result(Severity.CRITICAL), "critical")
        assert exc.value.code == 1

    def test_gate_passes_below_threshold(self):
        # LOW findings, threshold CRITICAL → no exit.
        _gate_and_exit(self._result(Severity.LOW), "critical")

    def test_gate_high_threshold_triggers_on_critical(self):
        with pytest.raises(SystemExit) as exc:
            _gate_and_exit(self._result(Severity.CRITICAL, Severity.LOW), "high")
        assert exc.value.code == 1
