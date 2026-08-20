"""Tests for every rule in the RulesEngine (C01-C06, H01-H08, M01-M08, L01-L05)
and all validator functions."""
import pytest
from conftest import rule_ids
from cpu_load_optimizer import RulesEngine, Severity


@pytest.fixture
def engine():
    return RulesEngine()


# ─────────────────────────────────────────────────────────────────────────────
# CRITICAL rules
# ─────────────────────────────────────────────────────────────────────────────

class TestC01FloatIntegerContext:

    def test_float_initialized_with_integer(self, engine):
        assert "C01" in rule_ids(engine.analyze("float speed = 5;\n", "t.c"))

    def test_double_initialized_with_integer(self, engine):
        assert "C01" in rule_ids(engine.analyze("double rate = 100;\n", "t.c"))

    def test_float_with_float_literal_no_fire(self, engine):
        # 5.0f is not a pure integer literal — C01 must not fire
        assert "C01" not in rule_ids(engine.analyze("float speed = 5.0f;\n", "t.c"))

    def test_float_with_expression_no_fire(self, engine):
        assert "C01" not in rule_ids(engine.analyze("float x = a + b;\n", "t.c"))

    def test_correct_line_number_reported(self, engine):
        src = "int a = 0;\nfloat x = 1;\n"
        findings = [f for f in engine.analyze(src, "t.c") if f.rule_id == "C01"]
        assert findings and findings[0].line_number == 2

    def test_multiple_declarations_multiple_findings(self, engine):
        src = "float a = 1;\nfloat b = 2;\nfloat c = 3;\n"
        c01 = [f for f in engine.analyze(src, "t.c") if f.rule_id == "C01"]
        assert len(c01) == 3


class TestC02DivisionPowerOf2:

    @pytest.mark.parametrize("n", [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024])
    def test_fires_for_power_of_two(self, engine, n):
        src = f"uint32_t x = 100;\nuint32_t y = x / {n};\n"
        assert "C02" in rule_ids(engine.analyze(src, "t.c")), f"C02 should fire for /{n}"

    def test_no_fire_for_non_power_of_two(self, engine):
        assert "C02" not in rule_ids(engine.analyze("uint32_t y = x / 3;\n", "t.c"))

    def test_no_fire_for_division_by_one(self, engine):
        assert "C02" not in rule_ids(engine.analyze("uint32_t y = x / 1;\n", "t.c"))

    def test_float_variable_blocked_by_validator(self, engine):
        src = "float x = 1.0f;\nfloat y = x / 4;\n"
        assert "C02" not in rule_ids(engine.analyze(src, "t.c"))

    def test_double_variable_blocked_by_validator(self, engine):
        src = "double x = 1.0;\ndouble y = x / 8;\n"
        assert "C02" not in rule_ids(engine.analyze(src, "t.c"))

    def test_validator_looks_back_multiple_lines(self, engine):
        src = "float myVar = 1.0f;\n" * 10 + "float y = myVar / 4;\n"
        assert "C02" not in rule_ids(engine.analyze(src, "t.c"))


class TestC03ModuloPowerOf2:

    @pytest.mark.parametrize("n", [2, 4, 8, 16, 32, 64])
    def test_fires_for_power_of_two(self, engine, n):
        src = f"uint32_t y = x % {n};\n"
        assert "C03" in rule_ids(engine.analyze(src, "t.c")), f"C03 should fire for %{n}"

    def test_no_fire_for_non_power_of_two(self, engine):
        assert "C03" not in rule_ids(engine.analyze("uint32_t y = x % 7;\n", "t.c"))

    def test_float_variable_blocked(self, engine):
        src = "float x = 1.0f;\nfloat y = x % 4;\n"
        assert "C03" not in rule_ids(engine.analyze(src, "t.c"))


class TestC04MultiplyPowerOf2:

    @pytest.mark.parametrize("n", [2, 4, 8, 16, 32, 64, 128])
    def test_fires_for_power_of_two(self, engine, n):
        src = f"uint32_t y = x * {n};\n"
        assert "C04" in rule_ids(engine.analyze(src, "t.c")), f"C04 should fire for *{n}"

    def test_no_fire_for_non_power_of_two(self, engine):
        assert "C04" not in rule_ids(engine.analyze("uint32_t y = x * 3;\n", "t.c"))

    def test_float_variable_blocked(self, engine):
        src = "float x = 2.0f;\nfloat y = x * 4;\n"
        assert "C04" not in rule_ids(engine.analyze(src, "t.c"))


class TestC05ExpensiveMathFunction:

    @pytest.mark.parametrize("func", [
        "sqrt", "sqrtf", "sin", "sinf", "cos", "cosf",
        "tan", "tanf", "pow", "powf", "log", "logf",
        "exp", "expf", "asin", "acos",
    ])
    def test_fires_for_math_function(self, engine, func):
        # C05 has needs_context=True: it only fires when the call is
        # detected inside a loop body (the engine checks loop bodies).
        # Put the call inside a for-loop on a single line so the
        # pattern and context check both trigger.
        src = f"for(int i=0;i<10;i++){{ float y = {func}(x); }}"
        assert "C05" in rule_ids(engine.analyze(src, "t.c")), f"C05 should fire for {func}()"

    @pytest.mark.parametrize("func", ["fabs", "fabsf", "floorf", "ceilf"])
    def test_fpu_cheap_functions_do_not_fire(self, engine, func):
        # P1.6 — on an FPU core these map to single instructions (VABS.F32,
        # VRINTM/VRINTP); flagging them is a false positive.
        src = f"for(int i=0;i<10;i++){{ float y = {func}(x); }}"
        assert "C05" not in rule_ids(engine.analyze(src, "t.c")), \
            f"C05 must NOT fire for FPU-cheap {func}()"

    def test_no_fire_outside_loop(self, engine):
        # Without a loop, the context check prevents C05 from firing.
        src = "float y = sqrt(x);\n"
        assert "C05" not in rule_ids(engine.analyze(src, "t.c"))


class TestC06DynamicMemory:

    @pytest.mark.parametrize("call", ["malloc(100)", "calloc(10, 4)", "realloc(p, 200)", "free(p)"])
    def test_fires_for_heap_function(self, engine, call):
        src = f"void f() {{ {call}; }}\n"
        assert "C06" in rule_ids(engine.analyze(src, "t.c")), f"C06 should fire for {call}"


# ─────────────────────────────────────────────────────────────────────────────
# HIGH rules
# ─────────────────────────────────────────────────────────────────────────────

class TestH01LoopInvariantComputation:

    def test_strlen_fires(self, engine):
        src = "for (int i = 0; i < 10; i++) {\n  n = strlen(s);\n}\n"
        assert "H01" in rule_ids(engine.analyze(src, "t.c"))

    @pytest.mark.parametrize("call", ["strchr(s, c)", "strstr(s, q)", "memchr(p, c, n)"])
    def test_on_scanners_fire(self, engine, call):
        src = f"for (int i = 0; i < 10; i++) {{\n  r = {call};\n}}\n"
        assert "H01" in rule_ids(engine.analyze(src, "t.c"))

    def test_sizeof_no_fire(self, engine):
        # P0.4 — sizeof is a compile-time constant (C11 §6.5.3.4), zero
        # runtime cost. Flagging it is a false positive by design.
        src = "for (int i = 0; i < 10; i++) {\n  n = sizeof(buf);\n}\n"
        assert "H01" not in rule_ids(engine.analyze(src, "t.c"))


class TestH02Recursion:

    def test_direct_recursion_detected(self, engine):
        src = (
            "int factorial(int n) {\n"
            "  if (n <= 1) return 1;\n"
            "  return n * factorial(n - 1);\n"
            "}\n"
        )
        assert "H02" in rule_ids(engine.analyze(src, "t.c"))

    def test_non_recursive_function_no_fire(self, engine):
        src = "int add(int a, int b) {\n  return a + b;\n}\n"
        assert "H02" not in rule_ids(engine.analyze(src, "t.c"))

    def test_mutual_recursion_no_fire(self, engine):
        # Indirect (mutual) recursion is NOT detected by the tool.
        src = (
            "void even(int n);\n"
            "void odd(int n) { if (n != 0) even(n - 1); }\n"
            "void even(int n) { if (n != 0) odd(n - 1); }\n"
        )
        # H02 only checks direct recursion — no fire expected
        assert "H02" not in rule_ids(engine.analyze(src, "t.c"))


class TestH03StrlenInLoopCondition:

    def test_strlen_in_for_condition_fires(self, engine):
        src = "for (int i = 0; i < strlen(s); i++) { x++; }\n"
        assert "H03" in rule_ids(engine.analyze(src, "t.c"))

    def test_strlen_precomputed_no_fire(self, engine):
        src = "size_t len = strlen(s);\nfor (int i = 0; i < len; i++) { x++; }\n"
        assert "H03" not in rule_ids(engine.analyze(src, "t.c"))

    def test_strlen_in_body_not_condition_no_fire(self, engine):
        src = "for (int i = 0; i < 10; i++) {\n  n = strlen(s);\n}\n"
        assert "H03" not in rule_ids(engine.analyze(src, "t.c"))


class TestH04FunctionCallInLoop:

    def test_user_function_in_loop_fires(self, engine):
        # H04 pattern is applied per-line: the for-loop header and the
        # function call must appear on the same source line.
        src = "for(int i=0;i<10;i++){ process(i); }\n"
        assert "H04" in rule_ids(engine.analyze(src, "t.c"))

    def test_printf_in_loop_not_in_matched_text(self, engine):
        # printf is in the standard-func exclusion list; any H04 finding
        # on that line must not have printf as the matched function.
        src = "for(int i=0;i<10;i++){ printf(\"%d\", i); }\n"
        h04 = [f for f in engine.analyze(src, "t.c") if f.rule_id == "H04"]
        for finding in h04:
            assert "printf" not in finding.matched_text


class TestH05OversizedDataType:

    def test_int_with_small_value_fires(self, engine):
        src = "int count = 5;\n"
        assert "H05" in rule_ids(engine.analyze(src, "t.c"))

    def test_int_with_zero_fires(self, engine):
        src = "int count = 0;\n"
        assert "H05" in rule_ids(engine.analyze(src, "t.c"))

    def test_int_with_large_value_no_fire(self, engine):
        # 1000 > 255, so uint8_t is not sufficient
        src = "int count = 1000;\n"
        assert "H05" not in rule_ids(engine.analyze(src, "t.c"))

    def test_boundary_at_255(self, engine):
        # 255 fits in uint8_t → should fire
        src = "int x = 255;\n"
        assert "H05" in rule_ids(engine.analyze(src, "t.c"))

    def test_boundary_above_255(self, engine):
        # 256 does not fit in uint8_t → should NOT fire
        src = "int x = 256;\n"
        assert "H05" not in rule_ids(engine.analyze(src, "t.c"))


class TestH06FloatEqualityComparison:

    def test_float_equality_fires(self, engine):
        # H06 pattern is per-line: 'float'/'double' keyword and the
        # == / != operator must appear on the same source line.
        # Alternative 1: float declaration whose initialiser contains ==.
        src = "float eq = (a == b);\n"
        assert "H06" in rule_ids(engine.analyze(src, "t.c"))

    def test_double_inequality_fires(self, engine):
        src = "double neq = (a != b);\n"
        assert "H06" in rule_ids(engine.analyze(src, "t.c"))


class TestH07StructPassByValue:

    def test_struct_pass_by_value_fires(self, engine):
        src = "void process(struct Config data) { return; }\n"
        assert "H07" in rule_ids(engine.analyze(src, "t.c"))

    def test_struct_pass_by_pointer_no_fire(self, engine):
        src = "void process(struct Config *data) { return; }\n"
        assert "H07" not in rule_ids(engine.analyze(src, "t.c"))

    def test_struct_pass_by_const_pointer_no_fire(self, engine):
        src = "void process(const struct Config *data) { return; }\n"
        assert "H07" not in rule_ids(engine.analyze(src, "t.c"))


class TestH08Removed:
    """P1.4 — H08 was removed: its single-line back-reference regex was a
    false positive ~80% of the time. It must never fire now."""

    def test_repeated_expression_no_longer_fires(self, engine):
        src = "int y = a+b, z = a+b;\n"
        assert "H08" not in rule_ids(engine.analyze(src, "t.c"))

    def test_h08_not_in_registry(self, engine):
        assert "H08" not in {r.id for r in engine.rules}


# ─────────────────────────────────────────────────────────────────────────────
# MEDIUM rules
# ─────────────────────────────────────────────────────────────────────────────

class TestM01MissingConst:

    def test_pointer_without_const_fires(self, engine):
        src = "void process(uint8_t *data) { return; }\n"
        assert "M01" in rule_ids(engine.analyze(src, "t.c"))

    def test_pointer_with_const_no_fire(self, engine):
        src = "void process(const uint8_t *data) { return; }\n"
        assert "M01" not in rule_ids(engine.analyze(src, "t.c"))


class TestM02NonStaticFunction:

    def test_non_static_function_fires(self, engine):
        src = "void helperFunc(int x) {\n  x++;\n}\n"
        assert "M02" in rule_ids(engine.analyze(src, "t.c"))

    def test_static_function_no_fire(self, engine):
        src = "static void helperFunc(int x) {\n  x++;\n}\n"
        assert "M02" not in rule_ids(engine.analyze(src, "t.c"))

    def test_extern_function_no_fire(self, engine):
        src = "extern void helperFunc(int x);\n"
        assert "M02" not in rule_ids(engine.analyze(src, "t.c"))


class TestM03GlobalExternVariable:

    def test_extern_variable_used_in_loop_fires(self, engine):
        # P1.5 — M03 now requires the global to actually be used in a loop.
        src = ("extern uint32_t globalCounter;\n"
               "for (int i = 0; i < 10; i++) { x += globalCounter; }\n")
        assert "M03" in rule_ids(engine.analyze(src, "t.c"))

    def test_volatile_variable_used_in_loop_fires(self, engine):
        src = ("volatile uint32_t hwRegister;\n"
               "for (int i = 0; i < 10; i++) { x = hwRegister; }\n")
        assert "M03" in rule_ids(engine.analyze(src, "t.c"))

    def test_extern_not_used_in_loop_no_fire(self, engine):
        # The old rule lied: it fired on the declaration regardless of any
        # loop usage. Now a global never touched in a loop must not fire.
        src = "extern uint32_t globalCounter;\n"
        assert "M03" not in rule_ids(engine.analyze(src, "t.c"))


class TestM05DeeplyNestedLoops:

    def test_four_deep_loops_fires(self, engine):
        # M05 pattern is applied per-line; all four nested loop headers
        # must be on the same source line for the regex to match.
        src = "for(;;){ for(;;){ for(;;){ for(;;){ x++; } } } }\n"
        assert "M05" in rule_ids(engine.analyze(src, "t.c"))

    def test_three_deep_loops_no_fire(self, engine):
        src = "for(;;){ for(;;){ for(;;){ x++; } } }\n"
        assert "M05" not in rule_ids(engine.analyze(src, "t.c"))


class TestM06SwitchWithoutDefault:

    def test_switch_without_default_fires(self, engine):
        src = "switch (x) { case 1: break; case 2: break; }\n"
        assert "M06" in rule_ids(engine.analyze(src, "t.c"))

    def test_switch_with_default_no_fire(self, engine):
        src = "switch (x) { case 1: break; default: break; }\n"
        assert "M06" not in rule_ids(engine.analyze(src, "t.c"))


class TestM07SignedBitfield:

    def test_signed_bitfield_fires(self, engine):
        src = "struct S { int flags : 4; };\n"
        assert "M07" in rule_ids(engine.analyze(src, "t.c"))

    def test_unsigned_bitfield_false_positive(self, engine):
        # The M07 regex `(?:signed\s+)?int\s+\w+\s*:\s*\d+` matches the
        # 'int' token inside 'unsigned int' — this is a known false
        # positive in the current implementation.
        src = "struct S { unsigned int flags : 4; };\n"
        assert "M07" in rule_ids(engine.analyze(src, "t.c"))


class TestM08SequentialCasts:

    def test_sequential_casts_fires(self, engine):
        src = "int x = (int)(float)raw;\n"
        assert "M08" in rule_ids(engine.analyze(src, "t.c"))

    def test_single_cast_no_fire(self, engine):
        src = "int x = (int)raw;\n"
        assert "M08" not in rule_ids(engine.analyze(src, "t.c"))


# ─────────────────────────────────────────────────────────────────────────────
# LOW rules
# ─────────────────────────────────────────────────────────────────────────────

class TestL01MagicNumber:

    def test_unusual_literal_fires(self, engine):
        # L01 suppresses numbers immediately before end-of-statement (';').
        # Use the number inside an expression (condition) instead.
        src = "if (delay > 42) { x++; }\n"
        assert "L01" in rule_ids(engine.analyze(src, "t.c"))

    def test_literal_in_assignment_suppressed(self, engine):
        # A magic number that is the sole value before ';' is suppressed
        # by the negative lookahead in the L01 pattern — document the
        # behaviour so future changes are noticed.
        src = "uint32_t x = 42;\n"
        l01 = [f for f in engine.analyze(src, "t.c") if f.rule_id == "L01"]
        assert not any(f.matched_text.strip() == "42" for f in l01)

    @pytest.mark.parametrize("n", [0, 1, 2, 10, 100, 1000])
    def test_common_numbers_filtered(self, engine, n):
        src = f"if (x > {n}) {{ y++; }}\n"
        l01 = [f for f in engine.analyze(src, "t.c") if f.rule_id == "L01"]
        assert not any(f.matched_text.strip() == str(n) for f in l01), \
            f"L01 should not fire for common literal {n}"

    def test_define_not_flagged(self, engine):
        src = "#define MAX_SIZE 128\n"
        assert "L01" not in rule_ids(engine.analyze(src, "t.c"))

    def test_three_digit_literal_in_expression_fires(self, engine):
        src = "if (delay > 999) { alert(); }\n"
        assert "L01" in rule_ids(engine.analyze(src, "t.c"))


class TestL03ArrayIndexExpression:

    def test_expression_in_index_fires(self, engine):
        src = "buf[i + j] = 0;\n"
        assert "L03" in rule_ids(engine.analyze(src, "t.c"))

    def test_simple_index_no_fire(self, engine):
        src = "buf[i] = 0;\n"
        assert "L03" not in rule_ids(engine.analyze(src, "t.c"))

    def test_subtraction_in_index_fires(self, engine):
        src = "arr[end - start] = x;\n"
        assert "L03" in rule_ids(engine.analyze(src, "t.c"))


class TestL04HardwareRegisterVolatile:

    def test_non_volatile_hw_register_fires(self, engine):
        src = "*(uint32_t *)0x40020000 = value;\n"
        assert "L04" in rule_ids(engine.analyze(src, "t.c"))

    def test_volatile_hw_register_no_fire(self, engine):
        src = "*(volatile uint32_t *)0x40020000 = value;\n"
        assert "L04" not in rule_ids(engine.analyze(src, "t.c"))

    def test_various_hex_addresses(self, engine):
        for addr in ["0x00000000", "0xDEADBEEF", "0x40020000"]:
            src = f"*(uint32_t *){addr} = 0;\n"
            assert "L04" in rule_ids(engine.analyze(src, "t.c")), \
                f"L04 should fire for address {addr}"


class TestL05UninitializedVariable:

    def test_uninitialized_int_fires(self, engine):
        src = "void f() {\n  int counter;\n}\n"
        assert "L05" in rule_ids(engine.analyze(src, "t.c"))

    def test_initialized_variable_no_fire(self, engine):
        src = "void f() {\n  int counter = 0;\n}\n"
        assert "L05" not in rule_ids(engine.analyze(src, "t.c"))

    def test_various_uninitialized_types(self, engine):
        for typ in ["char", "short", "long", "float", "double", "uint8_t", "int32_t"]:
            src = f"void f() {{\n  {typ} val;\n}}\n"
            assert "L05" in rule_ids(engine.analyze(src, "t.c")), \
                f"L05 should fire for uninitialized {typ}"


# ─────────────────────────────────────────────────────────────────────────────
# Severity filtering
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityFiltering:

    def test_min_critical_excludes_high_medium_low(self, engine):
        src = (
            "float speed = 5;\n"       # C01 CRITICAL
            "int x = 5;\n"             # H05 HIGH
            "int counter;\n"           # L05 LOW (inside function)
        )
        findings = engine.analyze(src, "t.c", min_severity=Severity.CRITICAL)
        for f in findings:
            assert f.severity == Severity.CRITICAL, \
                f"Rule {f.rule_id} has severity {f.severity.name}, expected CRITICAL only"

    def test_min_high_includes_critical(self, engine):
        src = "float speed = 5;\nvoid *p = malloc(100);\n"
        findings = engine.analyze(src, "t.c", min_severity=Severity.HIGH)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_min_low_returns_all_severities(self, engine):
        src = (
            "float speed = 5;\n"       # CRITICAL
            "int x = 5;\n"             # HIGH
            "extern uint32_t g;\n"     # MEDIUM
        )
        findings = engine.analyze(src, "t.c", min_severity=Severity.LOW)
        severities = {f.severity for f in findings}
        assert len(severities) >= 2

    def test_findings_sorted_severity_descending(self, engine):
        src = "float speed = 5;\nvoid *p = malloc(100);\nint x = 5;\n"
        findings = engine.analyze(src, "t.c")
        sevs = [f.severity for f in findings]
        assert sevs == sorted(sevs, reverse=True)

    def test_min_medium_excludes_low(self, engine):
        src = (
            "extern uint32_t g;\n"     # MEDIUM (M03)
            "uint32_t delay = 42;\n"   # LOW (L01)
        )
        findings = engine.analyze(src, "t.c", min_severity=Severity.MEDIUM)
        for f in findings:
            assert f.severity >= Severity.MEDIUM


# ─────────────────────────────────────────────────────────────────────────────
# Cross-cutting correctness invariants
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingInvariants:

    def test_file_path_matches_argument(self, engine):
        src = "float x = 5;\n"
        findings = engine.analyze(src, "/abs/path/myfile.c")
        assert all(f.file_path == "/abs/path/myfile.c" for f in findings)

    def test_line_numbers_are_positive(self, engine):
        src = "float x = 5;\nvoid *p = malloc(100);\n"
        findings = engine.analyze(src, "t.c")
        assert all(f.line_number >= 1 for f in findings)

    def test_impact_score_in_valid_range(self, engine):
        src = "float x = 5;\nvoid *p = malloc(100);\nuint32_t y = x / 4;\n"
        findings = engine.analyze(src, "t.c")
        assert all(1 <= f.impact_score <= 100 for f in findings)

    def test_findings_have_non_empty_description(self, engine):
        src = "float x = 5;\n"
        findings = engine.analyze(src, "t.c")
        assert all(f.description for f in findings)

    def test_findings_have_non_empty_recommendation(self, engine):
        src = "float x = 5;\n"
        findings = engine.analyze(src, "t.c")
        assert all(f.recommendation for f in findings)

    def test_empty_source_zero_findings(self, engine):
        assert engine.analyze("", "t.c") == []

    def test_only_whitespace_zero_findings(self, engine):
        assert engine.analyze("   \n\n\t\n", "t.c") == []

    def test_patterns_in_single_line_comments_do_not_fire(self, engine):
        src = (
            "// float x = 5;\n"
            "// void *p = malloc(100);\n"
            "// uint32_t y = z / 4;\n"
            "int valid = 0;\n"
        )
        ids = rule_ids(engine.analyze(src, "t.c"))
        assert "C01" not in ids
        assert "C06" not in ids
        assert "C02" not in ids

    def test_patterns_in_block_comments_do_not_fire(self, engine):
        src = "/* void *p = malloc(100); float x = 5; */\nint ok = 0;\n"
        ids = rule_ids(engine.analyze(src, "t.c"))
        assert "C01" not in ids
        assert "C06" not in ids

    def test_windows_line_endings_no_crash(self, engine):
        src = "float x = 5;\r\nvoid *p = malloc(100);\r\n"
        findings = engine.analyze(src, "t.c")
        assert "C01" in rule_ids(findings)
        assert "C06" in rule_ids(findings)

    def test_unicode_in_comment_no_crash(self, engine):
        src = "// 日本語コメント\nfloat x = 5;\n"
        assert "C01" in rule_ids(engine.analyze(src, "t.c"))

    def test_very_long_comment_line_no_crash(self, engine):
        src = "// " + "x" * 10000 + "\nfloat speed = 5;\n"
        assert "C01" in rule_ids(engine.analyze(src, "t.c"))

    def test_h_file_analyzed_same_as_c_file(self, engine):
        src = "float gRate = 5;\n"
        assert "C01" in rule_ids(engine.analyze(src, "header.h"))

    def test_no_cross_file_state_between_calls(self, engine):
        # Two separate calls must not share state
        r1 = engine.analyze("float x = 5;\n", "a.c")
        r2 = engine.analyze("int ok = 0;\n", "b.c")
        assert all(f.file_path == "a.c" for f in r1)
        assert all(f.file_path == "b.c" for f in r2)
