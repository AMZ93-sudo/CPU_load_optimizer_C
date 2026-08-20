# Corner-Case Audit — CPU Load Optimizer (July 2026)

Every finding below was **empirically verified** by running `RulesEngine.analyze()` against crafted adversarial C files (checked into `tests/corner_cases/`). Baseline: the existing suite passes (330/330 relevant tests; the 2 failures in `test_report.py` are a hardcoded `/home/user/...` path, see R1).

Verdict up front: the v2 engine is solid — string-masked brace counting, constant folding suppression, signed-shift demotion, and finding dedup are all working as designed. But there are **6 confirmed false-positive bugs, 6 confirmed false-negative gaps, and 4 robustness issues**. All fixes are local and low-risk (regex or small logic changes); none change the architecture.

---

## A. Confirmed FALSE POSITIVES (tool flags correct code)

### FP-1 — M07 flags `unsigned` bit-fields as signed  · severity: HIGH (bug)
```c
struct Flags { unsigned int ready : 1; };   /* → flagged "Signed Bit-field" */
```
The pattern `\b(?:signed\s+)?int\s+\w+\s*:\s*\d+\s*;` happily matches the `int` inside `unsigned int`. Every MISRA-correct bit-field in the codebase gets flagged — the rule fires precisely on the code it recommends.
**Fix:** validate in code (check the full declaration text for `unsigned`), or use a fixed-width lookbehind: `(?<!unsigned\s)\bint\s+...` (note: evades on double spaces — code validation is safer).

### FP-2 — Multiline rules silently skip their validators  · severity: HIGH (bug)
In `analyze()`, the `rule.multiline` branch calls `pattern.finditer(cleaned)` and appends findings **without ever calling `rule.validator`**. M12's `_validate_const_table` (write-suppression) is therefore dead code:
```c
static uint8_t rw_table[4] = {1,2,3,4};
void mutate(uint8_t v) { rw_table[0] = v; }   /* → M12 still says "add const" — wrong */
```
**Fix:** in the multiline branch, call the validator (pass `lines` and the computed line index). One extra note: `_validate_const_table`'s write-check regex `name\[..\]\s*=(?!=)` matches the table's **own declaration**, so once wired in it would suppress *everything* — exclude the declaration line from the write scan.

### FP-3 — M02 flags `main()` and misses Allman-brace functions  · severity: HIGH (two bugs in one)
The M02 pattern is written with `re.MULTILINE` anchors but the rule is **not** marked `multiline=True`, so it runs per-line:
- `int main(void) {` (K&R brace) → flagged "add static" — `main` cannot be static.
- `int helper(v)\n{` (Allman brace) → **never matched at all**, because per-line matching can't see the `{` on the next line. Verified: the raw pattern matches Allman functions against full source; `analyze()` returns nothing for them. If your team's format style puts `{` on its own line, M02 currently does nothing.

**Fix:** set `multiline=True` on M02, and exclude `main` (plus, ideally, a configurable list of entry points/ISR handlers/AUTOSAR runnables).

### FP-4 — Rules match inside string literals  · severity: HIGH (noise generator)
`analyze()` matches per-line rules against `cleaned` (comments stripped) but **not string-masked**, even though `Preprocessor.mask_strings()` already exists and is used for brace counting. Verified hits:
```c
puts("speed/2 in path/to/file with 500 ms delay");
/* → C02 (div by 2), C09 (chained division on "path/to/file"), L01 (magic 500) */
puts("report_status( called )");   /* inside report_status() → H02 "recursive"! */
```
**Fix:** build `masked = Preprocessor.mask_strings(cleaned)` once in `analyze()` and run all pattern matching (including `_detect_recursion`'s body search and M11's chain counting) against it; keep `cleaned`/`original_lines` only for snippets. This is the highest FP-kill-per-line-of-code fix in the whole list.

### FP-5 — M06 flags switches that HAVE a default  · severity: MEDIUM
```c
switch (x) {
    case 1: { int t = 0; } break;   /* inner brace block */
    default: break;
}                                    /* → still flagged "Switch Without Default" */
```
The tempered-dot regex `\{(?:(?!default\s*:).)*\}` stops at the **first** `}` it can end on — the inner block's — before ever seeing `default:`. Any switch containing a compound statement, or a nested switch, before its default is a false positive.
**Fix:** extract the switch body with the existing masked brace counter, then search for `default\s*:` at depth 1. Regex alone cannot balance braces.

### FP-6 — M10 suggests reordering when BOTH operands are calls  · severity: LOW
`if (a_check(v) && b_check(v))` → flagged "put the cheap test first" — but the second operand is another call, not a cheap flag. **Fix:** append a negative lookahead so the second operand must not be a call: `&&\s*[A-Za-z_]\w*\b(?!\s*\()`.

### FP-7 — `#if 0` dead code is fully analyzed  · severity: MEDIUM
Verified: `malloc`/`n / 8` inside `#if 0 … #endif` produce C06/C02 findings. Dead-#if blocks are the classic graveyard of old code in automotive repos — this inflates counts and erodes trust in the report.
**Fix:** a small preprocessor pass that blanks `#if 0 … #endif` regions (respect nesting; leave `#else` branch live). Conditional inclusion semantics: [C11 §6.10.1, N1570 draft](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf).

---

## B. Confirmed FALSE NEGATIVES (tool misses real issues)

### FN-1 — `_POW2` misses hex, binary, and suffixed literals  · severity: HIGH — biggest accuracy gap for MISRA code
All verified as missed by C02/C03/C04:
```c
y = x / 0x10;   /* hex pow2 — missed  */
y = x / 4U;     /* MISRA-mandated U suffix — missed */
y = x / 0b1000; /* binary — missed */
```
This one matters most in your context: MISRA C:2012 (Rule 7.2 / Dir 4.6 culture) pushes teams to write `4U`, so on a compliant AUTOSAR codebase **C02/C03/C04 miss most real occurrences**. The `\b` after the digits fails against `U`/`L` suffixes, and `_POW2` only lists decimal literals.
**Fix:** match any numeric literal `(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|\d+)[uUlL]*` as divisor and verify power-of-two in the validator via `int(tok.rstrip('uUlL'), 0)` and `v & (v-1) == 0`. Also removes the arbitrary 4096 ceiling.

### FN-2 — Compound assignments missed  · severity: HIGH
`x /= 8; x %= 16; x *= 4;` → zero findings. Very common in filter/scaling code.
**Fix:** allow the compound forms: `_OPERAND\s*(/|%|\*)=\s*_POW2` as an alternation in C02/C03/C04 (or one extra rule reusing the same validator).

### FN-3 — H03 only knows `for`; `while (i < strlen(s))` missed  · severity: MEDIUM
Verified: the `while` form is only caught by generic H01 (lower specificity, different guidance); the O(n²) H03 diagnosis is lost. `do…while` is also uncovered.
**Fix:** second pattern `while\s*\([^)]*\bstrlen\s*\(`.
Side note on evidence: H03 cites **CERT STR31-C**, which is about null-terminator buffer space, not strlen-in-loop complexity — cite loop-invariant code motion instead (same Dragon Book reference as H01). See [STR31-C](https://wiki.sei.cmu.edu/confluence/display/c/STR31-C.+Guarantee+that+storage+for+strings+has+sufficient+space+for+character+data+and+the+null+terminator). Worth fixing since the README sells the rules as "verified & evidence-backed."

### FN-4 — H06 misses float comparisons of variables declared elsewhere  · severity: MEDIUM
```c
static float ratio;
...
if (ratio == 1.0f)   /* missed — no 'float' keyword on this line */
```
H06 only fires when `float`/`double` appears on the comparison line — the *least* common real-world shape. You already build `_float32_names`; wire it in: pattern `\b([A-Za-z_]\w*)\s*(?:==|!=)` + validator checking `_classify_operand_type(...) == 'float'` or an f-suffixed literal on either side.

### FN-5 — H09 misses MISRA-style `for (i = 0u; …)`  · severity: LOW
`0\b` fails against `0u`. **Fix:** `0[uUlL]*\b`. (Same suffix blindness family as FN-1.)

### FN-6 — C07 misses exponent-only and open-form double literals  · severity: LOW
`1e6`, `1.`, `.5` are all doubles but don't match `\d+\.\d+`. **Fix:** `(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?` with the same `(?![fF])` guard (require a dot **or** exponent so plain ints don't match). Reference: [Arm KA005775 — float vs double on Cortex-M4](https://developer.arm.com/documentation/ka005775/latest).

---

## C. Robustness / engineering

### R1 — Test suite is not portable
`tests/test_report.py` hardcodes `REPO_PATH = "/home/user/CPU_load_optimizer_C"` → 2 failures on any other machine/CI. Use `os.path.dirname(__file__)/..`, or a `tmp_path` git-init fixture, or `pytest.mark.skipif`.

### R2 — Braceless loop bodies swallow the following code
```c
for (i = 0; i < 100; i++)
    acc += v;          /* no braces */
```
`find_loop_bodies` scans forward for `{…}` balance; with no brace in the loop it runs into the **next** function and reports the loop body as spanning `return acc; } int two(v) {`. Verified: the reported body contained the next function's header. Consequence: `needs_context` rules (C05/H01/H04) attribute findings in *following* code to "inside a loop" — an FP amplifier that also happens to make braceless loops "work" by accident.
**Fix:** if no `{` appears before the first `;` that terminates the loop statement, take that single statement as the body.

### R3 — Severity filter leaks demoted findings
With `-s high`, a signed `x / 4` is demoted by `_demote_signed` to MEDIUM — and still appears in the report, because filtering happens on `rule.severity` before demotion. Verified. **Fix:** filter `findings` on the *finding's* final severity after the analysis loop (also fixes `--fail-on` interplay).

### R4 — Smaller items
- **UTF-8 BOM:** open files with `encoding='utf-8-sig'` or `^`-anchored rules can miss line 1.
- **Line continuations:** backslash-newline in macro bodies isn't spliced; multi-line macros are analyzed line-fragment by line-fragment.
- **M03 declaration pattern** (`\b(extern|volatile)\s+\w+\s+(\w+)\s*;`) misses qualified declarations like `extern volatile uint16_t x;` (three tokens).
- **H07/M01** still miss multi-line parameter lists (pattern requires the signature on one line) — acceptable until the AST backend, but worth a code comment.

---

## D. Suggested priority order

| Phase | Items | Effort | Payoff |
|-------|-------|--------|--------|
| P0 — FP kill | FP-4 (mask strings), FP-1, FP-2, FP-3, R3, FP-6 | ~½ day | Removes every verified FP class except switch/`#if 0`; all one-liners or near |
| P1 — FN recall | FN-1, FN-2 (suffix/hex/compound pow2), FN-4, FN-3, FN-5 | ~½ day | Biggest accuracy win on real MISRA/AUTOSAR code |
| P2 — structural | R2 (braceless loops), FP-7 (`#if 0`), FP-5 (brace-aware switch) | 1–2 days | Requires the masked brace counter you already have |
| P3 — hygiene | R1, FN-6, R4, H03 citation | opportunistic | CI portability + credibility |

Regression fixtures for all of the above are in `tests/corner_cases/fp_cases.c` (must produce **zero** findings for the named rules) and `tests/corner_cases/fn_cases.c` (every marked line **must** fire). Wire them into pytest before touching the regexes, and P0–P2 can be done without breaking the 330 green tests.

## References
- MISRA C:2012 Guidelines — https://misra.org.uk/
- GCC Optimize Options (strength reduction at -O1+) — https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html
- Arm: float vs double on Cortex-M4 (KA005775) — https://developer.arm.com/documentation/ka005775/latest
- C11 final draft N1570 (§6.10.1 conditional inclusion, §6.4.4.2 float constants) — https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf
- SEI CERT C STR31-C (for the citation correction) — https://wiki.sei.cmu.edu/confluence/display/c/STR31-C.+Guarantee+that+storage+for+strings+has+sufficient+space+for+character+data+and+the+null+terminator
