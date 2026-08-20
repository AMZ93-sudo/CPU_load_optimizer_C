# 🚀 CPU Load Optimizer — Improvement Plan

> **Target file:** `cpu_load_optimizer.py` (single-file tool, ~4000 lines)
> **Audience:** Claude Code (execute phase by phase), reviewed by Zeko (Tech Lead, USPM/KSS)
> **Goal:** Robust, accurate, low-false-positive static analyzer for embedded C, CI-ready, team-shareable.
> **Engineering principle:** FTR — First Time Right. Every fix ships with a regression test.

---

## 📊 Executive Summary

| Phase | Theme | Items | Risk if skipped |
|-------|-------|-------|-----------------|
| 🔴 P0 | Correctness bugs (tool is silently wrong today) | 7 | Dead rules, duplicate findings, constant-folding FPs, broken LLM round-trip |
| 🟠 P1 | Accuracy & false-positive reduction (incl. 7 new researched rules) | 10 | Colleagues lose trust after first obvious FP |
| 🟡 P2 | Robustness, CI & team workflow | 7 | Tool stays a personal script, never a team asset |
| 🟢 P3 | Architecture & nice-to-haves | 5 | Maintainability debt |

---

## 🔴 PHASE 0 — Critical Correctness Bugs

### P0.1 — Multi-line rules NEVER match (4 dead rules) 🐛
**Location:** `RulesEngine.analyze()` — the "Standard pattern matching" block iterates `for i, line in enumerate(lines)` and runs `rule.pattern.finditer(line)` **per single line**.

**Problem:** These rules require multi-line input and therefore can never fire on real code:
- `M05` — Deeply Nested Loops (4 nested loops never sit on one line)
- `M06` — Switch Without Default (`re.DOTALL` is useless on a 1-line string)
- `L02` — Long If-Else Chain (5+ branches)
- `H04` — Function Call in Tight Loop (`for(...){...call();` on one line ≈ never)

**Fix:**
1. Add a `multiline: bool = False` field to `Rule`.
2. Mark M05, M06, L02, H04 (and audit M02, L05) as `multiline=True`.
3. For multiline rules, run `pattern.finditer(cleaned_source)` against the **whole stripped source**, compute the line number via `cleaned[:m.start()].count('\n') + 1`, then map through `line_map`.
4. Rewrite H04 to use `Preprocessor.find_loop_bodies()` output instead of a giant regex (same approach as C05/H01) — far more reliable.

**Acceptance test:** A fixture file with a 4-level nested loop, a multi-line switch without `default`, and a 6-branch if-else chain must yield exactly 1 finding each for M05/M06/L02.

---

### P0.2 — Duplicate findings in nested loops 🐛
**Location:** `Preprocessor.find_loop_bodies()` + `RulesEngine.analyze()` C05/H01 blocks.

**Problem:** `find_loop_bodies()` returns the outer loop **and** every inner loop. A `sqrtf()` inside an inner loop appears in both bodies → reported twice (or N times for N nesting levels). Inflates counts and the CPU-reduction estimate.

**Fix:** Deduplicate findings by key `(rule_id, file_path, line_number, matched_text)` before sorting in `analyze()`. One `seen: set` is enough. Optionally: only attribute context-rules to the **innermost** enclosing loop.

**Acceptance test:** `for { for { x = sqrtf(y); } }` → exactly **one** C05 finding.

---

### P0.3 — `LLMResponseParser` cannot parse either prompt's output format 🐛
**Location:** `LLMResponseParser.parse()` vs `LLMValidationExport._build_automated_llm_prompt()` and `_build_validation_prompt()`.

**Problem:** Three incompatible contracts coexist:
| Component | Expected output format |
|-----------|------------------------|
| `LLMResponseParser` | `[C01] ... \n VERDICT: CONFIRMED \n REASONING: ...` |
| `automated_llm_prompt.md` | `### Finding #N — <rule_id> — <name>` + `**Classification:** TRUE POSITIVE` |
| `validation_prompt.md` | Raw full HTML document |

The parser is **dead code** — nothing in the pipeline produces its expected format. The validated-report generator (`LLMValidatedReportGenerator`) can therefore never run end-to-end.

**Fix (pick ONE canonical contract — recommended: structured JSON):**
1. Change both prompts to require a fenced JSON block:
   ```json
   {"verdicts": [{"finding_index": 1, "rule_id": "C02", "line": 145,
                  "verdict": "CONFIRMED", "reasoning": "...", "revised_impact": 70}]}
   ```
2. Rewrite `LLMResponseParser.parse()` to extract the JSON block (strip ``` fences), validate against a schema, and correlate via `finding_index` against `findings_cache.json` (already written — use it as the join key, far more reliable than rule_id + line proximity matching).
3. Add a CLI entry point: `python cpu_load_optimizer.py --apply-validation <response_file> --cache <findings_cache.json> -o validated_report.html` so the round-trip is one command instead of a manual copy/paste ritual.

**Acceptance test:** Round-trip test: cache → mock LLM JSON response → parser → `LLMValidatedReportGenerator` → HTML containing only confirmed findings.

---

### P0.4 — `sizeof` flagged as expensive loop computation (false positive by design) 🐛
**Location:** Rule `H01`, pattern `\b(sizeof|strlen)\s*\(`.

**Problem:** `sizeof` is evaluated at **compile time** — zero runtime cost (C11 §6.5.3.4; the only exception is VLAs, which are banned by MISRA anyway). Flagging it is an instant credibility-killer in front of embedded colleagues.

**Fix:** Remove `sizeof` from H01. Keep `strlen` and consider adding `strchr`, `strstr`, `memchr` (genuinely O(n) per call).

**Reference:** [SEI CERT C — ARR01-C / sizeof semantics](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard)

---

### P0.5 — Exit code is always 0 → CI cannot gate 🐛
**Location:** `main()` / `run_analysis()`.

**Problem:** `--staged` mode is clearly designed for pre-commit / pipeline use, but the process always exits 0. Jenkins/GitLab/pre-commit hooks can't fail the build on CRITICAL findings.

**Fix:**
1. Add `--fail-on {critical,high,medium,low}` (default: no gating, backward compatible).
2. `sys.exit(1)` if any finding ≥ threshold; `sys.exit(2)` on tool error (distinguish "findings" from "crash").
3. Document the pre-commit hook recipe in the README:
   ```bash
   python cpu_load_optimizer.py --staged . --fail-on critical
   ```

---

### P0.6 — Brace counting breaks on braces inside string/char literals 🐛
**Location:** `Preprocessor.find_loop_bodies()` and `find_function_bodies()`.

**Problem:** Comments are stripped, but **strings are preserved**. `printf("{")` or `char c = '{';` corrupts `brace_count`, silently truncating/extending loop & function bodies → wrong context for C05/H01/H02.

**Fix:** Before brace counting, run a `mask_strings()` pass that replaces string/char-literal contents with spaces (preserving length & newlines). Reuse the state machine already in `strip_comments()`.

**Acceptance test:** A loop containing `log("{ start }");` must still be detected with the correct end line.

---

### P0.7 — Literal ÷ literal flagged as optimization opportunity (constant-folding FP) 🐛 *(reported by Zeko on real code)*
**Location:** Rules `C02`, `C03`, `C04` (and indirectly `L03`, `H08`) — operand capture `(\w+)`.

**Problem:** `\w` matches **digits**, so `10 / 2`, `512 % 8`, `100 * 4`, even `0x40 / 16` are captured with a numeric literal as the "variable." But **every** modern compiler evaluates literal-only expressions at compile time via **constant folding** — this happens in the compiler front-end and is active at ALL optimization levels, **including `-O0`** (verified: GCC folds `0x15/c`-style constant sub-expressions even unoptimized). These findings are pure false positives with zero runtime cost. Same applies when both operands are `#define`d numeric constants or `static const` integers — constant **propagation** folds those too at `-O1+`.

**Fix:** New shared validator `_validate_runtime_operand(match, line, lines, line_idx)` chained before `_validate_not_float_context`:
1. **Reject numeric literals:** `re.fullmatch(r'(0[xX][0-9A-Fa-f]+|0[bB][01]+|\d+)[uUlL]*', operand)` → skip finding.
2. **Reject macro/const constants:** build a per-file constant table during preprocessing — collect `#define NAME <number>` and `static const <inttype> NAME = <number>;` — if the operand name is in the table, skip (constant propagation handles it). Make this behavior configurable (`assume_constant_propagation: true` in config, since certified compilers at `-O0` may not propagate — but folding of pure literals is always safe to suppress).
3. Apply the same operand check to `L03` (e.g., `arr[4 + 8]` folds to `arr[12]`) and `H08`.

**Acceptance tests:**
| Input | Expected |
|-------|----------|
| `int x = 100 / 4;` | 0 findings (literal/literal) |
| `y = x / 4;` | 1 finding (C02 — runtime operand, valid) |
| `#define N 100` … `y = N / 4;` | 0 findings (macro constant) |
| `y = buf[i] / 4;` | 1 finding (after P1.7 operand extension) |

**References:** [Constant folding — Wikipedia](https://en.wikipedia.org/wiki/Constant_folding) · [Stanford CS107 — Constant Folding at -O0 vs -O2 (disassembly proof)](https://web.stanford.edu/class/archive/cs/cs107/cs107.1206/lectures/15/Lecture15.pdf)

---

## 🟠 PHASE 1 — Accuracy & False-Positive Reduction

### P1.1 — C02/C04: signedness + compiler-already-does-it ⚠️
- `x / 8 → x >> 3` is **incorrect for signed ints**: division truncates toward zero, arithmetic shift floors toward −∞ (different results for negative `x`). The recommendation text mentions this, but the tool should *detect* it: extend `_validate_not_float_context` into `_classify_operand_type` returning `{unsigned, signed, float, unknown}` by scanning declarations (look for `uint*_t`, `unsigned` vs `int*_t`, `int`). Signed → demote to MEDIUM with a "verify semantics" note.
- GCC/armclang perform strength reduction for power-of-2 mul/div at `-O1+` ([GCC Optimize Options](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)). Add to the rule description: *"Verify your build's -O level; relevant mainly at -O0 or with certified compilers running restricted optimization."* Consider demoting C04 (multiplication) to MEDIUM — it is virtually always auto-optimized.

### P1.2 — NEW RULE (highest-value for Cortex-M4F): implicit `double` promotion 🌟
This is the **single biggest missing rule** for your ADAS targets. The Cortex-M4F FPU is **single-precision only** — any `double` operation falls into software emulation (10–100×).
- `C07`: float literal **without `f` suffix** used with `float` variables → `float x = 1.0;` / `y = x * 3.14;` (3.14 is `double` → whole expression promotes).
- `C08`: double-precision libm call where the `f` variant exists → `sin(`, `cos(`, `sqrt(` flagged when operand context is `float`; recommend `sinf/cosf/sqrtf`.
- Recommend compile flags note: `-Wdouble-promotion -fsingle-precision-constant`.
- **References:** [Arm — float vs double on Cortex-M4](https://developer.arm.com/documentation/ka005775/latest), [GCC Warning Options: -Wdouble-promotion](https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html)

### P1.3 — H07: typedef'd structs are invisible (≈100% miss rate on AUTOSAR code) ⚠️
Pattern only matches literal `struct X param`. AUTOSAR/Valeo code passes typedef'd types (`Dem_EventStatusType`, custom `*_Type` structs). Heuristic fix: also flag parameters whose type name matches configurable patterns (`\w+_t\b` excluding stdint, `\w+Type\b`, `\w+_st\b`) passed **by value**, with a lower confidence note. Make the suffix list configurable (→ P2.2 config file).

### P1.4 — H08 (repeated computation) regex is noise ⚠️
`(\w+\s*[op]\s*\w+).*\1` on a single line flags `a + b ... a + b` even across unrelated semantic contexts, and misses the much more common multi-line repetition. Either (a) delete the rule until a real CSE check exists, or (b) restrict to expensive sub-expressions only (`*`, `/`, `%`) appearing ≥2× **within one statement**, and demote to LOW. Option (a) recommended — a rule that's wrong 80% of the time is worse than no rule.

### P1.5 — M01/M03/L05: declaration-level heuristics flag too broadly ⚠️
- **M01 (missing const):** flags every non-const pointer param without checking writes. Minimum viable improvement: search the function body for `*param =`, `param[...] =`, `memcpy(param`, `(param)++` — if any write found, suppress. Use `find_function_bodies()` you already have.
- **M03 (global in loop):** the pattern flags every `extern`/`volatile` **declaration**, never verifying loop usage — the rule name lies. Fix: collect declared names, then flag only when the identifier appears inside a `find_loop_bodies()` body. Note: caching `volatile` into a local is **only** valid when no ISR/DMA coherence is required mid-loop — add that warning to the recommendation (safety-critical context!).
- **L05 (uninitialized var):** currently flags struct members and multi-line param lists. Suppress matches inside `struct/union` bodies and parameter lists (track `{}` context of structs). Also: the evidence text is backwards — init-to-zero stays in `.bss`; init-to-nonzero moves to `.data` (flash + startup copy cost). Fix the description so colleagues don't catch the error.

### P1.6 — C05: `fabs/fabsf` are cheap on FPU ⚠️
`fabsf` compiles to a single `VABS.F32` on M4F. Remove `fabs/fabsf` (and `floorf/ceilf` — `VRINTM/VRINTP` on M7, cheap-ish) from the "expensive" list or split into a separate LOW rule "verify FPU availability".

### P1.7 — C02/C03/C04 miss array elements and struct members
`(\w+)\s*/\s*8` cannot match `buf[i] / 8` or `cfg->scale / 8`. Extend the operand capture to `((?:\w+(?:\[[^\]]*\])?(?:\s*(?:->|\.)\s*\w+(?:\[[^\]]*\])?)*))` (identifier with optional index/member chains). Add fixtures for all three shapes.

### P1.8 — `_validate_not_float_context` 20-line lookback is fragile
Function parameters declared far above, or types from headers, escape the check. Improvement: build a per-function **symbol table** (name → declared type) during `find_function_bodies()` and consult it first; fall back to the 20-line window only for globals. This single change cuts FPs across C02/C03/C04.

### P1.9 — Severity model / estimation honesty 📐
The additive `%CPU` model with caps is a fine heuristic, but label it harder: rename "Estimated CPU Load Reduction" → "**Opportunity Index** (heuristic)" in both reports and put the methodology paragraph **above** the number, not in small italics below. Your top management has seen the USPM dashboards — they will quote that number. Make it un-misquotable.

---

### P1.10 — 🌐 NEW verified rules from research (vendor/compiler-backed) 📚
Seven additional rules verified against ARM documentation, Embedded.com engineering guides, and embedded-vendor training material. Each entry: detection sketch + severity + source.

**C09 — Chained / repeated division in one expression** 🔴 HIGH
`a/b/c` or `a/b + c/b`. Integer division is the slowest integer operation on Cortex-M (SDIV/UDIV 2–12 cycles, worse with operands); restructure to one division: `a/(b*c)`, `(a+c)/b` (verify no overflow in the product/sum).
*Detect:* two+ `/` with shared divisor or chained `/` in one statement (runtime operands only — apply P0.7 validator).
*Source:* [Embedded C Optimization Techniques (Emertxe)](https://slideshare.net/EmertxeSlides/embedded-c-optimization-techniques) — "Integer division is the slowest of all integer arithmetic operations; replace with multiplication when multiple divisions occur."

**H09 — Count-up loop with unused index → count-down candidate** 🟡 MEDIUM
`for (i = 0; i < N; i++)` where `i` is **not referenced in the body**: counting down to zero compiles to a single flag-setting `SUBS` + `BNE` instead of `ADD` + `CMP` + branch on ARM. **Only** flag when the index is unused in the body — otherwise reversed indexing costs more than it saves and harms readability.
*Detect:* parse loop header for the index var; grep body (via `find_loop_bodies`) for the identifier; flag if absent.
*Source:* [ARM — Writing Efficient Code for ARM](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/8009/1/580-Writing_Efficient_Code_for_ARM.pdf) · ARM loop guidance (SUBS/BNE vs ADD/CMP)

**H10 — Mixed signed/unsigned arithmetic in one expression** 🟡 MEDIUM
Implicit sign conversions generate extra extension/masking instructions and are a MISRA C:2012 Rule 10.4 (essential type) violation. Recommendation per vendor guidance: **unsigned** for division, modulo, loop counters, array indexing; signed only where negatives or int→float conversion is needed.
*Detect:* expression mixing identifiers whose declarations resolve to signed and unsigned (reuse P1.8 symbol table).
*Source:* Emertxe optimization notes (type-conversion cycle cost) · [MISRA C:2012 Rule 10.4](https://misra.org.uk/)

**M09 — `while` loop with guaranteed first iteration → `do-while`** 🔵 LOW
When the controlling variable is assigned a known-true constant immediately before the loop, `do-while` removes the initial test+branch. Hard to verify statically — flag only the narrow pattern `x = <const>; while (x <cond>)` where the const trivially satisfies the condition, with a "verify first-iteration guarantee" note.
*Source:* [Embedded.com — Engineering embedded software for optimum performance, Part 2](https://www.embedded.com/engineering-embedded-software-for-optimum-performance-part-2-more-c-code-techniques/) · ARM do-while guidance

**M10 — Expensive call first in short-circuit chain** 🔵 LOW→🟡 MEDIUM (if in loop)
`if (expensive_fn(x) && simple_flag)` — short-circuit evaluation means reordering to `simple_flag && expensive_fn(x)` skips the call whenever the cheap test fails. Flag when operand #1 is a function call and operand #2 is a plain identifier/comparison. Caveat in recommendation: only when the call is side-effect-free (cannot verify statically — say so).
*Source:* Standard C short-circuit semantics (C11 §6.5.13/14) + embedded optimization canon

**M11 — Repeated pointer-chase inside loop body** 🟡 MEDIUM
`ptr->field` or `cfg.sub.member` read ≥3× inside a loop body: without `restrict` the compiler must assume aliasing and reload from memory each time. Cache into a local before/at loop top. Highly relevant to your DAPM/ULFX handle-based module patterns.
*Detect:* count occurrences of identical `\w+(->|\.)\w+` chains within each `find_loop_bodies` body; threshold ≥3.
*Source:* [ARM — Writing Efficient Code for ARM](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/8009/1/580-Writing_Efficient_Code_for_ARM.pdf) (aliasing/restrict, register residency) · Embedded.com Part 2

**M12 — File-scope lookup table without `const`** 🟡 MEDIUM
Non-const initialized tables live in `.data`: they consume RAM **and** cost a flash→RAM copy at startup. `const` places them in flash (`.rodata`) directly. On RAM-constrained automotive MCUs this is both a CPU (startup) and memory win.
*Detect:* file-scope `static <type> name[...] = {...};` without `const`, no write references to `name` anywhere in the TU.
*Source:* Emertxe (const → ROM placement) · standard linker-section behavior (Renesas Embedded C III, data sections)

**🚫 ANTI-RULE — deliberately NOT adding "manually unroll loops":**
Manual unrolling is in every old optimization guide, but on modern Cortex-M with low-overhead-branch support (M55/M85) and current compilers it shows little or no benefit while bloating code and hurting MISRA-compliant maintainability — and GCC/armclang already unroll where profitable. Document this in `RULES.md` so a colleague doesn't "helpfully" add it later.
*Source:* [Alif Semiconductor — Cortex-M55 Optimization whitepaper](https://alifsemi.com/whitepaper/cortex-m55-optimization-and-tools/) ("generally no little or no benefit to simple loop unrolling") · [Loop unrolling — Wikipedia](https://en.wikipedia.org/wiki/Loop_unrolling) (cache-pressure counterproductivity)

---

## 🟡 PHASE 2 — Robustness, CI & Team Workflow

### P2.1 — Inline suppression + baseline file 🔇
Team adoption dies without a way to silence accepted findings.
1. Inline: `/* cpuopt-disable-next-line C02 */` and `/* cpuopt-disable-line C02 */` — check the raw line above/on the match before emitting. (Strip-comments pass removes them, so check `original_lines`.)
2. Baseline: `--baseline baseline.json` (generate with `--write-baseline`) — findings whose `(rule_id, file, matched_text_hash)` exist in baseline are suppressed. Lets you adopt the tool on legacy USPM modules without 400 day-one findings.
- **Pattern reference:** [Clang-Tidy NOLINT mechanism](https://clang.llvm.org/extra/clang-tidy/#suppressing-undesired-diagnostics)

### P2.2 — Config file (`cpuopt.yaml` / `pyproject.toml [tool.cpuopt]`) ⚙️
Per-project: enabled rules, severity overrides, magic-number allowlist, typedef-struct suffixes (P1.3), target MCU profile (`cortex-m4f`, `cortex-m0`, `rh850`) which toggles FPU-dependent rules (P1.6, P1.2). Searched upward from the analyzed path, like `.clang-format`.

### P2.3 — SARIF + JSON output for CI 🤖
Add `--format {html,json,sarif}`. SARIF gets you free annotations in GitHub/GitLab/Azure DevOps MR views and IDE problem panels.
- **Spec:** [SARIF 2.1.0 (OASIS)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- You already serialize findings in `findings_cache.json` — SARIF is a mapping layer on top.

### P2.4 — Test suite (this is the FTR guarantee) ✅
Create `tests/` with pytest:
- `tests/fixtures/true_positives/<rule_id>.c` — one minimal file per rule that MUST fire exactly once.
- `tests/fixtures/false_positives/<rule_id>_fp.c` — known traps that MUST NOT fire (e.g., `float` operand for C02, `sizeof` for H01, struct member for L05, string-brace for P0.6).
- `tests/test_preprocessor.py` — comment stripping edge cases (string with `//`, nested-looking `/* */`, line continuation).
- `tests/test_git_analyzer.py` — hunk-header parsing with synthetic diffs.
- `tests/test_llm_roundtrip.py` — P0.3 contract test.
- CI target: `pytest -q` green = every rule has ≥1 TP + ≥1 FP fixture. Mirrors your finance-cockpit test discipline (18/18 ✅).

### P2.5 — Replace pyautogui keystroke automation with an API call 🔁
`_run_automated_llm_verification()` (≈300 lines of sleep-and-pray VS Code focus juggling) is the most fragile component in the tool — one focus steal or extension update breaks it silently.
- **Preferred:** call the LLM API directly (`google-generativeai` or Claude API) with `automated_llm_prompt.md` + source content, parse the JSON contract from P0.3, generate `validated_action_report.html` in-process. Fully headless, CI-compatible, deterministic.
- **Fallback if corporate policy forbids API keys:** keep the keystroke path behind `--legacy-vscode-automation`, but add a clipboard-verification step (read clipboard back after copy) and abort cleanly on any window-activation failure instead of typing into the void.

### P2.6 — Performance & scale
- Pre-compile is done (module-level `re.compile`) ✅, but for directory scans add `multiprocessing.Pool` over files (analysis is embarrassingly parallel).
- HTML report with >500 findings becomes a multi-MB DOM. Cap rendered cards (e.g., top 300 by impact) with a "N more in JSON export" note.

### P2.7 — Minor report bugs
- `sortFindings('line')` returns 0 — implement by storing `data-line` on each card.
- `filterSeverity()` relies on the deprecated implicit global `event`; pass `this`/event explicitly.
- `Tool Precision` div-by-zero is guarded ✅ but shows `0%` when `original_total=0` — show `—` instead.

---

## 🟢 PHASE 3 — Architecture & Future

### P3.1 — Split the monolith into a package 📦
```
cpu_opt/
├── __init__.py
├── models.py          # Severity, Finding, Rule
├── preprocessor.py    # strip_comments, mask_strings, loop/function finders
├── rules/
│   ├── __init__.py    # registry
│   ├── arithmetic.py  # C01–C04, C07–C08, H06, H08, M08, L03
│   ├── loops.py       # C05, H01, H03, H04, M03, M05
│   ├── memory.py      # C06, H05, H07, M07, L04, L05
│   └── structure.py   # H02, M01, M02, M06, L01, L02
├── engine.py
├── report/            # html.py, sarif.py, json_out.py, shared_css.py  ← dedupe the 2× duplicated CSS
├── llm/               # export.py, parser.py, api_client.py
├── git_analyzer.py
├── gui.py
└── cli.py
```
Keep a thin `cpu_load_optimizer.py` shim for backward compatibility. The duplicated ~400-line CSS block (template vs validated report) becomes one `shared_css.py` constant.

### P3.2 — Optional real-parser backend 🌳
Regex will always have a ceiling. Add an opt-in AST backend (`--backend tree-sitter`):
- [py-tree-sitter](https://github.com/tree-sitter/py-tree-sitter) + [tree-sitter-c](https://github.com/tree-sitter/tree-sitter-c) — fast, error-tolerant (handles AUTOSAR macro soup better than pycparser), no preprocessor needed.
- Architecture: each rule declares `supports_ast: bool`; engine routes per backend. Start by porting the highest-FP rules (M01, H08, H05) — AST kills their false positives almost entirely.
- Alternative: [libclang Python bindings](https://libclang.readthedocs.io/) — most accurate, but needs include paths (painful for embedded SDKs).

### P3.3 — More verified rules worth adding later 📚
- Branch inside hot loop hoistable (loop unswitching candidate) — [Dragon Book Ch.10 / LLVM LoopUnswitch](https://llvm.org/docs/Passes.html#loop-unswitch-unswitch-loops)
- Missing `restrict` on non-aliasing pointer params — [C11 §6.7.3.1 / GCC docs](https://gcc.gnu.org/onlinedocs/gcc/Restricted-Pointers.html)
- `printf`-family in non-debug build paths (huge code+cycles on MCU)
- `%` by non-power-of-2 constant in hot loop → suggest reciprocal/decrement pattern
- Struct field ordering causing padding (cache/bus efficiency) — pairs nicely with your DAPM/ULFX struct-heavy code

### P3.4 — Versioned rule documentation
Generate `RULES.md` from the registry (id, severity, rationale, evidence link, fixture link) so colleagues can review/challenge rules in a PR instead of reading Python.

### P3.5 — GUI niceties (lowest priority)
Persist last-used paths to a small `~/.cpuopt_gui.json`; add a "Copy validation prompt" button so the manual Gemini flow is 1 click even without automation.

---

## 🗺️ Suggested Claude Code Execution Order

```
Session 1 (P0):  P0.4 → P0.7 → P0.2 → P0.6 → P0.1 → P0.5 → P0.3      + fixtures as you go
                 (P0.7 second — a ~20-line validator that kills the most embarrassing FP class)
Session 2 (P1):  P1.6 → P1.1 → P1.2 (new rules) → P1.7 → P1.8 → P1.5 → P1.3 → P1.4 → P1.9
Session 2b:      P1.10 new researched rules — order: C09 → M11 → M12 → H09 → H10 → M10 → M09
                 (every new rule lands with TP + FP fixtures BEFORE merging)
Session 3 (P2):  P2.4 (tests FIRST) → P2.1 → P2.2 → P2.3 → P2.7 → P2.5 → P2.6
Session 4 (P3):  P3.1 refactor → P3.2 spike → P3.3/P3.4
```
Rule of thumb per session: run the full fixture suite before and after; finding-count diffs must be explainable.

---

## 📚 Reference Library (verify claims here)

| Topic | Source |
|-------|--------|
| MISRA C:2012 (rules 6.1, 7.1, 8.8, 8.13, 9.1, 10.x, 13.3, 16.4, 21.3) | https://misra.org.uk/ |
| ARM Cortex-M4 TRM (instruction timing, FPU) | https://developer.arm.com/documentation/100166/0001 |
| Arm AAPCS (call overhead, parameter passing) | https://github.com/ARM-software/abi-aa/blob/main/aapcs32/aapcs32.rst |
| float vs double on Cortex-M4 | https://developer.arm.com/documentation/ka005775/latest |
| GCC optimization & warning options | https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html |
| SEI CERT C Coding Standard | https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard |
| SARIF 2.1.0 spec | https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html |
| Clang-Tidy suppression model | https://clang.llvm.org/extra/clang-tidy/ |
| py-tree-sitter / tree-sitter-c | https://github.com/tree-sitter/py-tree-sitter |
| Compilers: Principles, Techniques & Tools (loop opt theory) | https://suif.stanford.edu/dragonbook/ |
| Constant folding (compile-time evaluation of literal expressions) | https://en.wikipedia.org/wiki/Constant_folding |
| Stanford CS107 — constant folding at -O0 vs -O2 with disassembly proof | https://web.stanford.edu/class/archive/cs/cs107/cs107.1206/lectures/15/Lecture15.pdf |
| ARM — Writing Efficient Code for ARM (count-down loops, restrict, alignment) | https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/8009/1/580-Writing_Efficient_Code_for_ARM.pdf |
| Embedded.com — Engineering embedded software, Part 2 (loops, pragmas, do-while) | https://www.embedded.com/engineering-embedded-software-for-optimum-performance-part-2-more-c-code-techniques/ |
| Embedded C Optimization Techniques (division cost, type conversion, const→ROM) | https://slideshare.net/EmertxeSlides/embedded-c-optimization-techniques |
| Alif — Cortex-M55 optimization (why manual loop unrolling is now an anti-pattern) | https://alifsemi.com/whitepaper/cortex-m55-optimization-and-tools/ |

---

*Generated 2026-06-10 · Review of cpu_load_optimizer.py v1.0 · KSS Platform Team*
