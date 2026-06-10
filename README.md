# CPU Load Optimizer — Static Analysis Tool for Embedded C/H Source Code

## 1. Project Overview

| Field | Detail |
|-------|--------|
| **Tool Name** | `cpu_load_optimizer` |
| **Purpose** | Statically analyze `.c` and `.h` files to detect CPU load optimization opportunities |
| **Language** | Python 3.8+ (no external LLM dependency) |
| **Target Domain** | Embedded C — Ultrasonic Sensor Platform (KSS Project) |
| **Output** | Interactive HTML report with severity-sorted findings |
| **Methodology** | Rule-based regex + AST-lite pattern matching against 25+ verified optimization rules |

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    cpu_load_optimizer.py                  │
├──────────────┬───────────────┬───────────────────────────┤
│  CLI Module  │  Core Engine  │  Report Generator         │
│  (argparse)  │  (Analyzer)   │  (HTML + Screenshot)      │
├──────────────┼───────────────┼───────────────────────────┤
│  - file/dir  │  - Preprocess │  - Jinja2-like templating │
│  - filters   │  - Tokenize   │  - Syntax highlighting    │
│  - output    │  - Pattern    │  - Impact sorting         │
│              │    Match      │  - Code annotation        │
│              │  - Classify   │  - Summary dashboard      │
│              │  - Score      │                           │
└──────────────┴───────────────┴───────────────────────────┘
```

### Data Flow

```
Input (.c/.h files)
       │
       ▼
┌─────────────────┐
│  Preprocessor   │  → Strip comments, normalize whitespace
│                 │  → Track line numbers accurately
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Rule Engine    │  → 25+ optimization rules organized by category
│                 │  → Each rule: regex pattern + context validator
│                 │  → Impact scoring (Critical/High/Medium/Low)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Finding Model  │  → rule_id, severity, line, code_snippet,
│                 │  → description, recommendation, evidence_url
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Report Gen     │  → Self-contained HTML with embedded CSS/JS
│                 │  → Annotated code screenshots (PIL-based)
│                 │  → Sortable/filterable dashboard
└─────────────────┘
```

---

## 3. Optimization Rules — Verified & Evidence-Backed

All rules below are sourced from industry-standard references: MISRA C, Renesas Application Notes, Embedded.com engineering guides, IEEE/ACM publications, and GCC/ARM compiler documentation. Each rule includes its evidence source.

### 3.1 CRITICAL Impact (Highest CPU Savings)

| ID | Rule Name | Pattern Detected | Why It Matters | Evidence |
|----|-----------|-----------------|----------------|----------|
| C01 | **Float in Integer Context** | `float`/`double` variables used in computations that could be integer | FPU operations cost 10-70x more cycles than integer on most MCUs without hardware FPU | Renesas Embedded C Programming III; ARM Cortex-M docs |
| C02 | **Division by Power of 2** | `x / 2`, `x / 4`, `x / 8`, `x / 16` ... `x / 1024` etc. | Integer division costs 12-20 cycles vs 1-2 cycles for bit shift | Renesas AppNote; GCC optimization docs |
| C03 | **Modulo by Power of 2** | `x % 2`, `x % 4`, `x % 8` etc. | Modulo compiles to expensive `DIV`; bitmask `x & (N-1)` is single cycle | ARM Architecture Reference Manual |
| C04 | **Multiply by Power of 2** | `x * 2`, `x * 4`, `x * 8` etc. | `MUL` costs 3-12 cycles vs 1 cycle for shift on many embedded cores | Renesas Embedded C III: "MUL takes 12-20 cycles, shift takes 2 cycles" |
| C05 | **Expensive Math in Loops** | `sqrt()`, `sin()`, `cos()`, `tan()`, `pow()`, `log()`, `exp()` inside loops | Math library calls cost 50-200+ cycles each; in loops this multiplies enormously | Embedded.com Optimization Guide; IEEE Embedded Systems Letters |
| C06 | **Dynamic Memory in Runtime** | `malloc()`, `calloc()`, `realloc()`, `free()` | Heap allocation is non-deterministic, causes fragmentation, wastes cycles | MISRA C Rule 21.3; AUTOSAR C++14 Rule A18-5-1 |

### 3.2 HIGH Impact

| ID | Rule Name | Pattern Detected | Why It Matters | Evidence |
|----|-----------|-----------------|----------------|----------|
| H01 | **Loop-Invariant Computation** | Expressions inside loop body whose operands don't change per iteration | Redundant recomputation every iteration; hoist outside loop | Aho, Sethi, Ullman — "Dragon Book" Compilers Ch.10 |
| H02 | **Recursive Function Calls** | Functions calling themselves | Stack overhead per call; iterative equivalent saves stack + branch penalty | MISRA C Dir 4.1; Embedded.com Performance Guide |
| H03 | **strlen() in Loop Condition** | `for(i=0; i<strlen(s); i++)` | Recomputes O(n) string length every iteration → O(n²) total | SEI CERT C Coding Standard — STR31-C |
| H04 | **Function Call in Tight Loop** | Non-inline function calls inside small loops | Each call has prologue/epilogue overhead (push/pop registers) | ARM Procedure Call Standard (AAPCS); Embedded.com |
| H05 | **Oversized Data Types** | `int` or `long` where `uint8_t`/`uint16_t` suffices (heuristic) | Wider types consume more bus cycles, cache, and memory bandwidth | MISRA C Rule 10.1-10.4; Renesas AppNote |
| H06 | **Floating-Point Comparison** | `==` or `!=` with `float`/`double` operands | Unreliable results + FPU comparison is slower than integer | MISRA C Rule 13.3; IEEE 754 Standard |
| H07 | **Large Struct Pass-by-Value** | Functions receiving struct parameters by value | Copies entire struct to stack on each call; use pointer instead | Embedded.com Engineering Embedded Software Part 1 |
| H08 | **Repeated Identical Computation** | Same expression computed multiple times in same scope | Wastes cycles recalculating known results; use temp variable | Common Subexpression Elimination — standard compiler theory |

### 3.3 MEDIUM Impact

| ID | Rule Name | Pattern Detected | Why It Matters | Evidence |
|----|-----------|-----------------|----------------|----------|
| M01 | **Missing `const` Qualifier** | Pointer parameters that are never written to | Without `const`, compiler assumes aliasing, blocks optimizations | MISRA C Rule 8.13; GCC optimization manual |
| M02 | **Missing `static` on Internal Functions** | Functions not declared `static` that are only used in one file | Prevents compiler from inlining and eliminates symbol export overhead | MISRA C Rule 8.8; GCC inter-procedural optimization |
| M03 | **Global Variable in Loop** | Reading/writing global or `extern` variables inside loops | Compiler must reload from memory each iteration (can't register-allocate) | Embedded.com Optimization Guide; Patterson & Hennessy |
| M04 | **Post-increment in Non-Value Context** | `i++` where `++i` would be equivalent (iterator context) | For complex types, post-increment creates temporary copy | Effective C++; Meyers — applies mainly to C++ but good habit |
| M05 | **Nested Loop Depth > 3** | Loops nested 4+ levels deep | Exponential complexity growth; often indicates algorithmic issue | Code Complete (McConnell); cyclomatic complexity research |
| M06 | **Switch Without Default** | `switch` statements missing `default` case | Missed optimization: compiler can't eliminate branch for unknown values | MISRA C Rule 16.4 |
| M07 | **Bit-field Operations on Non-unsigned** | Signed bit-fields | Implementation-defined behavior; unsigned is faster for bit ops | MISRA C Rule 6.1 |
| M08 | **Unnecessary Type Cast Chain** | Multiple sequential casts `(type2)(type1)var` | Each cast may generate conversion instructions | MISRA C Rules 10.3-10.5 |

### 3.4 LOW Impact (Style / Minor Savings)

| ID | Rule Name | Pattern Detected | Why It Matters | Evidence |
|----|-----------|-----------------|----------------|----------|
| L01 | **Magic Numbers** | Numeric literals (not 0, 1, -1) without `#define` or `const` | Prevents compiler constant folding across translation units | MISRA C Rule 7.1; Clean Code (Martin) |
| L02 | **Missing `volatile` on HW Register** | Pointer dereferences to common HW register address patterns | Without volatile, compiler may cache/eliminate critical reads | MISRA C Rule 2.2; ARM CMSIS guidelines |
| L03 | **Long If-Else Chain** | 5+ `if/else if` branches that could be a `switch` | Switch may compile to jump table (O(1)) vs sequential branch (O(n)) | GCC Internals — jump table optimization |
| L04 | **Computation in Array Index** | Complex expressions as array indices inside loops | Pre-compute index to help compiler with addressing mode selection | Patterson & Hennessy — Computer Organization |
| L05 | **Uninitialized Data** | Variables declared without initialization | Uninitialized data in BSS requires runtime zeroing; initialized goes to DATA | Renesas Embedded C III — data initialization section |

---

## 4. Implementation Modules

### 4.1 `cpu_load_optimizer.py` — Main Entry Point

```
Responsibilities:
  - CLI argument parsing (argparse)
  - File discovery (glob .c/.h)
  - Orchestrate analysis pipeline
  - Invoke report generation

CLI Interface:
  python cpu_load_optimizer.py <target> [options]

Arguments:
  <target>              Path to .c/.h file or directory

Options:
  --output, -o          Output HTML report path (default: report.html)
  --severity, -s        Minimum severity to report: critical|high|medium|low (default: low)
  --category, -c        Filter by category (e.g., "loop", "memory", "arithmetic")
  --annotate            Enable code screenshot annotations (requires Pillow)
  --verbose, -v         Print findings to console as well
```

### 4.2 `preprocessor.py` — Source Preparation

```
Responsibilities:
  - Read source file with encoding detection
  - Strip single-line (//) and multi-line (/* */) comments
  - Preserve line number mapping (critical for accurate reporting)
  - Normalize whitespace while keeping structure
  - Extract #include, #define, typedef info for context
  - Build simple scope tracker (function boundaries)

Key Functions:
  strip_comments(source: str) -> (str, line_map)
  extract_functions(source: str) -> List[FunctionInfo]
  extract_defines(source: str) -> Dict[str, str]
  extract_typedefs(source: str) -> Dict[str, str]
```

### 4.3 `rules_engine.py` — Pattern Matching Core

```
Responsibilities:
  - Define all optimization rules as Rule objects
  - Each Rule contains:
      - id: str (e.g., "C01")
      - name: str
      - severity: Enum (CRITICAL, HIGH, MEDIUM, LOW)
      - category: str
      - pattern: compiled regex or callable
      - validator: callable (context check to reduce false positives)
      - description: str
      - recommendation: str
      - evidence: str (URL or reference)
      - impact_score: int (1-100)
  - Execute all rules against preprocessed source
  - Return List[Finding]

Finding Model:
  @dataclass
  class Finding:
      rule_id: str
      rule_name: str
      severity: str
      category: str
      file_path: str
      line_number: int
      column: int
      code_snippet: str          # 5-line context window
      description: str
      recommendation: str
      evidence: str
      impact_score: int
      suggested_fix: str         # Concrete code replacement
```

### 4.4 `report_generator.py` — HTML Output

```
Responsibilities:
  - Generate self-contained HTML report (no external dependencies)
  - Embedded CSS for styling + JS for interactivity
  - Dashboard header with:
      - File(s) analyzed
      - Total findings by severity
      - Estimated CPU impact score
      - Pie/bar chart (pure CSS)
  - Findings table:
      - Sortable by severity, impact score, line number
      - Filterable by category
      - Expandable rows with code snippet + recommendation
  - Each finding shows:
      - Source code with syntax highlighting (embedded)
      - The problematic line highlighted in red
      - Recommended replacement highlighted in green
      - Evidence link
  - Summary section with top-5 highest-impact recommendations
```

### 4.5 `annotator.py` — (Bonus) Code Screenshot Annotations

```
Responsibilities:
  - Render code snippet as image using Pillow (PIL)
  - Highlight the problematic line
  - Draw annotation arrows pointing to the issue
  - Write the suggested fix text alongside
  - Save as PNG embedded in HTML report (base64)

Dependencies:
  - Pillow (PIL) — optional, graceful fallback if not installed
  - Uses monospace font rendering
  - Color coding: red = issue, green = fix
```

---

## 5. Detection Strategies (Technical Detail)

### 5.1 Regex-Based Detection (Primary)

Most rules use compiled regex patterns operating on preprocessed source. Examples:

```python
# C02: Division by power of 2
r'(\w+)\s*/\s*(2|4|8|16|32|64|128|256|512|1024)\b'

# C05: Math functions in loops
# Two-pass: first find loop bodies, then search for math calls within
r'\b(sqrt|sin|cos|tan|atan|pow|log|exp|fabs|ceil|floor)\s*\('

# H03: strlen in loop condition
r'for\s*\([^;]*;[^;]*strlen\s*\('

# H06: Float comparison
r'(\bfloat\b|\bdouble\b).*?(==|!=)'
```

### 5.2 Context-Aware Validation (False Positive Reduction)

Each regex match goes through a validator function:

```python
def validate_div_power_of_2(match, context):
    # Check it's not inside a comment (already stripped)
    # Check the dividend is not a float type
    # Check it's not inside a #define that's clearly a constant expression
    # Check the divisor is indeed a compile-time constant
    return is_integer_context(match, context)
```

### 5.3 Scope Tracking (Lightweight AST)

A simple brace-counting scope tracker identifies:
- Function boundaries (to detect recursion, static candidates)
- Loop bodies (to find loop-invariant code, function calls in loops)
- Struct definitions (to estimate struct sizes for pass-by-value detection)

---

## 6. Project Structure

```
cpu_load_optimizer/
├── cpu_load_optimizer.py    # Main entry point + CLI
├── preprocessor.py          # Comment stripping, line mapping
├── rules_engine.py          # All 25+ rules + matching engine
├── report_generator.py      # HTML report builder
├── annotator.py             # (Bonus) Code screenshot annotations
├── models.py                # Data classes (Finding, Rule, etc.)
├── utils.py                 # Helper functions
├── test_samples/            # Sample .c/.h files for validation
│   ├── sample_good.c        # Clean code (should have few findings)
│   ├── sample_bad.c         # Code with known issues (validation)
│   └── sample_ultrasonic.c  # Domain-specific test case
└── README.md                # Usage instructions
```

---

## 7. Deployment

```bash
# Minimal install (no screenshot feature)
pip install --user cpu_load_optimizer
# or just copy the directory and run:
python cpu_load_optimizer.py /path/to/source --output report.html

# Full install (with screenshot annotations)
pip install Pillow
python cpu_load_optimizer.py /path/to/source --output report.html --annotate
```

### CI / pre-commit gating (`--fail-on`)

`--fail-on {critical,high,medium,low}` makes the process exit **1** when any
finding is at or above the given severity, and exit **2** on a tool crash
(so pipelines can tell "found issues" from "the analyzer broke"). Without it
the tool always exits 0 (backward compatible).

```bash
# Block a commit if any CRITICAL CPU-load issue is staged
python cpu_load_optimizer.py --staged . --fail-on critical
```

`.git/hooks/pre-commit` (or a `pre-commit` hook entry):

```bash
#!/bin/sh
python cpu_load_optimizer.py --staged . --fail-on critical || {
    echo "CPU Load Optimizer found CRITICAL findings — commit blocked."
    exit 1
}
```

### LLM validation round-trip (`--apply-validation`)

```bash
# 1. Analyze and emit the LLM validation package (writes findings_cache.json)
python cpu_load_optimizer.py src/ --llm-export

# 2. Send Output/llm_validation/automated_llm_prompt.md to your LLM and save
#    its fenced JSON reply (the {"verdicts":[…]} block) as reply.json

# 3. Build the developer report from only the confirmed true positives
python cpu_load_optimizer.py --apply-validation reply.json \
    --cache Output/llm_validation/findings_cache.json \
    -o validated_action_report.html
```

The JSON contract (`finding_index` joins back to the cache) is the canonical
machine-readable format; the legacy `[C01] … VERDICT:` text format is still
parsed as a fallback.

**Requirements:**
- Python 3.8+ (standard library only for core functionality)
- Pillow (optional, for `--annotate` feature)
- No network access needed — fully offline
- No LLM dependency — deterministic rule-based analysis

---

## 8. Validation Strategy

| Test | Method | Expected Result |
|------|--------|-----------------|
| True Positive Rate | Run against `sample_bad.c` with known issues planted | All 25+ rule types detected |
| False Positive Rate | Run against `sample_good.c` (optimized code) | < 5 false positives |
| Performance | Run against 50,000-line codebase | < 30 seconds total |
| Report Accuracy | Manual review of top-10 findings | All recommendations are correct |
| Edge Cases | Macros, multi-line statements, nested preprocessor | No crashes, graceful handling |

---

## 9. Future Enhancements

1. **Call Graph Analysis** — Detect indirect recursion, dead code paths
2. **Cross-File Analysis** — Track global variable usage across translation units
3. **Custom Rule DSL** — Allow team to add project-specific rules via YAML config
4. **AUTOSAR/MISRA Compliance Mode** — Flag findings that also violate safety standards
5. **CI/CD Integration** — Exit code based on severity thresholds
6. **Diff Mode** — Only analyze changed lines (git integration)
7. **Benchmark Database** — Track findings over time, measure optimization progress
