#!/usr/bin/env python3
"""
CPU Load Optimizer — Static Analysis Tool for Embedded C/H Source Code
=====================================================================
Analyzes .c and .h files for CPU load optimization opportunities using
25+ verified, industry-standard rules. No LLM dependency.

Usage:
    python cpu_load_optimizer.py                        → Launch GUI
    python cpu_load_optimizer.py --gui                  → Launch GUI
    python cpu_load_optimizer.py <file_or_dir> [opts]   → Analyze file(s)
    python cpu_load_optimizer.py --staged <repo> [opts] → Analyze staged changes

Options:
    --output, -o     Output HTML report path (default: Output/)
    --severity, -s   Minimum severity: critical|high|medium|low
    --annotate       Enable code screenshot annotations (requires Pillow)
    --llm-export     Generate LLM validation export for Gemini/GPT review
    --staged REPO    Analyze only staged git changes in REPO
    --gui            Launch graphical interface
    --verbose, -v    Print findings to console

Author: KSS Platform Team
References:
    - MISRA C:2012 Guidelines
    - Renesas Embedded C Programming III Application Note
    - ARM Architecture Reference Manual
    - Embedded.com Engineering Embedded Software Guide
    - SEI CERT C Coding Standard
    - GCC Optimization Documentation
"""

import argparse
import os
import re
import sys
import html
import json
import subprocess
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import List, Dict, Tuple, Optional, Callable, Set
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

# ============================================================================
# MODELS
# ============================================================================

class Severity(IntEnum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls[s.upper()]


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    category: str
    file_path: str
    line_number: int
    code_snippet: str
    matched_text: str
    description: str
    recommendation: str
    suggested_fix: str
    evidence: str
    impact_score: int  # 1-100

    @property
    def severity_name(self) -> str:
        return self.severity.name

    @property
    def severity_color(self) -> str:
        return {
            Severity.CRITICAL: "#dc2626",
            Severity.HIGH: "#ea580c",
            Severity.MEDIUM: "#ca8a04",
            Severity.LOW: "#2563eb",
        }[self.severity]

    @property
    def severity_bg(self) -> str:
        return {
            Severity.CRITICAL: "#fef2f2",
            Severity.HIGH: "#fff7ed",
            Severity.MEDIUM: "#fefce8",
            Severity.LOW: "#eff6ff",
        }[self.severity]


@dataclass
class Rule:
    id: str
    name: str
    severity: Severity
    category: str
    pattern: Optional[re.Pattern]
    validator: Optional[Callable]
    description: str
    recommendation: str
    evidence: str
    impact_score: int
    fix_template: str = ""
    needs_context: bool = False


# ============================================================================
# PREPROCESSOR
# ============================================================================

class Preprocessor:
    """Strips comments, tracks line numbers, extracts structural info."""

    @staticmethod
    def strip_comments(source: str) -> Tuple[str, Dict[int, int]]:
        """Remove C/C++ comments while preserving line numbers."""
        result = []
        line_map = {}
        i = 0
        current_line = 1
        output_line = 1
        in_string = False
        string_char = None
        n = len(source)

        while i < n:
            # Track newlines
            if source[i] == '\n':
                result.append('\n')
                line_map[output_line] = current_line
                current_line += 1
                output_line += 1
                i += 1
                in_string = False
                continue

            # String literals — don't strip inside strings
            if not in_string and source[i] in ('"', "'"):
                in_string = True
                string_char = source[i]
                result.append(source[i])
                i += 1
                continue
            elif in_string:
                if source[i] == '\\' and i + 1 < n:
                    result.append(source[i:i+2])
                    i += 2
                    continue
                if source[i] == string_char:
                    in_string = False
                result.append(source[i])
                i += 1
                continue

            # Single-line comment
            if i + 1 < n and source[i] == '/' and source[i+1] == '/':
                while i < n and source[i] != '\n':
                    i += 1
                continue

            # Multi-line comment
            if i + 1 < n and source[i] == '/' and source[i+1] == '*':
                i += 2
                while i + 1 < n and not (source[i] == '*' and source[i+1] == '/'):
                    if source[i] == '\n':
                        result.append('\n')
                        line_map[output_line] = current_line
                        current_line += 1
                        output_line += 1
                    i += 1
                i += 2  # skip */
                continue

            result.append(source[i])
            i += 1

        line_map[output_line] = current_line
        return ''.join(result), line_map

    @staticmethod
    def get_context(lines: List[str], line_idx: int, window: int = 2) -> str:
        """Get surrounding lines for context."""
        start = max(0, line_idx - window)
        end = min(len(lines), line_idx + window + 1)
        ctx_lines = []
        for i in range(start, end):
            marker = ">>>" if i == line_idx else "   "
            ctx_lines.append(f"{marker} {i+1:4d} | {lines[i]}")
        return '\n'.join(ctx_lines)

    @staticmethod
    def find_loop_bodies(source: str) -> List[Tuple[int, int, str]]:
        """Find loop start/end line numbers and their body content."""
        loops = []
        lines = source.split('\n')
        loop_pattern = re.compile(r'^\s*(for|while|do)\s*[\(\{]')

        i = 0
        while i < len(lines):
            m = loop_pattern.match(lines[i])
            if m:
                loop_start = i
                brace_count = 0
                body_lines = []
                found_open = False

                for j in range(i, len(lines)):
                    line = lines[j]
                    for ch in line:
                        if ch == '{':
                            brace_count += 1
                            found_open = True
                        elif ch == '}':
                            brace_count -= 1
                    body_lines.append(line)
                    if found_open and brace_count == 0:
                        loops.append((loop_start, j, '\n'.join(body_lines)))
                        break
            i += 1
        return loops

    @staticmethod
    def find_function_bodies(source: str) -> List[Dict]:
        """Extract function name, start line, end line, and body."""
        functions = []
        lines = source.split('\n')
        # Match function definitions (simplified — works for most C code)
        func_pattern = re.compile(
            r'^[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{?\s*$'
        )

        i = 0
        while i < len(lines):
            m = func_pattern.match(lines[i])
            if m:
                name = m.group(1)
                # Skip if it's a control keyword
                if name in ('if', 'else', 'for', 'while', 'do', 'switch',
                            'return', 'case', 'sizeof', 'typedef', 'struct',
                            'union', 'enum'):
                    i += 1
                    continue

                func_start = i
                brace_count = 0
                found_open = False
                body_lines = []

                for j in range(i, len(lines)):
                    line = lines[j]
                    for ch in line:
                        if ch == '{':
                            brace_count += 1
                            found_open = True
                        elif ch == '}':
                            brace_count -= 1
                    body_lines.append(line)
                    if found_open and brace_count == 0:
                        functions.append({
                            'name': name,
                            'start': func_start,
                            'end': j,
                            'body': '\n'.join(body_lines)
                        })
                        break
            i += 1
        return functions


# ============================================================================
# RULES ENGINE — 25+ Verified Optimization Rules
# ============================================================================

class RulesEngine:
    """Defines and executes all CPU load optimization rules."""

    def __init__(self):
        self.rules = self._build_rules()

    def _build_rules(self) -> List[Rule]:
        rules = []

        # ── CRITICAL ─────────────────────────────────────────────────────

        rules.append(Rule(
            id="C01", name="Float in Potential Integer Context",
            severity=Severity.CRITICAL, category="Arithmetic",
            pattern=re.compile(
                r'\b(float|double)\s+\w+\s*=\s*\d+\s*;'
            ),
            validator=None,
            description=(
                "A floating-point variable is initialized with a pure integer "
                "literal. If this value never requires fractional precision, "
                "using an integer type would avoid expensive FPU operations. "
                "On MCUs without hardware FPU, float ops cost 10-70x more "
                "CPU cycles than integer equivalents."
            ),
            recommendation=(
                "Evaluate whether this variable truly needs floating-point "
                "precision. If it represents counts, indices, flags, or "
                "thresholds that are always whole numbers, switch to "
                "uint32_t, int32_t, or a narrower integer type."
            ),
            evidence=(
                "Renesas Embedded C Programming III — FPU vs ALU cycle cost; "
                "ARM Cortex-M4 TRM — software FP emulation overhead"
            ),
            impact_score=90,
            fix_template="Replace 'float/double' with appropriate integer type"
        ))

        rules.append(Rule(
            id="C02", name="Division by Power of 2",
            severity=Severity.CRITICAL, category="Arithmetic",
            pattern=re.compile(
                r'(\w+)\s*/\s*(2|4|8|16|32|64|128|256|512|1024|2048|4096)\b'
            ),
            validator=self._validate_not_float_context,
            description=(
                "Integer division by a constant power of 2 detected. "
                "Hardware integer division (DIV) costs 12-20+ CPU cycles "
                "on most embedded processors, while an equivalent right "
                "bit-shift (>>) costs only 1-2 cycles."
            ),
            recommendation=(
                "Replace `x / N` with `x >> log2(N)` for unsigned integers. "
                "For signed integers, be aware that right-shift of negative "
                "values is implementation-defined; use unsigned types or "
                "explicit handling."
            ),
            evidence=(
                "Renesas Embedded C III: 'MUL takes 12-20 cycles, SHIFT "
                "takes 2 cycles'; ARM Architecture Ref Manual — instruction "
                "cycle counts"
            ),
            impact_score=85,
            fix_template="x / {N} → x >> {shift}"
        ))

        rules.append(Rule(
            id="C03", name="Modulo by Power of 2",
            severity=Severity.CRITICAL, category="Arithmetic",
            pattern=re.compile(
                r'(\w+)\s*%\s*(2|4|8|16|32|64|128|256|512|1024|2048|4096)\b'
            ),
            validator=self._validate_not_float_context,
            description=(
                "Modulo operation with a power-of-2 constant detected. "
                "The modulo operator compiles to an expensive DIV instruction. "
                "For powers of 2, a bitmask (AND) achieves the same result "
                "in a single cycle."
            ),
            recommendation=(
                "Replace `x % N` with `x & (N - 1)` for unsigned integers. "
                "Example: `x % 16` becomes `x & 0x0F`."
            ),
            evidence=(
                "ARM Architecture Ref Manual — AND vs DIV cycle counts; "
                "GCC source — strength reduction optimization pass"
            ),
            impact_score=85,
            fix_template="x % {N} → x & ({N} - 1)"
        ))

        rules.append(Rule(
            id="C04", name="Multiplication by Power of 2",
            severity=Severity.CRITICAL, category="Arithmetic",
            pattern=re.compile(
                r'(\w+)\s*\*\s*(2|4|8|16|32|64|128|256|512|1024|2048|4096)\b'
            ),
            validator=self._validate_not_float_context,
            description=(
                "Integer multiplication by a constant power of 2 detected. "
                "While many compilers optimize this automatically, some "
                "embedded compilers with low optimization levels do not. "
                "MUL can cost 3-12 cycles vs 1 cycle for left-shift."
            ),
            recommendation=(
                "Replace `x * N` with `x << log2(N)`. Verify your compiler "
                "isn't already doing this by checking the disassembly."
            ),
            evidence=(
                "Renesas Embedded C III — MUL vs SHIFT cycle comparison; "
                "ARM Cortex-M instruction timing tables"
            ),
            impact_score=75,
            fix_template="x * {N} → x << {shift}"
        ))

        rules.append(Rule(
            id="C05", name="Expensive Math Function in Loop",
            severity=Severity.CRITICAL, category="Loop",
            pattern=re.compile(
                r'\b(sqrt|sqrtf|sin|sinf|cos|cosf|tan|tanf|atan|atan2|'
                r'pow|powf|log|logf|log10|exp|expf|fabs|fabsf|'
                r'ceil|ceilf|floor|floorf|asin|acos)\s*\('
            ),
            validator=None,
            description=(
                "Expensive math library function detected. These functions "
                "typically cost 50-200+ CPU cycles each. If called inside "
                "a loop, the total cost multiplies by iteration count."
            ),
            recommendation=(
                "Consider: (1) Pre-compute results outside the loop if "
                "inputs don't change per iteration. (2) Use lookup tables "
                "for trigonometric functions with known input ranges. "
                "(3) Use fixed-point approximations. (4) Use CORDIC "
                "algorithms for sin/cos on MCUs without FPU."
            ),
            evidence=(
                "Embedded.com Optimization Guide; ARM Cortex-M4 FPU "
                "instruction timing; Renesas AppNote on lookup tables"
            ),
            impact_score=92,
            fix_template="Pre-compute, use lookup table, or use fixed-point approximation",
            needs_context=True  # Check if inside loop
        ))

        rules.append(Rule(
            id="C06", name="Dynamic Memory Allocation",
            severity=Severity.CRITICAL, category="Memory",
            pattern=re.compile(
                r'\b(malloc|calloc|realloc|free)\s*\('
            ),
            validator=None,
            description=(
                "Dynamic memory allocation detected. In embedded systems, "
                "heap operations are non-deterministic in execution time, "
                "cause memory fragmentation, and add significant overhead "
                "for bookkeeping. This directly impacts CPU load and "
                "worst-case execution time (WCET)."
            ),
            recommendation=(
                "Replace with static allocation, memory pools, or "
                "stack-based allocation. Pre-allocate buffers at init time. "
                "Use fixed-size arrays where possible."
            ),
            evidence=(
                "MISRA C:2012 Rule 21.3 — prohibits stdlib memory "
                "allocation; AUTOSAR C++14 Rule A18-5-1"
            ),
            impact_score=88,
            fix_template="Replace with static allocation or memory pool"
        ))

        # ── HIGH ─────────────────────────────────────────────────────────

        rules.append(Rule(
            id="H01", name="Potential Loop-Invariant Computation",
            severity=Severity.HIGH, category="Loop",
            pattern=re.compile(
                r'\b(sizeof|strlen)\s*\([^)]+\)'
            ),
            validator=None,
            description=(
                "A function call that may return a constant result is used "
                "inside a scope that could be a loop body. If this value "
                "doesn't change per iteration, computing it once before "
                "the loop saves cycles proportional to the iteration count."
            ),
            recommendation=(
                "Hoist invariant computations outside the loop. Store the "
                "result in a local variable before the loop begins."
            ),
            evidence=(
                "Aho, Sethi, Ullman — Compilers: Principles, Techniques "
                "and Tools (Dragon Book) Ch.10 — Loop Optimization"
            ),
            impact_score=70,
            fix_template="const size_t len = strlen(s); // before loop",
            needs_context=True
        ))

        rules.append(Rule(
            id="H02", name="Recursive Function",
            severity=Severity.HIGH, category="Control Flow",
            pattern=None,  # Custom detection
            validator=None,
            description=(
                "Recursive function detected. Each recursive call adds "
                "stack frame overhead (register saves, stack pointer "
                "adjustment, return address push). For deep recursion, "
                "this causes stack overflow risk and significant CPU "
                "overhead."
            ),
            recommendation=(
                "Convert to iterative equivalent using explicit stack or "
                "accumulator pattern. Most recursive algorithms have "
                "direct iterative translations."
            ),
            evidence=(
                "MISRA C:2012 Directive 4.1 — run-time failures shall "
                "be minimized; stack overflow prevention"
            ),
            impact_score=72,
            fix_template="Convert to iterative implementation"
        ))

        rules.append(Rule(
            id="H03", name="strlen() in Loop Condition",
            severity=Severity.HIGH, category="Loop",
            pattern=re.compile(
                r'for\s*\([^;]*;\s*[^;]*\bstrlen\s*\([^)]*\)\s*[^;]*;'
            ),
            validator=None,
            description=(
                "strlen() is called in the loop condition. This means "
                "the O(n) strlen traversal executes on EVERY iteration, "
                "turning the loop from O(n) to O(n²) complexity."
            ),
            recommendation=(
                "Compute strlen() once before the loop: "
                "`size_t len = strlen(s); for (i = 0; i < len; i++)`"
            ),
            evidence=(
                "SEI CERT C Coding Standard STR31-C; widely documented "
                "performance anti-pattern"
            ),
            impact_score=80,
            fix_template="size_t len = strlen({var}); for(i=0; i<len; i++)"
        ))

        rules.append(Rule(
            id="H04", name="Function Call in Tight Loop",
            severity=Severity.HIGH, category="Loop",
            pattern=re.compile(
                r'(?:for|while)\s*\([^)]*\)\s*\{[^}]{0,200}\b(\w+)\s*\([^)]*\)\s*;'
            ),
            validator=self._validate_not_standard_func,
            description=(
                "A non-trivial function call detected inside a loop body. "
                "Each call incurs prologue/epilogue overhead (register "
                "push/pop, stack frame setup, branch and return). For "
                "tight loops, this overhead accumulates significantly."
            ),
            recommendation=(
                "Consider: (1) Marking the function as `inline` or "
                "`__attribute__((always_inline))`. (2) Moving the function "
                "body directly into the loop if it's small. (3) Using "
                "a macro for very simple operations."
            ),
            evidence=(
                "ARM AAPCS — Procedure Call Standard overhead; "
                "Embedded.com — Engineering Embedded Software Part 1"
            ),
            impact_score=68,
            fix_template="Mark function as inline or move body into loop"
        ))

        rules.append(Rule(
            id="H05", name="Potentially Oversized Data Type",
            severity=Severity.HIGH, category="Data Types",
            pattern=re.compile(
                r'\b(int|long|unsigned\s+int|unsigned\s+long)\s+\w+\s*='
                r'\s*(\d+)\s*;'
            ),
            validator=self._validate_oversized_type,
            description=(
                "An integer variable uses a type wider than necessary for "
                "its assigned value. On 8/16-bit MCUs, operations on "
                "32-bit types require multiple instructions. Even on "
                "32-bit MCUs, narrower types improve cache utilization."
            ),
            recommendation=(
                "Use the narrowest type that fits the value range: "
                "uint8_t (0-255), uint16_t (0-65535), int8_t (-128 to 127), "
                "int16_t (-32768 to 32767). Include <stdint.h>."
            ),
            evidence=(
                "MISRA C:2012 Rules 10.1-10.4 — essential type model; "
                "Renesas AppNote — data type sizing impact"
            ),
            impact_score=60,
            fix_template="Use uint8_t, uint16_t, or int16_t as appropriate"
        ))

        rules.append(Rule(
            id="H06", name="Floating-Point Equality Comparison",
            severity=Severity.HIGH, category="Arithmetic",
            pattern=re.compile(
                r'(?:float|double)\s+\w+[^;]*(?:==|!=)'
                r'|(?:==|!=)\s*[^;]*\b(?:float|double)\b'
            ),
            validator=None,
            description=(
                "Direct equality/inequality comparison of floating-point "
                "values detected. This is both unreliable (due to FP "
                "representation) and slower than integer comparison on "
                "most embedded architectures."
            ),
            recommendation=(
                "Use epsilon-based comparison: "
                "`fabs(a - b) < EPSILON` instead of `a == b`. "
                "Better yet, redesign to use integer/fixed-point if "
                "possible."
            ),
            evidence=(
                "MISRA C:2012 Rule 13.3 — FP equality; "
                "IEEE 754 Standard — representation precision limits"
            ),
            impact_score=65,
            fix_template="fabs(a - b) < EPSILON"
        ))

        rules.append(Rule(
            id="H07", name="Large Struct Pass-by-Value",
            severity=Severity.HIGH, category="Memory",
            pattern=re.compile(
                r'\b\w+\s+\w+\s*\([^)]*\bstruct\s+\w+\s+(?![\*])\w+[^)]*\)'
            ),
            validator=None,
            description=(
                "A struct appears to be passed by value to a function. "
                "This copies the entire struct onto the stack for each call. "
                "For large structs, this is a major CPU and memory waste."
            ),
            recommendation=(
                "Pass structs by pointer: "
                "`void func(const struct MyStruct *s)` instead of "
                "`void func(struct MyStruct s)`. Add `const` if the "
                "function doesn't modify the struct."
            ),
            evidence=(
                "Embedded.com — Engineering Embedded Software Part 1; "
                "ARM AAPCS — parameter passing conventions"
            ),
            impact_score=65,
            fix_template="Pass by const pointer instead of by value"
        ))

        rules.append(Rule(
            id="H08", name="Redundant Repeated Computation",
            severity=Severity.HIGH, category="Arithmetic",
            pattern=re.compile(
                r'(\w+\s*[\+\-\*\/\%\&\|\^]\s*\w+).*\1'
            ),
            validator=None,
            description=(
                "The same arithmetic expression appears to be computed "
                "multiple times in the same scope. Each redundant "
                "computation wastes CPU cycles."
            ),
            recommendation=(
                "Store the result in a local temporary variable and "
                "reuse it. The compiler may do CSE (Common Subexpression "
                "Elimination) at high optimization levels, but explicit "
                "caching guarantees it."
            ),
            evidence=(
                "Common Subexpression Elimination — standard compiler "
                "optimization theory; Dragon Book Ch.10"
            ),
            impact_score=62,
            fix_template="const type temp = expr; // reuse temp"
        ))

        # ── MEDIUM ───────────────────────────────────────────────────────

        rules.append(Rule(
            id="M01", name="Missing const on Read-Only Pointer Parameter",
            severity=Severity.MEDIUM, category="Qualifiers",
            pattern=re.compile(
                r'\b\w+\s+\w+\s*\(\s*(?:\w+\s+)*(\w+)\s*\*\s*\w+[^)]*\)'
            ),
            validator=self._validate_missing_const,
            description=(
                "A pointer parameter lacks a `const` qualifier. Without "
                "`const`, the compiler must assume the pointed-to data "
                "may be modified, preventing certain optimizations like "
                "register caching and instruction reordering."
            ),
            recommendation=(
                "Add `const` to pointer parameters that are not modified: "
                "`void func(const uint8_t *data)`. This enables compiler "
                "optimizations and documents intent."
            ),
            evidence=(
                "MISRA C:2012 Rule 8.13 — const pointer parameters; "
                "GCC optimization manual — restrict/const impact"
            ),
            impact_score=45,
            fix_template="Add const qualifier to pointer parameter"
        ))

        rules.append(Rule(
            id="M02", name="Non-static Internal Function",
            severity=Severity.MEDIUM, category="Linkage",
            pattern=re.compile(
                r'^(?!static\s)(?!extern\s)(?!inline\s)'
                r'(?!typedef\s)(?!struct\s)(?!union\s)(?!enum\s)'
                r'(?!#)(?!\s*\*)(?!return\s)'
                r'(\w[\w\s\*]*\s+)(\w+)\s*\([^)]*\)\s*\{',
                re.MULTILINE
            ),
            validator=None,
            description=(
                "A function is not declared `static` but may only be used "
                "within this translation unit. Non-static functions are "
                "globally visible, preventing the compiler from inlining "
                "them or eliminating unused code."
            ),
            recommendation=(
                "Add `static` to functions that are only used within "
                "the same .c file. This allows the compiler to inline "
                "them and eliminate symbol export overhead."
            ),
            evidence=(
                "MISRA C:2012 Rule 8.8 — function linkage; "
                "GCC inter-procedural optimization documentation"
            ),
            impact_score=42,
            fix_template="Add 'static' keyword to function definition"
        ))

        rules.append(Rule(
            id="M03", name="Global/Extern Variable Access in Loop",
            severity=Severity.MEDIUM, category="Loop",
            pattern=re.compile(
                r'\b(extern|volatile)\s+\w+\s+(\w+)\s*;'
            ),
            validator=None,
            description=(
                "A global or extern variable may be accessed inside a "
                "loop. The compiler must reload such variables from memory "
                "on each iteration (can't keep them in registers) because "
                "they could be modified by interrupts or other threads."
            ),
            recommendation=(
                "Cache the global variable in a local variable before "
                "the loop: `uint32_t local_copy = global_var;` Then use "
                "the local copy inside the loop. Write back after the "
                "loop if needed."
            ),
            evidence=(
                "Embedded.com — loop optimization; Patterson & Hennessy "
                "— register allocation principles"
            ),
            impact_score=50,
            fix_template="Cache in local variable before loop"
        ))

        rules.append(Rule(
            id="M05", name="Deeply Nested Loops (>3 levels)",
            severity=Severity.MEDIUM, category="Loop",
            pattern=re.compile(
                r'(?:for|while)\s*\([^)]*\)\s*\{[^}]*'
                r'(?:for|while)\s*\([^)]*\)\s*\{[^}]*'
                r'(?:for|while)\s*\([^)]*\)\s*\{[^}]*'
                r'(?:for|while)\s*\([^)]*\)\s*\{'
            ),
            validator=None,
            description=(
                "4+ levels of nested loops detected. This creates "
                "exponential complexity growth and is a strong indicator "
                "of an algorithmic issue that will dominate CPU load."
            ),
            recommendation=(
                "Refactor to reduce nesting: extract inner loops into "
                "separate functions, use lookup tables, flatten multi-"
                "dimensional operations, or reconsider the algorithm."
            ),
            evidence=(
                "Code Complete (McConnell) — cyclomatic complexity; "
                "Pareto principle: 80% execution in 20% of code"
            ),
            impact_score=55,
            fix_template="Refactor to reduce nesting depth"
        ))

        rules.append(Rule(
            id="M06", name="Switch Without Default Case",
            severity=Severity.MEDIUM, category="Control Flow",
            pattern=re.compile(
                r'switch\s*\([^)]+\)\s*\{(?:(?!default\s*:).)*\}',
                re.DOTALL
            ),
            validator=None,
            description=(
                "A switch statement lacks a `default` case. Without it, "
                "the compiler may generate additional branch logic to "
                "handle unknown values instead of optimizing to a jump "
                "table."
            ),
            recommendation=(
                "Add a `default:` case, even if just `default: break;`. "
                "This helps the compiler generate an efficient jump table "
                "and satisfies MISRA requirements."
            ),
            evidence="MISRA C:2012 Rule 16.4 — every switch shall have default",
            impact_score=35,
            fix_template="Add default: case to switch statement"
        ))

        rules.append(Rule(
            id="M07", name="Signed Bit-field",
            severity=Severity.MEDIUM, category="Data Types",
            pattern=re.compile(
                r'\b(?:signed\s+)?int\s+\w+\s*:\s*\d+\s*;'
            ),
            validator=None,
            description=(
                "A signed bit-field detected. Bit manipulation on signed "
                "types has implementation-defined behavior and may "
                "generate additional sign-extension instructions."
            ),
            recommendation=(
                "Use `unsigned int` for all bit-fields to ensure portable, "
                "efficient bit operations without sign-extension overhead."
            ),
            evidence="MISRA C:2012 Rule 6.1 — bit-field types",
            impact_score=38,
            fix_template="Change to unsigned int"
        ))

        rules.append(Rule(
            id="M08", name="Sequential Type Casts",
            severity=Severity.MEDIUM, category="Arithmetic",
            pattern=re.compile(
                r'\(\s*\w+\s*\)\s*\(\s*\w+\s*\)\s*\w+'
            ),
            validator=None,
            description=(
                "Multiple sequential type casts detected. Each cast may "
                "generate conversion instructions (especially between "
                "float/int or different-width integers)."
            ),
            recommendation=(
                "Reduce to a single cast to the final target type. "
                "Intermediate casts are usually unnecessary and add "
                "conversion overhead."
            ),
            evidence="MISRA C:2012 Rules 10.3-10.5 — type conversion rules",
            impact_score=35,
            fix_template="Combine into single cast to target type"
        ))

        # ── LOW ──────────────────────────────────────────────────────────

        rules.append(Rule(
            id="L01", name="Magic Number",
            severity=Severity.LOW, category="Maintainability",
            pattern=re.compile(
                r'(?<!["\'])\b(?<!\.)\b(\d{2,})\b(?![\s]*[;,\)]?\s*$)'
            ),
            validator=self._validate_magic_number,
            description=(
                "A numeric literal (magic number) is used directly in "
                "code. This prevents the compiler from constant-folding "
                "across translation units and makes code harder to "
                "maintain."
            ),
            recommendation=(
                "Define as `#define` or `static const`. Named constants "
                "enable the compiler to optimize better across files "
                "and improve code readability."
            ),
            evidence=(
                "MISRA C:2012 Rule 7.1; Clean Code (Robert C. Martin) "
                "— magic numbers"
            ),
            impact_score=20,
            fix_template="#define DESCRIPTIVE_NAME ({value})"
        ))

        rules.append(Rule(
            id="L02", name="Long If-Else Chain (5+)",
            severity=Severity.LOW, category="Control Flow",
            pattern=re.compile(
                r'if\s*\(.*\)\s*\{[^}]*\}\s*'
                r'(?:else\s+if\s*\(.*\)\s*\{[^}]*\}\s*){4,}'
            ),
            validator=None,
            description=(
                "A long if-else chain (5+ branches) detected. This "
                "compiles to sequential conditional branches. A switch "
                "statement may allow the compiler to generate a more "
                "efficient jump table (O(1) vs O(n) branching)."
            ),
            recommendation=(
                "If checking a single variable against constants, "
                "convert to a switch statement. Alternatively, use a "
                "lookup table with function pointers."
            ),
            evidence=(
                "GCC Internals — jump table optimization for switch; "
                "ARM branch prediction documentation"
            ),
            impact_score=25,
            fix_template="Convert to switch statement or lookup table"
        ))

        rules.append(Rule(
            id="L03", name="Computation in Array Index",
            severity=Severity.LOW, category="Arithmetic",
            pattern=re.compile(
                r'\w+\s*\[\s*\w+\s*[\+\-\*\/]\s*\w+\s*\]'
            ),
            validator=None,
            description=(
                "A complex expression is used as an array index. While "
                "many compilers handle this well with addressing modes, "
                "complex index expressions can prevent the compiler from "
                "using efficient base+offset addressing."
            ),
            recommendation=(
                "Pre-compute complex array indices in a local variable: "
                "`const uint32_t idx = base + offset * stride;` This can "
                "help the compiler select optimal addressing modes."
            ),
            evidence=(
                "Patterson & Hennessy — Computer Organization; "
                "ARM addressing mode documentation"
            ),
            impact_score=18,
            fix_template="Pre-compute index in local variable"
        ))

        rules.append(Rule(
            id="L04", name="Missing volatile on Hardware Register Pattern",
            severity=Severity.LOW, category="Qualifiers",
            pattern=re.compile(
                r'\*\s*\(\s*(?:uint\d+_t|unsigned\s+\w+)\s*\*\s*\)\s*0x[0-9A-Fa-f]+'
            ),
            validator=None,
            description=(
                "A memory-mapped hardware register access pattern is "
                "detected without `volatile` qualifier. Without volatile, "
                "the compiler may cache or eliminate reads/writes to "
                "hardware registers, causing incorrect behavior AND "
                "wasted cycles on retry logic."
            ),
            recommendation=(
                "Always use `volatile` for hardware register accesses: "
                "`*(volatile uint32_t *)0xDEADBEEF`. This ensures every "
                "access actually reaches the hardware."
            ),
            evidence=(
                "MISRA C:2012 Rule 2.2; ARM CMSIS guidelines; "
                "C11 Standard §6.7.3 — volatile semantics"
            ),
            impact_score=30,
            fix_template="Add volatile qualifier to hardware register access"
        ))

        rules.append(Rule(
            id="L05", name="Uninitialized Variable Declaration",
            severity=Severity.LOW, category="Data Types",
            pattern=re.compile(
                r'^\s+(?:uint\d+_t|int\d+_t|int|unsigned|char|short|long'
                r'|float|double)\s+(\w+)\s*;',
                re.MULTILINE
            ),
            validator=None,
            description=(
                "A variable is declared without initialization. "
                "Uninitialized data goes to BSS section which requires "
                "runtime zeroing. Initialized data goes to DATA section "
                "and is loaded directly."
            ),
            recommendation=(
                "Initialize variables at declaration: "
                "`uint32_t counter = 0U;` This avoids BSS-to-DATA copy "
                "overhead and prevents undefined-behavior bugs."
            ),
            evidence=(
                "Renesas Embedded C III — data initialization sections; "
                "MISRA C:2012 Rule 9.1"
            ),
            impact_score=15,
            fix_template="Initialize variable at declaration"
        ))

        return rules

    # ── Validators (False Positive Reduction) ────────────────────────

    def _validate_not_float_context(self, match, line: str,
                                     lines: List[str],
                                     line_idx: int) -> bool:
        """Reject if the operation is on float/double variables.

        Checks for DIRECT float/double declaration of the variable,
        not just any float keyword appearing near the variable name.
        This avoids false positives like:
          float my_func(int raw_adc)  ← raw_adc is int, not float
        """
        var_name = match.group(1)
        start = max(0, line_idx - 20)
        context = '\n'.join(lines[start:line_idx + 1])

        # Pattern 1: Direct variable declaration
        #   float var_name   /  double var_name  /  float *var_name
        direct_decl = re.search(
            rf'\b(?:float|double)\s+\*?\s*{re.escape(var_name)}\b',
            context
        )
        if direct_decl:
            return False  # Variable IS float → skip this rule

        # Pattern 2: Variable assigned from float cast or float literal
        #   var_name = (float)...  /  var_name = 3.14
        float_assign = re.search(
            rf'\b{re.escape(var_name)}\s*=\s*\((?:float|double)\)',
            context
        )
        if float_assign:
            return False

        # Pattern 3: Check if current line has float result
        #   float result = var_name / 8  (result is float, so op is float)
        if re.match(r'\s*(?:float|double)\s+', line):
            return False

        return True  # Variable is NOT float → rule applies

    def _validate_not_standard_func(self, match, line: str,
                                     lines: List[str],
                                     line_idx: int) -> bool:
        """Reject standard library and common functions from being flagged."""
        if match.lastindex and match.lastindex >= 1:
            func_name = match.group(1)
        else:
            return True
        standard_funcs = {
            'if', 'else', 'for', 'while', 'do', 'switch', 'return',
            'sizeof', 'printf', 'sprintf', 'snprintf', 'fprintf',
            'memcpy', 'memset', 'memmove', 'memcmp',
            'strcpy', 'strncpy', 'strcmp', 'strncmp', 'strlen',
        }
        return func_name not in standard_funcs

    def _validate_oversized_type(self, match, line: str,
                                  lines: List[str],
                                  line_idx: int) -> bool:
        """Check if the assigned value fits in a smaller type."""
        try:
            value = int(match.group(2))
            return value <= 255  # Flag only if uint8_t would suffice
        except (ValueError, IndexError):
            return False

    def _validate_missing_const(self, match, line: str,
                                 lines: List[str],
                                 line_idx: int) -> bool:
        """Check if const is already present."""
        return 'const' not in line

    def _validate_magic_number(self, match, line: str,
                                lines: List[str],
                                line_idx: int) -> bool:
        """Filter out common acceptable numeric literals."""
        try:
            val = int(match.group(1))
            # Skip very common numbers and array sizes
            if val in (0, 1, 2, 10, 100, 1000):
                return False
            # Skip if it's in a #define
            if line.strip().startswith('#define'):
                return False
            # Skip if it's in an array declaration
            if re.search(r'\[\s*\d+\s*\]', line):
                return False
            return True
        except (ValueError, IndexError):
            return False

    # ── Core Analysis ────────────────────────────────────────────────

    def analyze(self, source: str, file_path: str,
                min_severity: Severity = Severity.LOW) -> List[Finding]:
        """Run all rules against the source code."""
        findings = []
        cleaned, line_map = Preprocessor.strip_comments(source)
        lines = cleaned.split('\n')
        original_lines = source.split('\n')
        loop_bodies = Preprocessor.find_loop_bodies(cleaned)
        functions = Preprocessor.find_function_bodies(cleaned)

        for rule in self.rules:
            if rule.severity < min_severity:
                continue

            # Special case: recursive function detection
            if rule.id == "H02":
                findings.extend(
                    self._detect_recursion(functions, file_path,
                                           original_lines, rule, line_map)
                )
                continue

            if rule.pattern is None:
                continue

            # Context-aware rules (check if inside loop)
            if rule.needs_context and rule.id == "C05":
                for loop_start, loop_end, loop_body in loop_bodies:
                    for m in rule.pattern.finditer(loop_body):
                        # Calculate actual line number
                        match_offset = loop_body[:m.start()].count('\n')
                        actual_line = loop_start + match_offset
                        orig_line = line_map.get(actual_line + 1,
                                                  actual_line + 1)

                        snippet = Preprocessor.get_context(
                            original_lines, min(orig_line - 1,
                                                 len(original_lines) - 1)
                        )
                        findings.append(Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            file_path=file_path,
                            line_number=orig_line,
                            code_snippet=snippet,
                            matched_text=m.group(0),
                            description=rule.description,
                            recommendation=rule.recommendation,
                            suggested_fix=rule.fix_template,
                            evidence=rule.evidence,
                            impact_score=rule.impact_score,
                        ))
                continue

            if rule.needs_context and rule.id == "H01":
                for loop_start, loop_end, loop_body in loop_bodies:
                    for m in rule.pattern.finditer(loop_body):
                        match_offset = loop_body[:m.start()].count('\n')
                        actual_line = loop_start + match_offset
                        orig_line = line_map.get(actual_line + 1,
                                                  actual_line + 1)
                        snippet = Preprocessor.get_context(
                            original_lines, min(orig_line - 1,
                                                 len(original_lines) - 1)
                        )
                        findings.append(Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            file_path=file_path,
                            line_number=orig_line,
                            code_snippet=snippet,
                            matched_text=m.group(0),
                            description=rule.description,
                            recommendation=rule.recommendation,
                            suggested_fix=rule.fix_template,
                            evidence=rule.evidence,
                            impact_score=rule.impact_score,
                        ))
                continue

            # Standard pattern matching
            for i, line in enumerate(lines):
                for m in rule.pattern.finditer(line):
                    # Run validator if present
                    if rule.validator:
                        if not rule.validator(m, line, lines, i):
                            continue

                    orig_line = line_map.get(i + 1, i + 1)
                    snippet = Preprocessor.get_context(
                        original_lines,
                        min(orig_line - 1, len(original_lines) - 1)
                    )

                    findings.append(Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        file_path=file_path,
                        line_number=orig_line,
                        code_snippet=snippet,
                        matched_text=m.group(0),
                        description=rule.description,
                        recommendation=rule.recommendation,
                        suggested_fix=rule.fix_template,
                        evidence=rule.evidence,
                        impact_score=rule.impact_score,
                    ))

        # Sort by impact score descending
        findings.sort(key=lambda f: (-f.severity, -f.impact_score))
        return findings

    def _detect_recursion(self, functions: List[Dict], file_path: str,
                          original_lines: List[str], rule: Rule,
                          line_map: Dict) -> List[Finding]:
        """Detect direct recursive function calls."""
        findings = []
        for func in functions:
            name = func['name']
            body = func['body']
            # Check if function calls itself (excluding the definition line)
            body_without_def = '\n'.join(body.split('\n')[1:])
            call_pattern = re.compile(rf'\b{re.escape(name)}\s*\(')
            if call_pattern.search(body_without_def):
                orig_line = line_map.get(func['start'] + 1,
                                         func['start'] + 1)
                snippet = Preprocessor.get_context(
                    original_lines,
                    min(orig_line - 1, len(original_lines) - 1)
                )
                findings.append(Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    file_path=file_path,
                    line_number=orig_line,
                    code_snippet=snippet,
                    matched_text=f"{name}() calls itself",
                    description=rule.description,
                    recommendation=rule.recommendation,
                    suggested_fix=rule.fix_template,
                    evidence=rule.evidence,
                    impact_score=rule.impact_score,
                ))
        return findings


# ============================================================================
# CODE ANNOTATOR (Bonus — PIL-based screenshots)
# ============================================================================

class CodeAnnotator:
    """Generates annotated code screenshot images."""

    def __init__(self):
        self.available = False
        try:
            from PIL import Image, ImageDraw, ImageFont
            self.Image = Image
            self.ImageDraw = ImageDraw
            self.ImageFont = ImageFont
            self.available = True
        except ImportError:
            pass

    def create_annotation(self, finding: Finding) -> Optional[str]:
        """Create a base64-encoded PNG of annotated code."""
        if not self.available:
            return None

        lines = finding.code_snippet.split('\n')
        line_height = 22
        char_width = 9
        padding = 20
        max_line_len = max(len(l) for l in lines) if lines else 40
        annotation_width = 400

        img_width = max(max_line_len * char_width + padding * 2 + annotation_width, 800)
        img_height = len(lines) * line_height + padding * 2 + 60

        img = self.Image.new('RGB', (img_width, img_height), '#1e1e2e')
        draw = self.ImageDraw.Draw(img)

        try:
            font = self.ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14)
            font_small = self.ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 11)
            font_bold = self.ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 13)
        except (OSError, IOError):
            font = self.ImageFont.load_default()
            font_small = font
            font_bold = font

        # Title bar
        draw.rectangle([(0, 0), (img_width, 30)], fill='#313244')
        draw.text((padding, 6), f"  {finding.rule_id}: {finding.rule_name}",
                  fill='#f38ba8', font=font_bold)

        # Code lines
        y = 40
        code_area_width = img_width - annotation_width - padding
        for line_text in lines:
            is_issue_line = line_text.startswith(">>>")
            bg_color = '#45475a' if is_issue_line else None
            text_color = '#f38ba8' if is_issue_line else '#cdd6f4'

            if bg_color:
                draw.rectangle(
                    [(padding - 5, y - 2),
                     (code_area_width, y + line_height - 2)],
                    fill=bg_color
                )

            draw.text((padding, y), line_text, fill=text_color, font=font)

            # Draw arrow to annotation for the issue line
            if is_issue_line:
                arrow_start_x = code_area_width + 10
                arrow_end_x = code_area_width + 40
                arrow_y = y + line_height // 2
                draw.line([(arrow_start_x, arrow_y),
                           (arrow_end_x, arrow_y)],
                          fill='#f38ba8', width=2)
                draw.polygon(
                    [(arrow_end_x, arrow_y - 5),
                     (arrow_end_x + 8, arrow_y),
                     (arrow_end_x, arrow_y + 5)],
                    fill='#f38ba8'
                )

                # Annotation box
                box_x = arrow_end_x + 15
                box_y = arrow_y - 25
                box_w = annotation_width - 80
                box_h = 50
                draw.rectangle(
                    [(box_x, box_y), (box_x + box_w, box_y + box_h)],
                    fill='#313244', outline='#a6e3a1', width=2
                )
                fix_text = finding.suggested_fix[:50]
                draw.text((box_x + 8, box_y + 5), "FIX:",
                          fill='#a6e3a1', font=font_bold)
                draw.text((box_x + 8, box_y + 22), fix_text,
                          fill='#a6e3a1', font=font_small)

            y += line_height

        # Convert to base64
        import io
        import base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return f"data:image/png;base64,{b64}"


# ============================================================================
# HTML REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generates a self-contained interactive HTML report."""

    # ── CPU Load Reduction Estimation Model ──────────────────────────
    # Based on empirical data from:
    #   - ARM Cortex-M instruction cycle timing tables
    #   - Renesas Embedded C III: MUL=12-20 cycles vs SHIFT=2 cycles
    #   - Embedded.com benchmarks: FPU sw emulation 10-70x slower
    #   - IEEE Embedded Systems Letters: loop optimization case studies
    #
    # The model estimates what percentage of OVERALL CPU load a category
    # of findings could reduce, assuming findings are in hot paths.
    # Real impact depends on how frequently the affected code runs.
    #
    # Per-finding base reduction (% CPU load), derived from cycle ratios:
    REDUCTION_MAP = {
        # CRITICAL: each finding affects 0.3-1.5% of total CPU
        # (e.g., DIV→SHIFT saves ~18 cycles per hit; in 10kHz loop = massive)
        "C01": 1.2,   # Float→Int: removes entire FPU emulation path
        "C02": 0.8,   # DIV→SHIFT: 12-20 cycles → 1-2 cycles per operation
        "C03": 0.8,   # MOD→AND: same as DIV→SHIFT
        "C04": 0.5,   # MUL→SHIFT: 3-12 cycles → 1 cycle (smaller gap)
        "C05": 1.5,   # Math in loop: 50-200 cycles × iteration count
        "C06": 1.0,   # malloc/free: heap mgmt overhead ~100-500 cycles
        # HIGH: each finding affects 0.2-0.8%
        "H01": 0.4,   # Loop-invariant: saves N × computation_cost
        "H02": 0.6,   # Recursion→Iteration: removes stack frame overhead
        "H03": 0.8,   # strlen in condition: O(n²)→O(n) complexity
        "H04": 0.3,   # Inline function: saves ~10-20 cycles prologue/epilogue
        "H05": 0.2,   # Data type sizing: bus width / cache efficiency
        "H06": 0.3,   # FP comparison: FPU compare vs integer compare
        "H07": 0.4,   # Struct pass-by-value: copies N bytes per call
        "H08": 0.3,   # Repeated computation: saves duplicate work
        # MEDIUM: each finding affects 0.1-0.3%
        "M01": 0.15,  # const: enables compiler register caching
        "M02": 0.1,   # static: enables inlining/dead code elimination
        "M03": 0.25,  # Global in loop: memory reload vs register
        "M05": 0.2,   # Deep nesting: algorithmic, hard to quantify
        "M06": 0.1,   # Switch default: jump table optimization
        "M07": 0.1,   # Signed bit-field: sign extension overhead
        "M08": 0.1,   # Cast chain: conversion instruction overhead
        # LOW: each finding affects 0.02-0.1%
        "L01": 0.05,  # Magic numbers: constant folding missed
        "L02": 0.1,   # If-else→Switch: sequential vs jump table
        "L03": 0.05,  # Array index: addressing mode selection
        "L04": 0.15,  # Missing volatile: wrong behavior + retry waste
        "L05": 0.03,  # Uninitialized: BSS zeroing overhead
    }

    # Maximum total reduction cap per severity (prevents unrealistic estimates)
    SEVERITY_CAP = {
        "CRITICAL": 18.0,  # Max 18% — critical fixes in isolation
        "HIGH":     10.0,  # Max 10%
        "MEDIUM":    5.0,  # Max 5%
        "LOW":       2.0,  # Max 2%
    }

    @classmethod
    def estimate_cpu_reduction(cls, findings: List[Finding]) -> Dict:
        """
        Estimate CPU load reduction if findings are resolved.

        Returns dict with per-severity and total estimates.
        Each estimate is a range (min%, max%) because actual impact
        depends on execution frequency of the affected code.
        """
        severity_groups = defaultdict(list)
        for f in findings:
            severity_groups[f.severity_name].append(f)

        estimates = {}
        total_min = 0.0
        total_max = 0.0

        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            group = severity_groups.get(sev_name, [])
            if not group:
                estimates[sev_name] = {
                    "count": 0, "min_pct": 0.0, "max_pct": 0.0,
                    "raw_pct": 0.0
                }
                continue

            raw_total = 0.0
            for f in group:
                base = cls.REDUCTION_MAP.get(f.rule_id, 0.1)
                raw_total += base

            # Apply cap
            cap = cls.SEVERITY_CAP.get(sev_name, 5.0)
            capped = min(raw_total, cap)

            # Min estimate: 40% of calculated (cold path / low frequency code)
            # Max estimate: 100% of calculated (hot path / high frequency code)
            min_pct = round(capped * 0.4, 1)
            max_pct = round(capped, 1)

            estimates[sev_name] = {
                "count": len(group),
                "min_pct": min_pct,
                "max_pct": max_pct,
                "raw_pct": round(raw_total, 1),
            }
            total_min += min_pct
            total_max += max_pct

        # Total with its own cap (diminishing returns)
        total_cap = 30.0
        estimates["TOTAL"] = {
            "min_pct": round(min(total_min, total_cap * 0.4), 1),
            "max_pct": round(min(total_max, total_cap), 1),
        }

        return estimates

    @staticmethod
    def generate(findings: List[Finding], files_analyzed: List[str],
                 annotator: Optional[CodeAnnotator] = None,
                 output_path: str = "cpu_load_report.html"):
        """Generate the full HTML report."""

        # Compute stats
        total = len(findings)
        by_severity = Counter(f.severity_name for f in findings)
        by_category = Counter(f.category for f in findings)
        total_impact = sum(f.impact_score for f in findings)
        avg_impact = total_impact / total if total else 0

        # Compute CPU load reduction estimates
        cpu_estimates = ReportGenerator.estimate_cpu_reduction(findings)

        # Generate annotation images if available
        annotations = {}
        if annotator and annotator.available:
            for i, f in enumerate(findings[:20]):  # Limit to top 20
                img = annotator.create_annotation(f)
                if img:
                    annotations[i] = img

        # Build findings HTML
        findings_html = []
        for i, f in enumerate(findings):
            snippet_escaped = html.escape(f.code_snippet)
            matched_escaped = html.escape(f.matched_text)
            annotation_img = ""
            if i in annotations:
                annotation_img = f'''
                <div class="annotation-img">
                    <img src="{annotations[i]}" alt="Annotated code" />
                </div>'''

            findings_html.append(f'''
            <div class="finding" data-severity="{f.severity_name}"
                 data-category="{f.category}" data-impact="{f.impact_score}">
                <div class="finding-header" onclick="toggleFinding(this)">
                    <div class="finding-left">
                        <span class="severity-badge"
                              style="background:{f.severity_color}">
                            {f.severity_name}
                        </span>
                        <span class="rule-id">{f.rule_id}</span>
                        <span class="rule-name">{f.rule_name}</span>
                    </div>
                    <div class="finding-right">
                        <span class="impact-score">Impact: {f.impact_score}/100</span>
                        <span class="file-loc">{os.path.basename(f.file_path)}:{f.line_number}</span>
                        <span class="expand-icon">&#9660;</span>
                    </div>
                </div>
                <div class="finding-body" style="display:none">
                    <div class="finding-grid">
                        <div class="finding-detail">
                            <h4>Issue Description</h4>
                            <p>{f.description}</p>
                            <h4>Matched Code</h4>
                            <code class="matched">{matched_escaped}</code>
                            <h4>Code Context</h4>
                            <pre class="code-context">{snippet_escaped}</pre>
                            {annotation_img}
                        </div>
                        <div class="finding-action">
                            <h4>Recommendation</h4>
                            <p>{f.recommendation}</p>
                            <h4>Suggested Fix</h4>
                            <div class="fix-box">{f.suggested_fix}</div>
                            <h4>Evidence / Reference</h4>
                            <p class="evidence">{f.evidence}</p>
                        </div>
                    </div>
                </div>
            </div>''')

        # Category chart data
        cat_items = sorted(by_category.items(), key=lambda x: -x[1])
        max_cat = max(by_category.values()) if by_category else 1
        cat_bars = ""
        for cat, count in cat_items:
            pct = (count / max_cat) * 100
            cat_bars += f'''
            <div class="bar-row">
                <span class="bar-label">{cat}</span>
                <div class="bar-track">
                    <div class="bar-fill" style="width:{pct}%"></div>
                </div>
                <span class="bar-value">{count}</span>
            </div>'''

        # Top 5 recommendations
        top5 = findings[:5]
        top5_html = ""
        for j, f in enumerate(top5):
            top5_html += f'''
            <div class="top-rec">
                <span class="top-rank">#{j+1}</span>
                <div class="top-content">
                    <strong>{f.rule_id}: {f.rule_name}</strong>
                    <span class="top-loc">{os.path.basename(f.file_path)}:{f.line_number}</span>
                    <p>{f.recommendation[:200]}{'...' if len(f.recommendation) > 200 else ''}</p>
                </div>
                <span class="top-impact" style="color:{f.severity_color}">
                    {f.impact_score}
                </span>
            </div>'''

        files_list = ", ".join(os.path.basename(fp) for fp in files_analyzed)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report_html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CPU Load Optimization Report</title>
<style>
:root {{
    --bg: #0f0f17;
    --surface: #1a1a2e;
    --surface2: #222240;
    --border: #2d2d4a;
    --text: #e2e2f0;
    --text-dim: #8888a8;
    --accent: #6c5ce7;
    --accent-glow: rgba(108, 92, 231, 0.15);
    --critical: #dc2626;
    --high: #ea580c;
    --medium: #ca8a04;
    --low: #2563eb;
    --success: #16a34a;
    --font-mono: 'Courier New', 'Consolas', monospace;
    --font-body: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    font-family: var(--font-body);
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    min-height: 100vh;
}}

.container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}

/* ── Header ─────────────────────────────────────────── */
.report-header {{
    background: linear-gradient(135deg, var(--surface) 0%, #16163a 100%);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 40px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
}}
.report-header::before {{
    content: '';
    position: absolute;
    top: -50%;
    right: -10%;
    width: 300px;
    height: 300px;
    background: radial-gradient(circle, var(--accent-glow) 0%, transparent 70%);
    pointer-events: none;
}}

.header-top {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 30px;
    position: relative;
}}

.tool-title {{
    font-size: 28px;
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(135deg, #a78bfa, #6c5ce7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}}
.tool-subtitle {{
    color: var(--text-dim);
    font-size: 14px;
    margin-top: 4px;
}}

.header-meta {{
    text-align: right;
    font-size: 13px;
    color: var(--text-dim);
}}

/* ── Stats Grid ─────────────────────────────────────── */
.stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}}

.stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
}}
.stat-value {{
    font-size: 36px;
    font-weight: 800;
    font-family: var(--font-mono);
}}
.stat-label {{
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-dim);
    margin-top: 4px;
}}

/* ── Dashboard Row ──────────────────────────────────── */
.dashboard-row {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    margin-bottom: 24px;
}}
@media (max-width: 900px) {{
    .dashboard-row {{ grid-template-columns: 1fr; }}
}}

.panel {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
}}
.panel-title {{
    font-size: 16px;
    font-weight: 700;
    margin-bottom: 16px;
    color: var(--accent);
}}

/* Bar chart */
.bar-row {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
}}
.bar-label {{
    width: 100px;
    font-size: 13px;
    text-align: right;
    color: var(--text-dim);
}}
.bar-track {{
    flex: 1;
    height: 20px;
    background: var(--surface2);
    border-radius: 4px;
    overflow: hidden;
}}
.bar-fill {{
    height: 100%;
    background: linear-gradient(90deg, var(--accent), #a78bfa);
    border-radius: 4px;
    transition: width 0.6s ease;
}}
.bar-value {{
    width: 30px;
    font-size: 13px;
    font-weight: 700;
    font-family: var(--font-mono);
}}

/* Top recommendations */
.top-rec {{
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
}}
.top-rec:last-child {{ border-bottom: none; }}
.top-rank {{
    width: 32px;
    height: 32px;
    background: var(--surface2);
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    font-size: 14px;
    color: var(--accent);
    flex-shrink: 0;
}}
.top-content {{ flex: 1; }}
.top-content strong {{ font-size: 14px; }}
.top-content p {{ font-size: 12px; color: var(--text-dim); margin-top: 4px; }}
.top-loc {{ font-size: 11px; color: var(--text-dim); margin-left: 8px; }}
.top-impact {{
    font-size: 24px;
    font-weight: 800;
    font-family: var(--font-mono);
    flex-shrink: 0;
}}

/* ── Controls ───────────────────────────────────────── */
.controls {{
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
    flex-wrap: wrap;
    align-items: center;
}}

.filter-btn {{
    padding: 8px 16px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    color: var(--text);
    cursor: pointer;
    font-size: 13px;
    transition: all 0.2s;
}}
.filter-btn:hover {{ border-color: var(--accent); }}
.filter-btn.active {{
    background: var(--accent);
    border-color: var(--accent);
    color: white;
}}

.sort-select {{
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    color: var(--text);
    font-size: 13px;
    cursor: pointer;
}}

/* ── Findings ───────────────────────────────────────── */
.findings-section {{
    margin-top: 10px;
}}
.findings-count {{
    font-size: 14px;
    color: var(--text-dim);
    margin-bottom: 12px;
}}

.finding {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 8px;
    overflow: hidden;
    transition: border-color 0.2s;
}}
.finding:hover {{ border-color: var(--accent); }}

.finding-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 20px;
    cursor: pointer;
    gap: 12px;
}}
.finding-left {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.finding-right {{ display: flex; align-items: center; gap: 14px; flex-shrink: 0; }}

.severity-badge {{
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    color: white;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
.rule-id {{
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 14px;
    color: var(--accent);
}}
.rule-name {{ font-size: 14px; font-weight: 600; }}
.impact-score {{
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--text-dim);
}}
.file-loc {{
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-dim);
}}
.expand-icon {{
    font-size: 12px;
    color: var(--text-dim);
    transition: transform 0.2s;
}}

.finding-body {{ padding: 0 20px 20px; }}
.finding-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
}}
@media (max-width: 900px) {{
    .finding-grid {{ grid-template-columns: 1fr; }}
}}

.finding-detail h4, .finding-action h4 {{
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--accent);
    margin: 16px 0 8px;
}}
.finding-detail h4:first-child,
.finding-action h4:first-child {{ margin-top: 0; }}

.finding-detail p, .finding-action p {{
    font-size: 13px;
    color: var(--text);
    line-height: 1.6;
}}

.code-context {{
    background: #0d0d1a;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    font-family: var(--font-mono);
    font-size: 12px;
    line-height: 1.7;
    overflow-x: auto;
    white-space: pre;
    color: #cdd6f4;
}}

code.matched {{
    background: rgba(243, 139, 168, 0.15);
    border: 1px solid rgba(243, 139, 168, 0.3);
    padding: 4px 8px;
    border-radius: 4px;
    font-family: var(--font-mono);
    font-size: 12px;
    color: #f38ba8;
    display: inline-block;
    max-width: 100%;
    overflow-x: auto;
}}

.fix-box {{
    background: rgba(166, 227, 161, 0.1);
    border: 1px solid rgba(166, 227, 161, 0.3);
    border-radius: 8px;
    padding: 12px;
    font-family: var(--font-mono);
    font-size: 13px;
    color: #a6e3a1;
}}

.evidence {{
    font-size: 12px;
    color: var(--text-dim);
    font-style: italic;
}}

.annotation-img {{
    margin-top: 12px;
}}
.annotation-img img {{
    max-width: 100%;
    border-radius: 8px;
    border: 1px solid var(--border);
}}

/* ── Footer ─────────────────────────────────────────── */
.report-footer {{
    text-align: center;
    padding: 40px 0 20px;
    font-size: 12px;
    color: var(--text-dim);
}}

/* ── CPU Load Reduction Estimation ──────────────────── */
.cpu-estimation-panel {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    position: relative;
}}
.cpu-estimation-panel .panel-title {{
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 8px;
    color: #a78bfa;
}}
.estimation-disclaimer {{
    font-size: 11px;
    color: var(--text-dim);
    margin-bottom: 20px;
    line-height: 1.5;
    font-style: italic;
    max-width: 800px;
}}
.estimation-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 20px;
}}
@media (max-width: 900px) {{
    .estimation-grid {{ grid-template-columns: repeat(2, 1fr); }}
}}
@media (max-width: 500px) {{
    .estimation-grid {{ grid-template-columns: 1fr; }}
}}
.est-card {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px;
    text-align: center;
}}
.est-header {{
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1px;
    color: var(--text-dim);
    margin-bottom: 12px;
}}
.est-severity-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    display: inline-block;
}}
.est-range {{
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    margin-bottom: 10px;
}}
.est-value {{
    font-family: var(--font-mono);
    font-size: 22px;
    font-weight: 800;
    color: var(--text);
}}
.est-arrow {{
    color: var(--text-dim);
    font-size: 16px;
}}
.est-bar-track {{
    height: 6px;
    background: rgba(255,255,255,0.05);
    border-radius: 3px;
    overflow: hidden;
    margin-bottom: 8px;
}}
.est-bar-fill {{
    height: 100%;
    border-radius: 3px;
    transition: width 0.8s ease;
}}
.est-detail {{
    font-size: 11px;
    color: var(--text-dim);
}}
.est-total {{
    background: linear-gradient(135deg, rgba(108,92,231,0.1) 0%, rgba(167,139,250,0.05) 100%);
    border: 1px solid rgba(108,92,231,0.3);
    border-radius: 10px;
    padding: 20px;
    text-align: center;
}}
.est-total-label {{
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1.5px;
    color: var(--text-dim);
    margin-bottom: 8px;
}}
.est-total-value {{
    font-family: var(--font-mono);
    font-size: 36px;
    font-weight: 800;
    background: linear-gradient(135deg, #a78bfa, #6c5ce7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 4px;
}}
.est-total-note {{
    font-size: 11px;
    color: var(--text-dim);
}}
</style>
</head>
<body>

<div class="container">

    <!-- Header -->
    <div class="report-header">
        <div class="header-top">
            <div>
                <div class="tool-title">CPU Load Optimizer</div>
                <div class="tool-subtitle">
                    Static Analysis Report — Embedded C Optimization Opportunities
                </div>
            </div>
            <div class="header-meta">
                <div>Generated: {timestamp}</div>
                <div>Files: {files_list}</div>
                <div>Tool Version: 1.0.0</div>
            </div>
        </div>
    </div>

    <!-- Stats -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value" style="color:var(--accent)">{total}</div>
            <div class="stat-label">Total Findings</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:var(--critical)">
                {by_severity.get("CRITICAL", 0)}
            </div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:var(--high)">
                {by_severity.get("HIGH", 0)}
            </div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:var(--medium)">
                {by_severity.get("MEDIUM", 0)}
            </div>
            <div class="stat-label">Medium</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:var(--low)">
                {by_severity.get("LOW", 0)}
            </div>
            <div class="stat-label">Low</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:var(--success)">
                {avg_impact:.0f}
            </div>
            <div class="stat-label">Avg Impact Score</div>
        </div>
    </div>

    <!-- Dashboard -->
    <div class="dashboard-row">
        <div class="panel">
            <div class="panel-title">Findings by Category</div>
            {cat_bars}
        </div>
        <div class="panel">
            <div class="panel-title">Top 5 Highest-Impact Recommendations</div>
            {top5_html}
        </div>
    </div>

    <!-- CPU Load Reduction Estimation -->
    <div class="cpu-estimation-panel">
        <div class="panel-title">
            Estimated CPU Load Reduction (If Resolved)
        </div>
        <p class="estimation-disclaimer">
            Estimates based on ARM Cortex-M instruction cycle ratios,
            Renesas embedded benchmarks, and IEEE case studies.
            Actual impact depends on execution frequency of affected code paths.
            Range represents cold-path (min) to hot-path (max) scenarios.
        </p>
        <div class="estimation-grid">
            <div class="est-card est-critical">
                <div class="est-header">
                    <span class="est-severity-dot" style="background:var(--critical)"></span>
                    CRITICAL
                </div>
                <div class="est-range">
                    <span class="est-value">{cpu_estimates['CRITICAL']['min_pct']}%</span>
                    <span class="est-arrow">—</span>
                    <span class="est-value">{cpu_estimates['CRITICAL']['max_pct']}%</span>
                </div>
                <div class="est-bar-track">
                    <div class="est-bar-fill" style="width:{min(cpu_estimates['CRITICAL']['max_pct']*3.3, 100)}%;
                         background:var(--critical)"></div>
                </div>
                <div class="est-detail">{cpu_estimates['CRITICAL']['count']} findings</div>
            </div>
            <div class="est-card est-high">
                <div class="est-header">
                    <span class="est-severity-dot" style="background:var(--high)"></span>
                    HIGH
                </div>
                <div class="est-range">
                    <span class="est-value">{cpu_estimates['HIGH']['min_pct']}%</span>
                    <span class="est-arrow">—</span>
                    <span class="est-value">{cpu_estimates['HIGH']['max_pct']}%</span>
                </div>
                <div class="est-bar-track">
                    <div class="est-bar-fill" style="width:{min(cpu_estimates['HIGH']['max_pct']*3.3, 100)}%;
                         background:var(--high)"></div>
                </div>
                <div class="est-detail">{cpu_estimates['HIGH']['count']} findings</div>
            </div>
            <div class="est-card est-medium">
                <div class="est-header">
                    <span class="est-severity-dot" style="background:var(--medium)"></span>
                    MEDIUM
                </div>
                <div class="est-range">
                    <span class="est-value">{cpu_estimates['MEDIUM']['min_pct']}%</span>
                    <span class="est-arrow">—</span>
                    <span class="est-value">{cpu_estimates['MEDIUM']['max_pct']}%</span>
                </div>
                <div class="est-bar-track">
                    <div class="est-bar-fill" style="width:{min(cpu_estimates['MEDIUM']['max_pct']*3.3, 100)}%;
                         background:var(--medium)"></div>
                </div>
                <div class="est-detail">{cpu_estimates['MEDIUM']['count']} findings</div>
            </div>
            <div class="est-card est-low">
                <div class="est-header">
                    <span class="est-severity-dot" style="background:var(--low)"></span>
                    LOW
                </div>
                <div class="est-range">
                    <span class="est-value">{cpu_estimates['LOW']['min_pct']}%</span>
                    <span class="est-arrow">—</span>
                    <span class="est-value">{cpu_estimates['LOW']['max_pct']}%</span>
                </div>
                <div class="est-bar-track">
                    <div class="est-bar-fill" style="width:{min(cpu_estimates['LOW']['max_pct']*3.3, 100)}%;
                         background:var(--low)"></div>
                </div>
                <div class="est-detail">{cpu_estimates['LOW']['count']} findings</div>
            </div>
        </div>
        <div class="est-total">
            <div class="est-total-label">TOTAL ESTIMATED REDUCTION</div>
            <div class="est-total-value">
                {cpu_estimates['TOTAL']['min_pct']}% — {cpu_estimates['TOTAL']['max_pct']}%
            </div>
            <div class="est-total-note">
                Combined impact if all findings are resolved
            </div>
        </div>
    </div>

    <!-- Controls -->
    <div class="controls">
        <button class="filter-btn active" onclick="filterSeverity('ALL')">All</button>
        <button class="filter-btn" onclick="filterSeverity('CRITICAL')"
                style="border-color:var(--critical)">Critical</button>
        <button class="filter-btn" onclick="filterSeverity('HIGH')"
                style="border-color:var(--high)">High</button>
        <button class="filter-btn" onclick="filterSeverity('MEDIUM')"
                style="border-color:var(--medium)">Medium</button>
        <button class="filter-btn" onclick="filterSeverity('LOW')"
                style="border-color:var(--low)">Low</button>
        <select class="sort-select" onchange="sortFindings(this.value)">
            <option value="impact">Sort: Impact (High→Low)</option>
            <option value="severity">Sort: Severity</option>
            <option value="line">Sort: Line Number</option>
        </select>
    </div>

    <!-- Findings -->
    <div class="findings-section">
        <div class="findings-count" id="findings-count">
            Showing {total} findings
        </div>
        {''.join(findings_html)}
    </div>

    <div class="report-footer">
        CPU Load Optimizer v1.0 — Rule-based static analysis for embedded C
        optimization<br>
        References: MISRA C:2012, Renesas Embedded C III, ARM Architecture
        Manual, SEI CERT C, GCC Docs
    </div>
</div>

<script>
function toggleFinding(header) {{
    const body = header.nextElementSibling;
    const icon = header.querySelector('.expand-icon');
    if (body.style.display === 'none') {{
        body.style.display = 'block';
        icon.innerHTML = '&#9650;';
    }} else {{
        body.style.display = 'none';
        icon.innerHTML = '&#9660;';
    }}
}}

function filterSeverity(sev) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');

    const findings = document.querySelectorAll('.finding');
    let shown = 0;
    findings.forEach(f => {{
        if (sev === 'ALL' || f.dataset.severity === sev) {{
            f.style.display = 'block';
            shown++;
        }} else {{
            f.style.display = 'none';
        }}
    }});
    document.getElementById('findings-count').textContent =
        `Showing ${{shown}} of {total} findings`;
}}

function sortFindings(by) {{
    const container = document.querySelector('.findings-section');
    const findings = Array.from(container.querySelectorAll('.finding'));
    const countDiv = document.getElementById('findings-count');

    findings.sort((a, b) => {{
        if (by === 'impact') return b.dataset.impact - a.dataset.impact;
        if (by === 'severity') {{
            const order = {{'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1}};
            return order[b.dataset.severity] - order[a.dataset.severity];
        }}
        if (by === 'line') return 0; // keep original order by line
    }});

    findings.forEach(f => container.appendChild(f));
    container.insertBefore(countDiv, container.firstChild);
}}
</script>

</body>
</html>'''

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_html)

        return output_path


# ============================================================================
# LLM VALIDATION EXPORT — Structured output for secondary LLM review
# ============================================================================

class LLMValidationExport:
    """
    Generates an LLM-optimized export package for secondary validation.

    Instead of feeding the bloated HTML report to an LLM, this creates:
    1. A compact findings summary (text/markdown) — max ~2000 tokens
    2. A pre-built validation prompt with clear instructions
    3. Guidance on what to upload and how

    This ensures the LLM spends its context window on THINKING about
    your code, not parsing CSS and JavaScript.
    """

    @staticmethod
    def generate(findings: List[Finding], files_analyzed: List[str],
                 output_dir: str, source_files_content: Dict[str, str]):
        """
        Generate the LLM validation export package.

        Args:
            findings: List of findings from the analyzer
            files_analyzed: Paths to analyzed files
            output_dir: Where to write the export files
            source_files_content: Dict of {filepath: source_code}
        """
        os.makedirs(output_dir, exist_ok=True)

        # ── File 1: Compact Findings Export ──────────────────────────
        findings_text = LLMValidationExport._build_findings_export(
            findings, files_analyzed
        )
        findings_path = os.path.join(output_dir, "findings_for_review.md")
        with open(findings_path, 'w', encoding='utf-8') as f:
            f.write(findings_text)

        # ── File 2: Validation Prompt ────────────────────────────────
        prompt_text = LLMValidationExport._build_validation_prompt(
            findings, files_analyzed
        )
        prompt_path = os.path.join(output_dir, "validation_prompt.md")
        with open(prompt_path, 'w', encoding='utf-8') as f:
            f.write(prompt_text)

        # ── File 3: Instructions ─────────────────────────────────────
        instructions = LLMValidationExport._build_instructions(
            files_analyzed, findings_path, prompt_path
        )
        instructions_path = os.path.join(output_dir, "HOW_TO_VALIDATE.md")
        with open(instructions_path, 'w', encoding='utf-8') as f:
            f.write(instructions)

        return findings_path, prompt_path, instructions_path

    @staticmethod
    def _build_findings_export(findings: List[Finding],
                                files_analyzed: List[str]) -> str:
        """Build a compact, token-efficient findings summary.

        IMPORTANT: Every individual finding gets its own entry with its
        own code context. The LLM needs to see each occurrence to
        validate it — grouping by rule_id hides code context from
        subsequent occurrences and prevents proper validation.

        Token efficiency is achieved by:
        - Showing description/evidence only on the first occurrence of
          each rule_id (the LLM already knows the rule after seeing it)
        - Keeping code samples to the flagged line only (>>> line)
        """
        lines = []
        lines.append("# CPU Load Optimizer — Findings for LLM Validation")
        lines.append(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"# Files: {', '.join(os.path.basename(f) for f in files_analyzed)}")
        lines.append(f"# Total: {len(findings)} findings")
        lines.append("")

        # Group by severity for clarity
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        grouped = defaultdict(list)
        for f in findings:
            grouped[f.severity_name].append(f)

        # Track which rule_ids we've already described
        described_rules = set()

        finding_number = 0
        for sev in severity_order:
            group = grouped.get(sev, [])
            if not group:
                continue
            lines.append(f"## {sev} ({len(group)} findings)")
            lines.append("")

            for f in group:
                finding_number += 1
                is_first = f.rule_id not in described_rules

                lines.append(
                    f"### Finding #{finding_number}: "
                    f"[{f.rule_id}] {f.rule_name}"
                )
                lines.append(
                    f"- **File**: "
                    f"{os.path.basename(f.file_path)}  "
                    f"**Line**: {f.line_number}  "
                    f"**Impact**: {f.impact_score}/100"
                )

                # Show description + evidence only on first occurrence
                if is_first:
                    lines.append(
                        f"- **Issue**: {f.description[:200]}"
                    )
                    described_rules.add(f.rule_id)
                else:
                    lines.append(f"- *(Same rule as above)*")

                # ALWAYS show this finding's own code context
                lines.append(f"- **Code at line {f.line_number}**:")
                lines.append("```c")
                for snippet_line in f.code_snippet.split('\n'):
                    stripped = snippet_line.strip()
                    if stripped:
                        lines.append(stripped)
                lines.append("```")
                lines.append(
                    f"- **Matched**: `{f.matched_text[:120]}`"
                )
                lines.append(
                    f"- **Suggested fix**: {f.suggested_fix}"
                )

                # Evidence only on first occurrence
                if is_first:
                    lines.append(
                        f"- **Evidence**: {f.evidence[:150]}"
                    )

                lines.append("")

        return '\n'.join(lines)

    @staticmethod
    def _build_validation_prompt(findings: List[Finding],
                                  files_analyzed: List[str]) -> str:
        """Build the actual prompt to paste into Gemini."""

        # Count unique rules
        unique_rules = set(f.rule_id for f in findings)
        sev_counts = Counter(f.severity_name for f in findings)

        prompt = f"""You are an embedded systems expert reviewing CPU load optimization findings from a static analysis tool. The tool analyzed embedded C source code for an ultrasonic sensor platform and produced the findings attached in "findings_for_review.md".

## YOUR TASK

For each finding in the attached findings document, provide:

1. **VERDICT**: One of:
   - **CONFIRMED** — This is a real optimization opportunity that will reduce CPU load
   - **FALSE POSITIVE** — The tool flagged this incorrectly; this code is already optimal or the rule doesn't apply here
   - **CONTEXT NEEDED** — Cannot determine without knowing runtime behavior (e.g., how often this code executes)
   - **PARTIAL** — The issue exists but the impact is different than stated

2. **REASONING** (1-2 sentences): Why you reached this verdict, referencing the specific code.

3. **REVISED IMPACT** (optional): If you disagree with the impact score, suggest a revised one.

## WHAT TO LOOK FOR

The tool uses regex-based pattern matching, so it may:
- Flag struct member declarations as "uninitialized variables" (they're initialized when the struct is used)
- Flag divisions that the compiler already optimizes at -O2
- Miss context about whether code is in a hot path or cold path
- Flag standard library functions as "function calls in loops" even though they're already optimized
- Not know if a float variable genuinely needs floating-point precision

## FORMAT YOUR RESPONSE AS

For each finding, use this format:
```
[RULE_ID] Rule Name — Line(s)
VERDICT: CONFIRMED | FALSE POSITIVE | CONTEXT NEEDED | PARTIAL
REASONING: ...
```

Then at the end, provide:
- **Overall accuracy estimate**: What percentage of findings are valid?
- **Top 3 most impactful findings**: Which ones should be fixed first?
- **Missed opportunities**: Anything the tool missed that you can see in the source code?

## CONTEXT

- This is embedded C for an automotive ultrasonic sensor platform
- Target MCU likely ARM Cortex-M based (common for automotive sensors)
- Code runs in real-time loops, so CPU load optimization is critical
- The team's goal is measurable CPU load reduction

Please be rigorous and specific. The team will use your review to prioritize their optimization work.
"""
        return prompt

    @staticmethod
    def _build_instructions(files_analyzed: List[str],
                            findings_path: str,
                            prompt_path: str) -> str:
        """Build step-by-step instructions for the user."""
        source_files = '\n'.join(
            f"   - `{os.path.basename(f)}`" for f in files_analyzed
        )

        return f"""# How to Validate Findings with Gemini 3 Pro

## Step-by-Step Process

### Step 1: Open Gemini 3 Pro
Go to your company-approved Gemini web interface.

### Step 2: Upload Files (in this order)

**Upload 1 — The source code file(s):**
{source_files}
   These are the original C files that were analyzed.

**Upload 2 — The findings summary:**
   - `findings_for_review.md`
   This is a compact, LLM-optimized summary of all findings.
   (~2000 tokens vs ~50,000 tokens for the HTML report)

### Step 3: Paste the Validation Prompt
Open `validation_prompt.md` and copy-paste its ENTIRE content
into the Gemini chat as your message.

### Step 4: Review Gemini's Response
Gemini will go through each finding and give a verdict:
- **CONFIRMED** → Fix this, it's real
- **FALSE POSITIVE** → Ignore, remove from your action list
- **CONTEXT NEEDED** → You need to decide based on your domain knowledge
- **PARTIAL** → Consider with adjusted priority

### Step 5: Create Your Action Plan
Filter findings to only CONFIRMED ones, sort by impact score,
and start fixing from the top.

## Why This Approach (Not HTML Upload)

| Approach | Tokens Used | LLM Thinking Room | Quality |
|----------|-------------|-------------------|---------|
| HTML report + source | ~60,000 | Low | Poor — LLM wastes tokens on CSS/JS |
| JSON findings + source | ~8,000 | High | Good |
| **This export + source** | **~4,000** | **Maximum** | **Best** |

The compact markdown export gives the LLM all the information it needs
(rule ID, location, code sample, evidence) without any visual formatting
overhead. This means Gemini can spend its context window actually
ANALYZING your code instead of parsing HTML tags.

## Pro Tips

1. **Split large codebases**: If you have 10+ source files, validate
   in batches of 3-4 files per Gemini session for best quality.

2. **Follow up on CONTEXT NEEDED**: For those findings, tell Gemini
   specifics like "this function runs at 10kHz in the main sensor loop"
   and ask it to re-evaluate.

3. **Ask for missed findings**: After validation, ask Gemini:
   "Looking at the source code, are there any CPU optimization
   opportunities that the tool missed?"

4. **Save the validated results**: Copy Gemini's response and save it
   alongside the HTML report for documentation.
"""


# ============================================================================
# GIT STAGED CHANGES ANALYZER
# ============================================================================

class GitAnalyzer:
    """
    Handles git repository analysis — specifically staged changes.

    Uses git CLI via subprocess (no gitpython dependency).
    Parses unified diff to identify exactly which lines changed,
    then filters analysis findings to only report issues on those lines.
    """

    @staticmethod
    def is_git_repo(path: str) -> bool:
        """Check if the given path is inside a git repository."""
        try:
            result = subprocess.run(
                ['git', '-C', path, 'rev-parse', '--is-inside-work-tree'],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0 and result.stdout.strip() == 'true'
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def get_repo_root(path: str) -> Optional[str]:
        """Get the root directory of the git repository."""
        try:
            result = subprocess.run(
                ['git', '-C', path, 'rev-parse', '--show-toplevel'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    @staticmethod
    def get_staged_files(repo_path: str) -> List[str]:
        """
        Get list of staged .c/.h files (added or modified).

        Returns absolute paths to the staged files.
        """
        try:
            result = subprocess.run(
                ['git', '-C', repo_path, 'diff', '--cached',
                 '--name-only', '--diff-filter=ACM'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return []

            all_files = result.stdout.strip().split('\n')
            c_h_files = [
                f for f in all_files
                if f.strip() and (f.endswith('.c') or f.endswith('.h'))
            ]
            # Convert to absolute paths
            return [
                os.path.join(repo_path, f) for f in c_h_files
            ]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    @staticmethod
    def get_staged_line_numbers(repo_path: str,
                                 file_path: str) -> set:
        """
        Parse 'git diff --cached' to extract the exact line numbers
        that were added or modified in the staged version.

        Returns a set of 1-based line numbers representing changed lines.

        How it works:
        - Unified diff headers look like: @@ -old,count +new,count @@
        - Lines starting with '+' (but not '+++') are additions
        - We track the current line number in the new (staged) version
        - Only '+' lines are "changed" — context lines are unchanged
        """
        rel_path = os.path.relpath(file_path, repo_path)
        try:
            result = subprocess.run(
                ['git', '-C', repo_path, 'diff', '--cached', '-U0',
                 '--', rel_path],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return set()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return set()

        changed_lines = set()
        current_line = 0

        for line in result.stdout.split('\n'):
            # Parse hunk header: @@ -old_start,old_count +new_start,new_count @@
            hunk_match = re.match(
                r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', line
            )
            if hunk_match:
                start = int(hunk_match.group(1))
                count = int(hunk_match.group(2)) if hunk_match.group(2) else 1
                # With -U0, all lines in the range are changes
                for i in range(count):
                    changed_lines.add(start + i)
                continue

        return changed_lines

    @staticmethod
    def get_staged_content(repo_path: str, file_path: str) -> Optional[str]:
        """
        Get the staged version of a file (not the working copy).

        This is important: the working copy might have unstaged changes.
        We want to analyze exactly what will be committed.
        """
        rel_path = os.path.relpath(file_path, repo_path)
        try:
            result = subprocess.run(
                ['git', '-C', repo_path, 'show', f':{rel_path}'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    @staticmethod
    def get_staged_summary(repo_path: str,
                            staged_files: List[str]) -> Dict:
        """
        Build a summary of staged changes for display.

        Returns dict with file names, line counts, etc.
        """
        summary = {
            'repo_root': repo_path,
            'total_files': len(staged_files),
            'files': []
        }

        for fp in staged_files:
            changed_lines = GitAnalyzer.get_staged_line_numbers(
                repo_path, fp
            )
            summary['files'].append({
                'path': fp,
                'name': os.path.basename(fp),
                'changed_lines': len(changed_lines),
                'line_numbers': sorted(changed_lines)
            })

        summary['total_changed_lines'] = sum(
            f['changed_lines'] for f in summary['files']
        )
        return summary


# ============================================================================
# CORE ANALYSIS RUNNER (shared by CLI and GUI)
# ============================================================================

def discover_files(target: str) -> List[str]:
    """Find all .c and .h files in the target path."""
    target_path = Path(target)
    if target_path.is_file():
        if target_path.suffix in ('.c', '.h'):
            return [str(target_path)]
        else:
            print(f"Warning: {target} is not a .c or .h file")
            return []
    elif target_path.is_dir():
        files = []
        for ext in ('*.c', '*.h'):
            files.extend(str(p) for p in target_path.rglob(ext))
        return sorted(files)
    else:
        print(f"Error: {target} does not exist")
        return []


def run_analysis(files: List[str],
                 output_path: str,
                 min_severity: str = "low",
                 annotate: bool = False,
                 llm_export: bool = False,
                 verbose: bool = False,
                 staged_mode: bool = False,
                 repo_path: Optional[str] = None,
                 staged_lines: Optional[Dict[str, set]] = None,
                 log_callback=None) -> Dict:
    """
    Core analysis pipeline — used by both CLI and GUI.

    Args:
        files: List of file paths to analyze
        output_path: Where to write the HTML report
        min_severity: Minimum severity to report
        annotate: Whether to generate code annotations
        llm_export: Whether to generate LLM validation export
        verbose: Print findings to console
        staged_mode: If True, filter findings to staged lines only
        repo_path: Git repo root (required if staged_mode=True)
        staged_lines: Dict of {filepath: set(line_numbers)} for filtering
        log_callback: Optional function(msg) for GUI logging

    Returns:
        Dict with analysis results summary
    """
    def log(msg):
        if log_callback:
            log_callback(msg)
        print(msg)

    # Ensure output directory exists
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    engine = RulesEngine()
    min_sev = Severity.from_str(min_severity)
    all_findings = []
    analysis_mode = "Staged Changes" if staged_mode else "Full File"

    log(f"\n{'='*60}")
    log(f"  CPU Load Optimizer v1.0")
    log(f"  Mode: {analysis_mode}")
    log(f"  Analyzing {len(files)} file(s)...")
    log(f"{'='*60}\n")

    for fp in files:
        log(f"  Scanning: {os.path.basename(fp)}")
        try:
            if staged_mode and repo_path:
                # Read the STAGED version, not the working copy
                source = GitAnalyzer.get_staged_content(repo_path, fp)
                if source is None:
                    log(f"    → Error: cannot read staged content")
                    continue
            else:
                with open(fp, 'r', encoding='utf-8', errors='replace') as f:
                    source = f.read()

            findings = engine.analyze(source, fp, min_sev)

            # Filter to staged lines only if in staged mode
            if staged_mode and staged_lines and fp in staged_lines:
                changed = staged_lines[fp]
                before_count = len(findings)
                findings = [
                    f for f in findings if f.line_number in changed
                ]
                log(f"    → {before_count} total findings, "
                    f"{len(findings)} on staged lines")
            else:
                log(f"    → {len(findings)} finding(s)")

            all_findings.extend(findings)

        except Exception as e:
            log(f"    → Error: {e}")

    # Sort findings
    all_findings.sort(key=lambda f: (-f.severity, -f.impact_score))

    # Print to console if verbose
    if verbose:
        log(f"\n{'─'*60}")
        for f in all_findings:
            log(f"  [{f.severity_name:8}] {f.rule_id} {f.rule_name}")
            log(f"           {os.path.basename(f.file_path)}:{f.line_number}")
            log(f"           Impact: {f.impact_score}/100")
            log(f"           {f.matched_text[:80]}")
            log("")

    # Generate HTML report
    annotator = CodeAnnotator() if annotate else None
    report_path = ReportGenerator.generate(
        all_findings, files, annotator, output_path
    )

    # Generate LLM export if requested
    llm_export_paths = None
    if llm_export:
        llm_output_dir = str(Path(output_path).parent / "llm_validation")
        source_contents = {}
        for fp in files:
            try:
                if staged_mode and repo_path:
                    content = GitAnalyzer.get_staged_content(repo_path, fp)
                    if content:
                        source_contents[fp] = content
                else:
                    with open(fp, 'r', encoding='utf-8',
                              errors='replace') as f:
                        source_contents[fp] = f.read()
            except Exception:
                pass

        llm_export_paths = LLMValidationExport.generate(
            all_findings, files, llm_output_dir, source_contents
        )

    log(f"\n{'='*60}")
    log(f"  Analysis Complete! ({analysis_mode})")
    log(f"  Total findings: {len(all_findings)}")
    log(f"  Report saved to: {report_path}")
    if llm_export_paths:
        log(f"  LLM validation export:")
        for p in llm_export_paths:
            log(f"    → {p}")
    log(f"{'='*60}\n")

    return {
        'total_findings': len(all_findings),
        'findings': all_findings,
        'report_path': report_path,
        'llm_export_paths': llm_export_paths,
        'by_severity': dict(Counter(f.severity_name for f in all_findings)),
        'mode': analysis_mode,
    }


# ============================================================================
# GUI — tkinter Launcher
# ============================================================================

def launch_gui():
    """Launch the tkinter GUI for CPU Load Optimizer."""
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
    except ImportError:
        print("Error: tkinter is not available.")
        print("Install with: sudo apt-get install python3-tk")
        sys.exit(1)

    class OptimizerGUI:
        """
        Professional GUI launcher with two analysis modes.

        Mode 1: Analyze specific source file(s) or directory
        Mode 2: Analyze only staged git changes in a repository
        """

        # ── Color scheme (matches HTML report theme) ──
        BG = "#0f0f17"
        SURFACE = "#1a1a2e"
        SURFACE2 = "#222240"
        BORDER = "#2d2d4a"
        TEXT = "#e2e2f0"
        TEXT_DIM = "#8888a8"
        ACCENT = "#6c5ce7"
        ACCENT_LIGHT = "#a78bfa"
        CRITICAL = "#dc2626"
        HIGH = "#ea580c"
        MEDIUM = "#ca8a04"
        LOW = "#2563eb"
        SUCCESS = "#16a34a"

        def __init__(self):
            self.root = tk.Tk()
            self.root.title("CPU Load Optimizer v1.0")
            self.root.configure(bg=self.BG)
            self.root.resizable(True, True)

            # Center window
            w, h = 720, 740
            x = (self.root.winfo_screenwidth() // 2) - (w // 2)
            y = (self.root.winfo_screenheight() // 2) - (h // 2)
            self.root.geometry(f"{w}x{h}+{x}+{y}")
            self.root.minsize(600, 650)

            # Variables
            self.mode = tk.StringVar(value="file")
            self.file_path = tk.StringVar()
            self.repo_path = tk.StringVar()
            self.severity = tk.StringVar(value="low")
            self.llm_export = tk.BooleanVar(value=True)
            self.annotate = tk.BooleanVar(value=False)
            self.is_running = False

            self._build_ui()

        def _build_ui(self):
            """Construct the full GUI layout."""
            root = self.root

            # ── Header ───────────────────────────────────────
            header = tk.Frame(root, bg=self.SURFACE, pady=16, padx=24)
            header.pack(fill=tk.X)

            tk.Label(
                header, text="CPU Load Optimizer",
                font=("Segoe UI", 22, "bold"),
                fg=self.ACCENT_LIGHT, bg=self.SURFACE
            ).pack(anchor=tk.W)
            tk.Label(
                header,
                text="Static analysis for embedded C/H CPU optimization "
                     "• 25+ verified rules • No LLM dependency",
                font=("Segoe UI", 9),
                fg=self.TEXT_DIM, bg=self.SURFACE
            ).pack(anchor=tk.W, pady=(4, 0))

            # ── Separator ────────────────────────────────────
            tk.Frame(root, bg=self.BORDER, height=1).pack(fill=tk.X)

            # ── Main content frame ───────────────────────────
            content = tk.Frame(root, bg=self.BG, padx=24, pady=16)
            content.pack(fill=tk.BOTH, expand=True)

            # ── Mode Selection ───────────────────────────────
            mode_label = tk.Label(
                content, text="ANALYSIS MODE",
                font=("Segoe UI", 10, "bold"),
                fg=self.ACCENT_LIGHT, bg=self.BG
            )
            mode_label.pack(anchor=tk.W, pady=(0, 10))

            # --- Mode 1: File Analysis ---
            mode1_frame = tk.Frame(content, bg=self.SURFACE,
                                   highlightbackground=self.BORDER,
                                   highlightthickness=1, padx=16, pady=12)
            mode1_frame.pack(fill=tk.X, pady=(0, 8))

            mode1_top = tk.Frame(mode1_frame, bg=self.SURFACE)
            mode1_top.pack(fill=tk.X)

            self.rb_file = tk.Radiobutton(
                mode1_top, text="Analyze Source File / Directory",
                variable=self.mode, value="file",
                font=("Segoe UI", 11, "bold"),
                fg=self.TEXT, bg=self.SURFACE,
                selectcolor=self.SURFACE2,
                activebackground=self.SURFACE,
                activeforeground=self.ACCENT_LIGHT,
                command=self._on_mode_change
            )
            self.rb_file.pack(side=tk.LEFT)

            tk.Label(
                mode1_frame,
                text="Browse for a .c / .h file or a folder "
                     "containing source files",
                font=("Segoe UI", 9),
                fg=self.TEXT_DIM, bg=self.SURFACE
            ).pack(anchor=tk.W, pady=(2, 8))

            file_row = tk.Frame(mode1_frame, bg=self.SURFACE)
            file_row.pack(fill=tk.X)

            self.file_entry = tk.Entry(
                file_row, textvariable=self.file_path,
                font=("Consolas", 10),
                bg=self.SURFACE2, fg=self.TEXT,
                insertbackground=self.TEXT,
                relief=tk.FLAT, highlightthickness=1,
                highlightbackground=self.BORDER
            )
            self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True,
                                 ipady=6, padx=(0, 8))

            self.btn_browse_file = tk.Button(
                file_row, text="Browse File",
                font=("Segoe UI", 9, "bold"),
                bg=self.ACCENT, fg="white",
                activebackground=self.ACCENT_LIGHT,
                relief=tk.FLAT, padx=12, pady=4,
                cursor="hand2",
                command=self._browse_file
            )
            self.btn_browse_file.pack(side=tk.LEFT, padx=(0, 4))

            self.btn_browse_dir = tk.Button(
                file_row, text="Browse Folder",
                font=("Segoe UI", 9, "bold"),
                bg=self.SURFACE2, fg=self.TEXT,
                activebackground=self.BORDER,
                relief=tk.FLAT, padx=12, pady=4,
                cursor="hand2",
                command=self._browse_directory
            )
            self.btn_browse_dir.pack(side=tk.LEFT)

            # --- Mode 2: Git Staged Changes ---
            mode2_frame = tk.Frame(content, bg=self.SURFACE,
                                   highlightbackground=self.BORDER,
                                   highlightthickness=1, padx=16, pady=12)
            mode2_frame.pack(fill=tk.X, pady=(0, 16))

            mode2_top = tk.Frame(mode2_frame, bg=self.SURFACE)
            mode2_top.pack(fill=tk.X)

            self.rb_staged = tk.Radiobutton(
                mode2_top, text="Analyze Staged Git Changes",
                variable=self.mode, value="staged",
                font=("Segoe UI", 11, "bold"),
                fg=self.TEXT, bg=self.SURFACE,
                selectcolor=self.SURFACE2,
                activebackground=self.SURFACE,
                activeforeground=self.ACCENT_LIGHT,
                command=self._on_mode_change
            )
            self.rb_staged.pack(side=tk.LEFT)

            tk.Label(
                mode2_frame,
                text="Browse for a git repository — only staged "
                     "(git add) changes in .c/.h files will be analyzed",
                font=("Segoe UI", 9),
                fg=self.TEXT_DIM, bg=self.SURFACE
            ).pack(anchor=tk.W, pady=(2, 8))

            repo_row = tk.Frame(mode2_frame, bg=self.SURFACE)
            repo_row.pack(fill=tk.X)

            self.repo_entry = tk.Entry(
                repo_row, textvariable=self.repo_path,
                font=("Consolas", 10),
                bg=self.SURFACE2, fg=self.TEXT,
                insertbackground=self.TEXT,
                relief=tk.FLAT, highlightthickness=1,
                highlightbackground=self.BORDER
            )
            self.repo_entry.pack(side=tk.LEFT, fill=tk.X, expand=True,
                                 ipady=6, padx=(0, 8))

            self.btn_browse_repo = tk.Button(
                repo_row, text="Browse Repository",
                font=("Segoe UI", 9, "bold"),
                bg=self.ACCENT, fg="white",
                activebackground=self.ACCENT_LIGHT,
                relief=tk.FLAT, padx=12, pady=4,
                cursor="hand2",
                command=self._browse_repo
            )
            self.btn_browse_repo.pack(side=tk.LEFT)

            # Staged files info label
            self.staged_info = tk.Label(
                mode2_frame, text="",
                font=("Consolas", 9),
                fg=self.TEXT_DIM, bg=self.SURFACE,
                justify=tk.LEFT, anchor=tk.W
            )
            self.staged_info.pack(anchor=tk.W, fill=tk.X, pady=(8, 0))

            # ── Settings ─────────────────────────────────────
            settings_label = tk.Label(
                content, text="SETTINGS",
                font=("Segoe UI", 10, "bold"),
                fg=self.ACCENT_LIGHT, bg=self.BG
            )
            settings_label.pack(anchor=tk.W, pady=(0, 8))

            settings_frame = tk.Frame(content, bg=self.SURFACE,
                                       highlightbackground=self.BORDER,
                                       highlightthickness=1,
                                       padx=16, pady=12)
            settings_frame.pack(fill=tk.X, pady=(0, 16))

            settings_row1 = tk.Frame(settings_frame, bg=self.SURFACE)
            settings_row1.pack(fill=tk.X, pady=(0, 8))

            tk.Label(
                settings_row1, text="Minimum Severity:",
                font=("Segoe UI", 10),
                fg=self.TEXT, bg=self.SURFACE
            ).pack(side=tk.LEFT, padx=(0, 8))

            sev_menu = tk.OptionMenu(
                settings_row1, self.severity,
                "low", "medium", "high", "critical"
            )
            sev_menu.configure(
                font=("Consolas", 10),
                bg=self.SURFACE2, fg=self.TEXT,
                activebackground=self.BORDER,
                highlightthickness=0, relief=tk.FLAT,
                width=10
            )
            sev_menu["menu"].configure(
                bg=self.SURFACE2, fg=self.TEXT,
                activebackground=self.ACCENT,
                font=("Consolas", 10)
            )
            sev_menu.pack(side=tk.LEFT)

            settings_row2 = tk.Frame(settings_frame, bg=self.SURFACE)
            settings_row2.pack(fill=tk.X, pady=(0, 4))

            tk.Checkbutton(
                settings_row2,
                text="Generate LLM Validation Export "
                     "(for Gemini / GPT review)",
                variable=self.llm_export,
                font=("Segoe UI", 10),
                fg=self.TEXT, bg=self.SURFACE,
                selectcolor=self.SURFACE2,
                activebackground=self.SURFACE,
                activeforeground=self.TEXT
            ).pack(anchor=tk.W)

            tk.Checkbutton(
                settings_row2,
                text="Code Annotations (requires Pillow)",
                variable=self.annotate,
                font=("Segoe UI", 10),
                fg=self.TEXT, bg=self.SURFACE,
                selectcolor=self.SURFACE2,
                activebackground=self.SURFACE,
                activeforeground=self.TEXT
            ).pack(anchor=tk.W)

            # ── Run Button ───────────────────────────────────
            self.btn_run = tk.Button(
                content, text="▶  Run Analysis",
                font=("Segoe UI", 13, "bold"),
                bg=self.ACCENT, fg="white",
                activebackground=self.ACCENT_LIGHT,
                relief=tk.FLAT, pady=10,
                cursor="hand2",
                command=self._run_analysis
            )
            self.btn_run.pack(fill=tk.X, pady=(0, 16))

            # ── Status / Log ─────────────────────────────────
            status_label = tk.Label(
                content, text="STATUS",
                font=("Segoe UI", 10, "bold"),
                fg=self.ACCENT_LIGHT, bg=self.BG
            )
            status_label.pack(anchor=tk.W, pady=(0, 6))

            log_frame = tk.Frame(content, bg=self.SURFACE,
                                  highlightbackground=self.BORDER,
                                  highlightthickness=1)
            log_frame.pack(fill=tk.BOTH, expand=True)

            self.log_text = tk.Text(
                log_frame, font=("Consolas", 9),
                bg=self.SURFACE, fg=self.TEXT_DIM,
                relief=tk.FLAT, wrap=tk.WORD,
                insertbackground=self.TEXT,
                padx=12, pady=8,
                state=tk.DISABLED
            )
            scrollbar = tk.Scrollbar(
                log_frame, command=self.log_text.yview,
                bg=self.SURFACE2, troughcolor=self.SURFACE
            )
            self.log_text.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            self.log_text.pack(fill=tk.BOTH, expand=True)

            # Configure text tags for colored output
            self.log_text.tag_configure("info", foreground=self.TEXT)
            self.log_text.tag_configure("success",
                                         foreground=self.SUCCESS)
            self.log_text.tag_configure("warning",
                                         foreground=self.MEDIUM)
            self.log_text.tag_configure("error",
                                         foreground=self.CRITICAL)
            self.log_text.tag_configure("accent",
                                         foreground=self.ACCENT_LIGHT)

            self._log("Ready. Select a mode and browse for your target.",
                      "info")
            self._on_mode_change()

        # ── Logging ──────────────────────────────────────────

        def _log(self, msg: str, tag: str = "info"):
            """Append a message to the status log."""
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, msg + "\n", tag)
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)
            self.root.update_idletasks()

        def _clear_log(self):
            """Clear the status log."""
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.delete("1.0", tk.END)
            self.log_text.configure(state=tk.DISABLED)

        # ── Mode Switching ───────────────────────────────────

        def _on_mode_change(self):
            """Update UI state based on selected mode."""
            mode = self.mode.get()
            is_file = (mode == "file")

            # Visual state for file mode controls
            state_file = tk.NORMAL if is_file else tk.DISABLED
            state_repo = tk.DISABLED if is_file else tk.NORMAL

            self.file_entry.configure(state=state_file)
            self.btn_browse_file.configure(
                state=state_file,
                bg=self.ACCENT if is_file else self.BORDER
            )
            self.btn_browse_dir.configure(
                state=state_file,
                bg=self.SURFACE2 if is_file else self.BORDER
            )

            self.repo_entry.configure(state=state_repo)
            self.btn_browse_repo.configure(
                state=state_repo,
                bg=self.ACCENT if not is_file else self.BORDER
            )

        # ── Browse Dialogs ───────────────────────────────────

        def _browse_file(self):
            """Open file dialog for .c/.h files."""
            path = filedialog.askopenfilename(
                title="Select C/H Source File",
                filetypes=[
                    ("C Source Files", "*.c"),
                    ("C Header Files", "*.h"),
                    ("All C/H Files", "*.c *.h"),
                    ("All Files", "*.*")
                ]
            )
            if path:
                self.file_path.set(path)
                self._log(f"Selected file: {path}", "info")

        def _browse_directory(self):
            """Open directory dialog for source folder."""
            path = filedialog.askdirectory(
                title="Select Directory Containing Source Files"
            )
            if path:
                self.file_path.set(path)
                # Count .c/.h files in directory
                count = len(discover_files(path))
                self._log(
                    f"Selected directory: {path} "
                    f"({count} .c/.h files found)", "info"
                )

        def _browse_repo(self):
            """Open directory dialog for git repository."""
            path = filedialog.askdirectory(
                title="Select Git Repository Root"
            )
            if not path:
                return

            # Validate it's a git repo
            if not GitAnalyzer.is_git_repo(path):
                self._log(
                    f"ERROR: {path} is not a git repository!", "error"
                )
                messagebox.showerror(
                    "Not a Git Repository",
                    f"The selected directory is not a git repository.\n\n"
                    f"Path: {path}\n\n"
                    f"Make sure you select a folder that contains a "
                    f".git directory."
                )
                return

            # Find repo root (in case they selected a subfolder)
            repo_root = GitAnalyzer.get_repo_root(path) or path
            self.repo_path.set(repo_root)
            self._log(f"Repository: {repo_root}", "accent")

            # Check for staged files
            staged = GitAnalyzer.get_staged_files(repo_root)
            if not staged:
                self.staged_info.configure(
                    text="⚠ No staged .c/.h files found.\n"
                         "Stage changes first with: git add <file>",
                    fg=self.MEDIUM
                )
                self._log(
                    "WARNING: No staged .c/.h files. "
                    "Use 'git add' to stage changes first.", "warning"
                )
            else:
                summary = GitAnalyzer.get_staged_summary(
                    repo_root, staged
                )
                info_lines = [
                    f"✓ {summary['total_files']} staged file(s), "
                    f"{summary['total_changed_lines']} changed lines:"
                ]
                for f in summary['files']:
                    info_lines.append(
                        f"  • {f['name']} "
                        f"({f['changed_lines']} lines changed)"
                    )
                self.staged_info.configure(
                    text='\n'.join(info_lines),
                    fg=self.SUCCESS
                )
                self._log(
                    f"Found {summary['total_files']} staged C/H "
                    f"file(s) with {summary['total_changed_lines']} "
                    f"changed lines", "success"
                )
                for f_info in summary['files']:
                    self._log(
                        f"  • {f_info['name']}: "
                        f"lines {f_info['line_numbers'][:10]}"
                        f"{'...' if len(f_info['line_numbers']) > 10 else ''}",
                        "info"
                    )

        # ── Run Analysis ─────────────────────────────────────

        def _run_analysis(self):
            """Execute analysis based on selected mode."""
            if self.is_running:
                return

            mode = self.mode.get()
            self._clear_log()

            if mode == "file":
                self._run_file_analysis()
            else:
                self._run_staged_analysis()

        def _run_file_analysis(self):
            """Mode 1: Analyze specific file(s)."""
            target = self.file_path.get().strip()
            if not target:
                self._log("ERROR: No file or directory selected!", "error")
                messagebox.showwarning(
                    "No Target",
                    "Please browse for a .c/.h file or directory first."
                )
                return

            files = discover_files(target)
            if not files:
                self._log(
                    f"ERROR: No .c/.h files found in: {target}", "error"
                )
                return

            # Resolve output path
            script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
            output_dir = script_dir / "Output"
            output_path = str(output_dir / "cpu_load_report.html")

            self._execute_analysis(
                files=files,
                output_path=output_path,
                staged_mode=False
            )

        def _run_staged_analysis(self):
            """Mode 2: Analyze staged git changes."""
            repo = self.repo_path.get().strip()
            if not repo:
                self._log(
                    "ERROR: No repository selected!", "error"
                )
                messagebox.showwarning(
                    "No Repository",
                    "Please browse for a git repository first."
                )
                return

            if not GitAnalyzer.is_git_repo(repo):
                self._log(
                    f"ERROR: {repo} is not a git repository!", "error"
                )
                return

            staged_files = GitAnalyzer.get_staged_files(repo)
            if not staged_files:
                self._log(
                    "ERROR: No staged .c/.h files found!", "error"
                )
                self._log(
                    "Stage changes with: git add <file>", "warning"
                )
                messagebox.showwarning(
                    "No Staged Files",
                    "No staged .c/.h files found in the repository.\n\n"
                    "Stage your changes first:\n"
                    "  git add <file.c>\n"
                    "  git add .\n\n"
                    "Then run the analysis again."
                )
                return

            # Build staged line map
            staged_lines = {}
            for fp in staged_files:
                lines = GitAnalyzer.get_staged_line_numbers(repo, fp)
                staged_lines[fp] = lines

            # Output path
            script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
            output_dir = script_dir / "Output"
            output_path = str(
                output_dir / "cpu_load_staged_report.html"
            )

            self._execute_analysis(
                files=staged_files,
                output_path=output_path,
                staged_mode=True,
                repo_path=repo,
                staged_lines=staged_lines
            )

        def _execute_analysis(self, files, output_path,
                               staged_mode=False, repo_path=None,
                               staged_lines=None):
            """Run the analysis and update the GUI."""
            self.is_running = True
            self.btn_run.configure(
                text="⏳  Analyzing...",
                bg=self.BORDER, state=tk.DISABLED
            )
            self.root.update_idletasks()

            try:
                result = run_analysis(
                    files=files,
                    output_path=output_path,
                    min_severity=self.severity.get(),
                    annotate=self.annotate.get(),
                    llm_export=self.llm_export.get(),
                    verbose=False,
                    staged_mode=staged_mode,
                    repo_path=repo_path,
                    staged_lines=staged_lines,
                    log_callback=lambda msg: self._log(msg, "info")
                )

                # Show results summary
                self._log("", "info")
                self._log("━" * 50, "accent")
                self._log(
                    f"  ✓ ANALYSIS COMPLETE "
                    f"({result['mode']})", "success"
                )
                self._log(f"━" * 50, "accent")

                total = result['total_findings']
                by_sev = result['by_severity']

                self._log(f"  Total: {total} findings", "info")
                if by_sev.get('CRITICAL', 0) > 0:
                    self._log(
                        f"  CRITICAL: {by_sev['CRITICAL']}", "error"
                    )
                if by_sev.get('HIGH', 0) > 0:
                    self._log(
                        f"  HIGH: {by_sev['HIGH']}", "warning"
                    )
                if by_sev.get('MEDIUM', 0) > 0:
                    self._log(
                        f"  MEDIUM: {by_sev['MEDIUM']}", "info"
                    )
                if by_sev.get('LOW', 0) > 0:
                    self._log(
                        f"  LOW: {by_sev['LOW']}", "info"
                    )

                self._log("", "info")
                self._log(
                    f"  Report: {result['report_path']}", "accent"
                )

                if result.get('llm_export_paths'):
                    self._log("  LLM Export:", "accent")
                    for p in result['llm_export_paths']:
                        self._log(f"    → {p}", "info")

                # Offer to open report
                if messagebox.askyesno(
                    "Analysis Complete",
                    f"Found {total} optimization "
                    f"opportunities.\n\n"
                    f"Open the HTML report now?"
                ):
                    self._open_report(result['report_path'])

            except Exception as e:
                self._log(f"\nERROR: {str(e)}", "error")
                import traceback
                self._log(traceback.format_exc(), "error")
                messagebox.showerror("Analysis Error", str(e))

            finally:
                self.is_running = False
                self.btn_run.configure(
                    text="▶  Run Analysis",
                    bg=self.ACCENT, state=tk.NORMAL
                )

        def _open_report(self, path):
            """Open the HTML report in the default browser."""
            import webbrowser
            webbrowser.open(f"file://{os.path.abspath(path)}")

        def run(self):
            """Start the GUI main loop."""
            self.root.mainloop()

    # Launch the GUI
    app = OptimizerGUI()
    app.run()


# ============================================================================
# MAIN CLI
# ============================================================================

def main():
    """
    Entry point — launches GUI if no arguments given,
    otherwise runs CLI mode.

    Usage:
        python cpu_load_optimizer.py                  → Launch GUI
        python cpu_load_optimizer.py --gui             → Launch GUI
        python cpu_load_optimizer.py <target> [opts]   → CLI mode
        python cpu_load_optimizer.py --staged <repo>   → Staged changes CLI
    """
    # If no arguments or --gui flag, launch GUI
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and
                               sys.argv[1] == '--gui'):
        launch_gui()
        return

    parser = argparse.ArgumentParser(
        description="CPU Load Optimizer — Static analysis for embedded C "
                    "CPU load optimization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  File mode (default):
    python cpu_load_optimizer.py src/sensor.c
    python cpu_load_optimizer.py ./platform/ -o report.html -s high

  Staged changes mode:
    python cpu_load_optimizer.py --staged /path/to/repo
    python cpu_load_optimizer.py --staged . -s critical --llm-export

  GUI mode:
    python cpu_load_optimizer.py
    python cpu_load_optimizer.py --gui

Rules Reference:
  25+ verified optimization rules based on MISRA C:2012,
  ARM Architecture Manual, Renesas AppNotes, and GCC documentation.
  No LLM dependency — fully deterministic, offline analysis.
        """
    )
    parser.add_argument("target", nargs='?', default=None,
                        help="Path to .c/.h file or directory "
                             "(not used in --staged mode)")
    parser.add_argument("--gui", action="store_true",
                        help="Launch graphical interface")
    parser.add_argument("--staged", metavar="REPO_PATH", default=None,
                        help="Analyze only staged git changes "
                             "in the given repository")
    parser.add_argument("-o", "--output", default=None,
                        help="Output HTML report path "
                             "(default: Output/cpu_load_report.html)")
    parser.add_argument("-s", "--severity", default="low",
                        choices=["critical", "high", "medium", "low"],
                        help="Minimum severity to report")
    parser.add_argument("--annotate", action="store_true",
                        help="Enable code screenshot annotations "
                             "(needs Pillow)")
    parser.add_argument("--llm-export", action="store_true",
                        help="Generate LLM-optimized validation "
                             "export for Gemini/GPT review")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print findings to console")

    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return

    # ── Resolve output path ──────────────────────────────────
    if args.output is None:
        script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        output_dir = script_dir / "Output"
        output_dir.mkdir(parents=True, exist_ok=True)
        if args.staged:
            args.output = str(
                output_dir / "cpu_load_staged_report.html"
            )
        else:
            args.output = str(output_dir / "cpu_load_report.html")
        print(f"  Output directory: {output_dir}")
    else:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Staged changes mode ──────────────────────────────────
    if args.staged:
        repo_path = os.path.abspath(args.staged)

        if not GitAnalyzer.is_git_repo(repo_path):
            print(f"ERROR: {repo_path} is not a git repository!")
            sys.exit(1)

        repo_root = GitAnalyzer.get_repo_root(repo_path) or repo_path
        staged_files = GitAnalyzer.get_staged_files(repo_root)

        if not staged_files:
            print("No staged .c/.h files found.")
            print("Stage changes with: git add <file>")
            sys.exit(1)

        # Build staged line map
        staged_lines = {}
        for fp in staged_files:
            lines = GitAnalyzer.get_staged_line_numbers(repo_root, fp)
            staged_lines[fp] = lines
            print(f"  Staged: {os.path.basename(fp)} "
                  f"({len(lines)} changed lines)")

        run_analysis(
            files=staged_files,
            output_path=args.output,
            min_severity=args.severity,
            annotate=args.annotate,
            llm_export=args.llm_export,
            verbose=args.verbose,
            staged_mode=True,
            repo_path=repo_root,
            staged_lines=staged_lines
        )
        return

    # ── File mode (default) ──────────────────────────────────
    if not args.target:
        print("Error: No target specified. Use --help for usage.")
        sys.exit(1)

    files = discover_files(args.target)
    if not files:
        print("No .c or .h files found.")
        sys.exit(1)

    run_analysis(
        files=files,
        output_path=args.output,
        min_severity=args.severity,
        annotate=args.annotate,
        llm_export=args.llm_export,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
