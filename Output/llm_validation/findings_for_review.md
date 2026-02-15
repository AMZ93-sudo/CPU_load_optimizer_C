# CPU Load Optimizer — Findings for LLM Validation
# Generated: 2026-02-15 22:14
# Files: bad_example.c
# Total: 6 findings

## CRITICAL (1 findings)

### Finding #1: [C04] Multiplication by Power of 2
- **File**: bad_example.c  **Line**: 78  **Impact**: 75/100
- **Issue**: Integer multiplication by a constant power of 2 detected. While many compilers optimize this automatically, some embedded compilers with low optimization levels do not. MUL can cost 3-12 cycles vs 1 c
- **Code at line 78**:
```c
76 |
77 |     for (int i = 7; i >= 0; --i) {
>>>   78 |         uint8_t nibble = (uint8_t)((v >> (i * 4)) & 0xFu);
79 |         uint8_t ch = (nibble < 10) ? (uint8_t)('0' + nibble) : (uint8_t)('A' + nibble - 10);
80 |
```
- **Matched**: `i * 4`
- **Suggested fix**: x * {N} → x << {shift}
- **Evidence**: Renesas Embedded C III — MUL vs SHIFT cycle comparison; ARM Cortex-M instruction timing tables

## HIGH (2 findings)

### Finding #2: [H08] Redundant Repeated Computation
- **File**: bad_example.c  **Line**: 140  **Impact**: 62/100
- **Issue**: The same arithmetic expression appears to be computed multiple times in the same scope. Each redundant computation wastes CPU cycles.
- **Code at line 140**:
```c
138 |
139 |
>>>  140 |         x = (x / (x | 1u)) + (x % (x | 1u));
141 |
142 |
```
- **Matched**: `x | 1u)) + (x % (x | 1u`
- **Suggested fix**: const type temp = expr; // reuse temp
- **Evidence**: Common Subexpression Elimination — standard compiler optimization theory; Dragon Book Ch.10

### Finding #3: [H05] Potentially Oversized Data Type
- **File**: bad_example.c  **Line**: 77  **Impact**: 60/100
- **Issue**: An integer variable uses a type wider than necessary for its assigned value. On 8/16-bit MCUs, operations on 32-bit types require multiple instructions. Even on 32-bit MCUs, narrower types improve cac
- **Code at line 77**:
```c
75 | {
76 |
>>>   77 |     for (int i = 7; i >= 0; --i) {
78 |         uint8_t nibble = (uint8_t)((v >> (i * 4)) & 0xFu);
79 |         uint8_t ch = (nibble < 10) ? (uint8_t)('0' + nibble) : (uint8_t)('A' + nibble - 10);
```
- **Matched**: `int i = 7;`
- **Suggested fix**: Use uint8_t, uint16_t, or int16_t as appropriate
- **Evidence**: MISRA C:2012 Rules 10.1-10.4 — essential type model; Renesas AppNote — data type sizing impact

## LOW (3 findings)

### Finding #4: [L01] Magic Number
- **File**: bad_example.c  **Line**: 99  **Impact**: 20/100
- **Issue**: A numeric literal (magic number) is used directly in code. This prevents the compiler from constant-folding across translation units and makes code harder to maintain.
- **Code at line 99**:
```c
97 |
98 |
>>>   99 |     uint64_t wide = ((uint64_t)raw << 32) | (uint64_t)g_sample_count;
100 |     uint32_t m = expensive_mod_u64(wide);     /* modulo with large prime-ish divisor */
101 |
```
- **Matched**: `32`
- **Suggested fix**: #define DESCRIPTIVE_NAME ({value})
- **Evidence**: MISRA C:2012 Rule 7.1; Clean Code (Robert C. Martin) — magic numbers

### Finding #5: [L01] Magic Number
- **File**: bad_example.c  **Line**: 120  **Impact**: 20/100
- *(Same rule as above)*
- **Code at line 120**:
```c
118 |
119 |
>>>  120 |     busy_delay(2000);
121 |
122 |
```
- **Matched**: `2000`
- **Suggested fix**: #define DESCRIPTIVE_NAME ({value})

### Finding #6: [L01] Magic Number
- **File**: bad_example.c  **Line**: 175  **Impact**: 20/100
- *(Same rule as above)*
- **Code at line 175**:
```c
173 |
174 |
>>>  175 |         busy_delay(50000);
176 |
177 |
```
- **Matched**: `50000`
- **Suggested fix**: #define DESCRIPTIVE_NAME ({value})
