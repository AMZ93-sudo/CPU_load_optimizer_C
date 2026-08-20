# Gemini CLI Headless Repo-Aware Review — Implementation Plan

> **Feature:** `--gemini-review` — run **Gemini CLI in headless mode** against the browsed
> `.c`/`.h` file **plus its repository root**, to (a) validate the static findings and
> (b) discover cross-file CPU-load optimization opportunities the regex engine cannot see.
>
> **Target file:** `cpu_load_optimizer.py` (single file, 6859 lines)
> **Target machine:** corporate workstation (Windows, Gemini Code Assist Standard/Enterprise)
> **Author of plan:** Claude Code · **Reviewer:** Zeko (Tech Lead, USPM/KSS)
> **Design rule:** FTR — reuse what exists, add no new pip dependency, fail closed.

---

## 1. Current Status of the Tool (analysis)

| Area | State | Evidence |
|------|-------|----------|
| Engine | `RulesEngine` — 30+ rules, string-masking, symbol table, constant-folding suppression | `cpu_load_optimizer.py:376` |
| Roadmap | **Phase 0 (P0.1–P0.7) + Phase 1 (P1.1–P1.10) DONE & verified.** Phase 2/3 pending approval | `cpu_load_optimizer_improvement_plan.md`, commit `f3c3638` |
| Tests | 330 pass / 2 fail (pre-existing hard-coded `/home/user/...` path in `test_report.py`) | `tests/` |
| Open audit | 6 confirmed FPs, 6 FNs, 4 robustness issues, **not yet fixed** | `corner_case_audit_2026-07.md` (untracked) |
| LLM round-trip | **Contract already exists and works**: `findings_cache.json` → LLM JSON `{"verdicts":[…]}` → `LLMResponseParser` → `LLMValidatedReportGenerator` → HTML. CLI: `--apply-validation … --cache …` | `:3103`, `:4034`, `:4294`, `:6626` |
| LLM *transport* | **The weak link.** `_run_automated_llm_verification()` (`:6247`, ~300 lines) drives VS Code + Gemini Code Assist with `pyautogui` keystrokes, `sleep()`, and window-focus juggling. Single-file only, no repo context, silently breaks on any focus steal or extension update. Already flagged as **P2.5** in the roadmap. |

### Why this feature is the right next step

The round-trip *plumbing is already built and tested*. What is missing is a **reliable,
headless, repo-aware transport**. This feature is therefore **~70 % reuse / ~30 % new code**:
we replace the keystroke robot with a `subprocess` call and add the repository dimension.
It simultaneously closes roadmap item **P2.5**.

```
BEFORE:  findings → automated_llm_prompt.md → [pyautogui → VS Code → Gemini chat] → human copy/paste → --apply-validation
AFTER :  findings → gemini_review_prompt   → [subprocess: gemini -p "" --include-directories <repo>] → JSON → report   (0 human steps)
```

---

## 2. Empirical Validation Already Performed

Everything below was **executed**, not assumed (this machine, today):

| Check | Result |
|-------|--------|
| `gemini` on PATH | OK — `C:\Users\20114\AppData\Roaming\npm\gemini.cmd` |
| Version | OK — **0.49.0** |
| Headless flags exist (`gemini --help`) | OK — `-p/--prompt`, `-m/--model`, `-o/--output-format {text,json,stream-json}`, `--approval-mode {default,auto_edit,yolo,plan}`, `--include-directories`, `--session-id`, `--policy`, `--skip-trust`, `-e/--extensions`, `gemini skills …` |
| `-p` semantics | OK — help states: *"Run in non-interactive (headless) mode… **Appended to input on stdin (if any)**"* → we can pipe a large prompt on stdin and pass `-p ""` |
| Read-only mode exists | OK — `--approval-mode plan` = *"read-only mode"* — this is our primary guardrail |
| Actual invocation `echo … \| gemini -p "" --approval-mode plan -o json` | OK — flags accepted, stdin consumed, process reached the auth stage |
| Auth on a **personal** account (dev box) | **FAILED — `IneligibleTierError: This client is no longer supported for Gemini Code Assist for individuals`** |

### 2.1 Action item 0 — EXECUTED ON THE CORPORATE MACHINE: **PASSED**

```bash
echo "Reply with exactly: PONG" | gemini -p "" --approval-mode plan -o json
```

returned `"response": "PONG"`. **The feature is viable. Risk R1 is CLEARED on the corporate
machine.** (It remains true that the free "Code Assist for individuals" tier is rejected by
CLI 0.49 — so this feature will *not* work on personal machines. Document that in the README.)

The probe resolved the §6.4 unknown and surfaced **four new facts that change the design**:

| # | Observed | Consequence |
|---|----------|-------------|
| **F1** | Envelope confirmed: `{"session_id": "...", "response": "<model text>", "stats": {...}}` | `_extract_json()` reads the top-level **`response`** key, then finds the fenced json block inside it. `stats.models.*.tokens` and `stats.tools` are free telemetry → write them into `meta.json` (G12) |
| **F2** | **stdout is polluted with non-JSON preamble**: `The 'metricReader' option is deprecated…`, `Duplicate agent name 'issue_investigator' detected…`, `Ripgrep is not available. Falling back to GrepTool.` | **`json.loads(stdout)` will raise.** Mandatory: scan for the first `{` and use `json.JSONDecoder().raw_decode()` — see §6.4. This single fact would have broken a naive implementation on day one |
| **F3** | Model actually served: **`gemini-3.1-pro-preview`**, not 2.5-pro | Default model changes; and a *preview* model as the silent default is a determinism hazard → G15 now mandates an explicit `-m` |
| **F4** | `Duplicate agent name 'issue_investigator'` + deprecation warnings | The corporate machine has **custom agents/extensions/MCP servers configured**. They are being loaded into our run: unknown tools, extra tokens, unpredictable behaviour → **new guardrail G16 (environment isolation)** |
| **F5** | Baseline cost: **15,356 prompt tokens** for a one-line prompt; latency 3.5 s | That is the system-prompt + agents + tooling floor. Budget: findings prompt + repo reads sit *on top* of ~15 k. Confirms G3/G9 caps are necessary, not theoretical |
| **F6** | `Ripgrep is not available. Falling back to GrepTool.` | Our prompt deliberately drives repo-wide grep. On a large automotive repo the fallback grep is materially slower → **install ripgrep on the corporate machine** (see §6.5) |

---

## 3. Feature Specification

### 3.1 User-visible behaviour

**GUI (Mode 1 — file analysis):**

1. User browses a `.c`/`.h` file (existing field).
2. **NEW** field: *"Repository Root (for repo-aware Gemini review)"* + `Browse Repository` button.
   Auto-filled by walking parent directories from the browsed file until a `.git` is found; user can override.
3. **NEW** checkbox: *"Gemini CLI Deep Review (headless, repo-aware)"* — becomes the default LLM
   path; the old keystroke flow stays available behind a `Legacy VS Code automation` checkbox.
4. Run Analysis → static report as today → completion dialog gains a **`Run Gemini Review`** button.
5. Progress streams into the existing STATUS log. On success the browser opens
   `Output/validated_action_report.html`.

**CLI:**

```bash
python cpu_load_optimizer.py src/sensor.c --gemini-review --repo-root D:/repos/ecu_platform
```

```bash
python cpu_load_optimizer.py --staged . --gemini-review
```

```bash
python cpu_load_optimizer.py src/sensor.c --gemini-review --gemini-dry-run
```

### 3.2 What Gemini is asked to produce (two bounded phases, one call)

| Phase | Task | Output key | Cap |
|-------|------|-----------|-----|
| **A — Validate** | For each indexed static finding: `CONFIRMED` / `FALSE POSITIVE` / `PARTIAL` / `CONTEXT NEEDED`, with quoted evidence | `verdicts[]` (existing P0.3 contract — **unchanged**) | = number of findings |
| **B — Discover** | New CPU-load optimization opportunities in the target file, judged **in the context of the repository** (who calls it, at what rate, from which task/ISR) | `opportunities[]` (**new**) | **max 15**, ranked by estimated Δ CPU load |

Keeping Phase A's schema byte-identical means `LLMResponseParser` (`:4034`) and
`LLMValidatedReportGenerator` (`:4294`) are reused **with zero changes**.

---

## 4. Strict Guardrails (the core of this design)

| # | Guardrail | Mechanism | Why |
|---|-----------|-----------|-----|
| **G1** | **Gemini can never modify code** | `--approval-mode plan` (read-only). Belt-and-braces: run with `cwd` = the disposable workspace dir, never the repo | Corporate code integrity; no accidental edits |
| **G2** | **No `--yolo`, ever** | Hard-coded; the flag is not exposed in CLI or GUI | `yolo` auto-approves shell/write tools |
| **G3** | **Scope fence** | `.geminiignore` in the workspace excludes `.git/`, `build/`, `out/`, `*.o *.a *.elf *.hex *.map`, `third_party/`, `vendor/`, `Doc*/`, `*.pdf`, `*.xlsx` | Cuts token cost 5–20×, stops the agent wandering |
| **G4** | **Persona + hard rules pinned in context** | `GEMINI.md` written into the workspace (auto-loaded hierarchical context file) | Rules survive even if the prompt gets truncated |
| **G5** | **Evidence-or-drop** | Every verdict/opportunity must carry `file`, `line`, `quoted_code`, `evidence_kind ∈ {read_file, grep, call_site}`. The Python parser **discards any entry lacking them** | Mechanically suppresses hallucination — the single most effective accuracy guardrail |
| **G6** | **Closed output contract** | Exactly one fenced json block, schema `{"verdicts":[…], "opportunities":[…]}`; anything else is a parse failure | Deterministic machine consumption |
| **G7** | **One repair retry** | On schema failure, re-invoke once with a short `REPAIR` prompt containing the validation error + the malformed text. Never more than 2 calls total | Bounded cost, high recovery rate |
| **G8** | **Bounded discovery** | `opportunities` capped at 15; each needs `estimated_cycles_saved` + `confidence ∈ {high,medium,low}`; `confidence:"low"` entries render in a separate collapsed section | Prevents the "80 vague suggestions" failure mode |
| **G9** | **Resource limits** | `subprocess.run(timeout=…)` default 600 s; prompt hard-capped at 200 kB (truncate the findings list, never the rules); session turn limit in workspace settings; `--session-id <uuid>` per run | No hangs, no runaway loops, traceable runs |
| **G10** | **No credential handling by our tool** | We never read, write, or pass `GEMINI_API_KEY` / OAuth files. We inherit the user's already-authenticated `gemini` environment | Corporate security; nothing new to audit |
| **G11** | **Explicit egress consent** | First run per machine shows a one-time dialog: *"This sends source from `<repo>` to Google's Gemini service. Approved by your organisation?"* → stored in `Output/.gemini_review_consent`. `--gemini-yes` for CI | Source code leaves the machine — that must be a conscious act |
| **G12** | **Audit trail** | Every run writes `Output/gemini_review/run_<timestamp>/` with `prompt.md`, `GEMINI.md`, `stdout.json`, `parsed.json`, `meta.json` (version, model, session-id, exit code, duration) | Reproducibility + evidence for the safety/QA process |
| **G13** | **Fail closed** | Missing binary / auth error / timeout / non-zero exit / unparseable-after-repair → log a clear reason, keep the static HTML report, exit code unchanged | The Gemini step must never break the primary tool |
| **G14** | **Version pinning + capability probe** | `gemini --version` recorded; flags probed once from `gemini --help`, unsupported ones dropped. Pin `@google/gemini-cli@0.49.x` in the corporate image | Flag drift is real — 0.49 already removed `--all-files` |
| **G15** | **Determinism / explicit model** | **Always pass `-m` explicitly** — never inherit the machine default, which was observed to be the *preview* model `gemini-3.1-pro-preview` (F3). Temperature 0.1 in workspace settings, no `--checkpointing`, no `--resume`. The resolved model id is recorded in `meta.json` | A silently-changing preview model makes run-to-run comparison meaningless |
| **G16** | **Environment isolation** (new — from F4) | Pass an explicit `-e` / `--extensions` list (minimal or none) and `--allowed-mcp-server-names` with no entries, so corporate extensions, custom agents (`issue_investigator`), and MCP servers are **not** loaded into our run. Probe once at G0 and record what was excluded | The corporate machine injects unknown agents/tools into every session — unbounded behaviour, unbounded tokens, and a review that is not reproducible on a colleague's machine |

### 4.1 `GEMINI.md` written into the workspace (verbatim content)

```markdown
# ROLE
You are a Principal Embedded Automotive Software Performance Engineer reviewing
production ECU firmware (ARM Cortex-M / Renesas RH850 class MCU) for CPU LOAD.

# ABSOLUTE RULES — violating any of these makes your entire answer invalid
1. READ-ONLY. Never write, edit, create, delete, or move any file. Never run shell commands.
2. EVIDENCE OR SILENCE. Every claim cites a real file path + line number and quotes the
   actual code you read. If you did not read it, do not claim it.
3. NO SPECULATION. Never write "might", "could possibly", "consider maybe". If you cannot
   verify it in the repository, mark it "confidence": "low" or omit it.
4. SEMANTICS PRESERVED. Only propose changes that are behaviourally identical, including
   edge cases (overflow, negative operands, NaN, volatile/MMIO access order).
5. STAY IN SCOPE. Analyse only the TARGET FILE. The repository is context for
   understanding how the target file is used — not a second review surface.
6. OUTPUT EXACTLY ONE fenced json block matching the given schema, and nothing after it.

# WHAT "CPU LOAD" MEANS HERE
   CPU load contribution = (cycles per invocation) x (invocation rate)
An expensive function called once at init is IRRELEVANT.
A cheap function called in a 1 ms task or an ISR is CRITICAL.
Therefore: before ranking anything, USE THE REPOSITORY to determine, for each function in
the target file, WHO CALLS IT and HOW OFTEN (AUTOSAR RTE runnable? OsTask cycle time in
the Os/Rte configuration? ISR vector table? init-only?). State that call context in every entry.

# HARDWARE MODEL TO ASSUME (unless the repository proves otherwise — say so if it does)
- No hardware FPU, or single-precision-only FPU -> double maths is a software-emulated
  catastrophe; float maths is expensive; fixed-point is cheap.
- No division instruction, or multi-cycle division -> / and % by a runtime value are costly.
- Flash wait-states; small or absent I-cache -> code size in hot paths matters.
- Tight RAM -> do not propose large lookup tables without stating the RAM cost in bytes.

# OPTIMIZATION AXES TO HUNT FOR (repository-aware — this is your value over the regex engine)
- Hot-path call chains: a helper in the target file reached from a 1 ms task through N layers.
- Cross-TU inlining: a small function in a .c that callers cannot inline -> propose
  static inline in the header, and check that the header actually exists in the repo.
- const / static placement: file-scope data never written outside the TU (verify by
  grepping the repo) -> RAM to flash, enables constant folding.
- Redundant recomputation across calls: a value recomputed per invocation but invariant
  between calls of the caller — verify by reading the caller.
- float/double leaking in through a header typedef or a config macro defined elsewhere.
- Division / modulo by a value that is provably a compile-time constant in the repo config.
- Loop-invariant work whose invariance can only be proven from another file's definition.
- Struct-by-value parameters whose size is only visible in another header.
- Polling loops / busy-waits reachable from a periodic task.
- MISRA C:2012 and ISO 26262 compatibility: if a proposal weakens determinism, WCET
  predictability, or MISRA compliance, say so explicitly in "risk".

# WHAT NOT TO PROPOSE
- Compiler flags (-O3, -ffast-math), linker scripts, or build-system changes.
- Vendor pragmas without stating the portability cost.
- Micro-optimizations under ~20 cycles per invocation in code proven to be non-periodic.
- Anything that changes numerical results, including -ffast-math style reassociation.
- Style, naming, formatting, comments, or "readability" remarks.
```

### 4.2 Output schema (Phase A unchanged, Phase B new)

```json
{
  "verdicts": [
    {"finding_index": 1, "rule_id": "C02", "line": 145,
     "verdict": "CONFIRMED", "reasoning": "...",
     "revised_impact": 80,
     "evidence_kind": "read_file", "quoted_code": "speed = raw / 8;"}
  ],
  "opportunities": [
    {"id": "G01",
     "title": "Sensor_Normalize() recomputes the calibration scale every 1 ms",
     "file": "src/sensor.c", "line": 212,
     "quoted_code": "float k = (float)cal.gain / (float)cal.range;",
     "call_context": "Sensor_Normalize <- Sensor_MainFunction <- OsTask_1ms (Os/os_cfg.c:88)",
     "evidence_kind": "call_site",
     "why_expensive": "two int->float conversions plus one float divide per 1 ms invocation",
     "estimated_cycles_saved": 60,
     "estimated_invocation_rate_hz": 1000,
     "proposed_change": "hoist to a static float computed once in Sensor_Init()",
     "risk": "cal must not change at runtime — verified: written only in Sensor_Init (src/sensor.c:64)",
     "misra_iso26262_note": "no impact; removes a runtime divide, improves WCET",
     "confidence": "high"}
  ]
}
```

**The parser drops any entry that:** lacks `file` / `line` / `quoted_code` / `evidence_kind`;
has a `line` outside the target file's length; or has `quoted_code` that does not appear in
the target file (whitespace-normalised compare). **This is a cheap, brutal, extremely
effective anti-hallucination check — about 10 lines of Python.**

---

## 5. Exact Invocation

```python
cmd = [
    gemini_exe,                        # shutil.which("gemini.cmd") or "gemini.exe" or "gemini"
    "-p", "",                          # headless; the real prompt arrives on stdin
    "-m", model,                       # ALWAYS explicit (G15). Machine default was
                                       # observed to be gemini-3.1-pro-preview (F3)
    "-o", "json",                      # structured envelope
    "--approval-mode", "plan",         # READ-ONLY  (G1)
    "--include-directories", repo_root,  # the repository context
    "--session-id", session_uuid,      # traceability (G12)
    "--skip-trust",                    # avoid the interactive workspace-trust prompt
    # --- G16 environment isolation (F4): keep corporate extensions,
    #     custom agents and MCP servers out of the run. Exact spelling of
    #     the "none" case is settled by the G0 probe (see §6.5).
    "--allowed-mcp-server-names",      # (with no values / explicit empty set)
]
proc = subprocess.run(
    cmd, input=prompt_text, capture_output=True, text=True,
    encoding="utf-8", errors="replace",
    cwd=workspace_dir,                 # NOT the repo (G1)
    timeout=timeout_s,                 # (G9)
    env=os.environ.copy(),             # inherit existing auth (G10)
)
```

> **Windows note:** resolve `gemini.cmd` **before** bare `gemini` — the exact same
> `PATHEXT` trap already fixed for `code.cmd` in commit `fa0ccc6`
> (`cpu_load_optimizer.py:6367`). Reuse that pattern verbatim.

**Workspace layout (disposable, one per run):**

```
Output/gemini_review/run_2026-08-19_143210/
├── GEMINI.md              <- §4.1 persona + hard rules (auto-loaded context)
├── .geminiignore          <- G3 scope fence
├── .gemini/settings.json  <- temperature 0.1, turn limit
├── prompt.md              <- the exact stdin payload      (audit)
├── stdout.json            <- raw CLI output               (audit)
├── parsed.json            <- post-schema-validation       (audit)
└── meta.json              <- version/model/exit/duration  (audit)
```

---

## 6. Implementation Breakdown

All code lands in `cpu_load_optimizer.py`. **No new pip dependency** — `subprocess`,
`json`, `uuid`, `shutil`, `pathlib` are stdlib and mostly already imported.

| Step | Component | Location | New LOC | Risk |
|------|-----------|----------|---------|------|
| **G0** | `GeminiCLIRunner.probe()` — locate exe (`.cmd` first), `--version`, parse `--help` for supported flags, cheap auth preflight | new class after `GitAnalyzer` (`:5198`) | ~70 | Low |
| **G1** | `GeminiCLIRunner.build_workspace()` — write `GEMINI.md`, `.geminiignore`, `.gemini/settings.json` | same class | ~80 | Low |
| **G2** | `GeminiReviewPrompt.build()` — Phase A+B prompt, embeds `findings_for_review.md`, schema, caps | next to `LLMValidationExport` (`:3103`) | ~160 (mostly text) | Low |
| **G3** | `GeminiCLIRunner.run()` + `_extract_json()` + one repair retry | same class | ~120 | **Medium** — envelope shape (see §6.4) |
| **G4** | `_validate_entries()` (evidence-or-drop, G5) + `opportunities` section in `LLMValidatedReportGenerator` | `:4294` | ~110 | Low |
| **G5** | CLI flags `--gemini-review --repo-root --gemini-model --gemini-timeout --gemini-dry-run --gemini-yes` | `main()` (`:6668`) | ~40 | Low |
| **G6** | GUI: `self.repo_root` StringVar + entry + Browse button + auto-infer from `.git`; `self.gemini_review` checkbox; `Run Gemini Review` button in `_show_completion_dialog` (`:6152`); wiring in `_execute_analysis` (`:6009`) | `launch_gui()` | ~90 | Low |
| **G7** | `tests/test_gemini_cli.py` — all subprocess mocked, zero network | new file | ~180 | Low |
| | **Total** | | **≈ 850 LOC**, ~600 of it prompt/HTML text | |

### 6.1 Why this is genuinely easy

- The hard half already exists: findings cache, JSON verdict contract, verdict parser,
  validated-report generator, `--apply-validation` CLI. We change only the **transport**.
- `subprocess.run()` with a timeout is ~15 lines. It replaces ~300 lines of `pyautogui`
  sleep-and-pray — **this feature is net-negative complexity for the codebase.**
- Every guardrail is either a CLI flag, a text file, or a 10-line Python check.
- No new threads beyond the one the GUI already uses; no packaging change; still one file.

### 6.2 Suggested execution order (4 sittings)

1. ~~**Sitting 1:** Action item 0 auth probe.~~ **DONE — passed (§2.1).** Remaining before
   Sitting 2: the two 5-minute probes in §6.5 (extension isolation, install ripgrep).
2. **Sitting 2 (2 h):** G0 + G1 + G2 + `--gemini-dry-run`. Deliverable: workspace and prompt
   are generated and reviewable **without calling the model**. Fully testable offline.
3. **Sitting 3 (2 h):** G3 + G4 — first real end-to-end run on `bad_example.c` with this
   repository as the repo root.
4. **Sitting 4 (2 h):** G5 + G6 + G7 — CLI/GUI wiring and mocked tests.

### 6.3 Test plan (all offline, subprocess mocked)

| Test | Asserts |
|------|---------|
| `test_probe_prefers_cmd_on_windows` | `gemini.cmd` wins over `gemini` (the `fa0ccc6` trap) |
| `test_workspace_files_written` | `GEMINI.md`, `.geminiignore`, `settings.json` exist with expected content |
| `test_cmd_never_contains_yolo` | `--yolo` absent, `--approval-mode plan` present (G1/G2) |
| `test_cwd_is_workspace_not_repo` | `cwd != repo_root` (G1) |
| `test_prompt_contains_all_findings_indexed` | every finding index 1..N appears |
| `test_prompt_truncates_at_cap` | 500 findings → prompt ≤ 200 kB, rules block intact (G9) |
| `test_parse_valid_envelope` | `{"session_id","response","stats"}` → verdicts + opportunities extracted |
| `test_stdout_with_warning_preamble_parses` | **the real observed stdout** (3 warning lines then the object) parses correctly (F2/R11) |
| `test_trailing_text_after_envelope_parses` | `raw_decode` tolerates text after the closing brace |
| `test_zero_tool_calls_rejects_run` | `stats.tools.totalCalls == 0` → run rejected as ungrounded (R12) |
| `test_model_id_always_explicit` | `-m` is always in `cmd`; resolved id captured from `stats.models` (G15) |
| `test_isolation_flags_present` | extension/MCP isolation flags present in `cmd` (G16) |
| `test_hallucinated_quote_dropped` | `quoted_code` absent from source → entry discarded (G5) |
| `test_line_out_of_range_dropped` | line > file length → discarded (G5) |
| `test_missing_evidence_kind_dropped` | (G5) |
| `test_opportunities_capped_at_15` | (G8) |
| `test_repair_retry_once_then_gives_up` | at most 2 subprocess calls (G7) |
| `test_timeout_falls_back_cleanly` | `TimeoutExpired` → static report intact, exit code unchanged (G13) |
| `test_auth_error_message_is_actionable` | `IneligibleTierError` in stderr → human-readable licensing hint |
| `test_end_to_end_mocked` | mocked envelope → `validated_action_report.html` with an Opportunities section |

### 6.4 Output parsing — CONFIRMED, and the trap that would have broken it

The envelope is now known (F1). But **stdout is not pure JSON** (F2) — the CLI prepends
warnings before the object:

```
The 'metricReader' option is deprecated. Please use 'metricReaders' instead.
Duplicate agent name 'issue_investigator' detected. The later definition will be ignored.
Ripgrep is not available. Falling back to GrepTool.
{
  "session_id": "a7cd8ce4-…",
  "response": "PONG",
  "stats": { "models": { "gemini-3.1-pro-preview": { "tokens": {...} } }, "tools": {...} }
}
```

`json.loads(proc.stdout)` **raises** on this. The parser is therefore a strict two-stage lift:

```python
def _extract_envelope(stdout: str) -> dict:
    """Stage 1: lift the CLI envelope out of noise-prefixed stdout."""
    dec = json.JSONDecoder()
    for idx, ch in enumerate(stdout):
        if ch != '{':
            continue
        try:
            obj, _ = dec.raw_decode(stdout[idx:])   # tolerates trailing text too
        except ValueError:
            continue
        if isinstance(obj, dict) and 'response' in obj:
            return obj
    raise GeminiOutputError('no JSON envelope in stdout')

def _extract_contract(envelope: dict) -> dict:
    """Stage 2: lift OUR {"verdicts":…, "opportunities":…} out of the model text."""
    text = envelope.get('response', '')
    # fenced ```json block first, then any balanced {...} containing "verdicts"
    ...
```

Two notes that matter:

- Scanning for `{` and using `raw_decode` is robust whether the warnings land on stdout or
  stderr, and whether or not more text follows the object. Do **not** "fix" this by
  stripping the three known warning strings — the set of warnings is machine-dependent.
- `envelope["stats"]` is free telemetry. Log `tokens.total`, `tools.byName`, and
  `totalLatencyMs` into `meta.json` (G12). `tools.byName` is a genuinely useful
  guardrail signal: **if `totalCalls == 0`, Gemini never opened a single file** — the
  "review" was pure hallucination and the run must be rejected outright.

### 6.5 Two 5-minute probes to run before Sitting 2

1. **Isolation spelling (G16/F4).** Confirm how this CLI build expresses "no extensions":

```bash
gemini -e none -p "" --approval-mode plan -o json --allowed-mcp-server-names
```

   Compare the `stats` token count and the warning lines against the baseline 15,356. If the
   `Duplicate agent name 'issue_investigator'` warning disappears and prompt tokens drop, the
   isolation works. If `-e` rejects an empty/none value, fall back to a workspace-local
   `.gemini/settings.json` that disables extensions, and record the outcome in the plan.

2. **Get `rg` where the Gemini CLI itself will trust it (F6).**
   `Ripgrep is not available. Falling back to GrepTool.` Our prompt deliberately drives
   repo-wide symbol search; on a large automotive repo the fallback grep is materially
   slower and eats the G9 timeout.

   **Root cause is deeper than "not on PATH", and it was confirmed by reading the CLI's own
   bundled source** (`resolveRipgrepPath()` / `isTrustedSystemPath()` in
   `@google/gemini-cli/bundle/chunk-*.js`). The resolver:
   1. First checks a few fixed paths **next to its own install** (`<bundle>/rg-win32-x64.exe`,
      `<bundle>/vendor/ripgrep/rg-win32-x64.exe`) — accepted unconditionally, no PATH involved.
   2. Only if none of those exist does it fall back to a PATH lookup — **and even then it
      discards the result unless the resolved real path sits under one of three whitelisted
      prefixes: `C:\Windows`, `C:\Program Files`, or `C:\Program Files (x86)`.**

   Consequence, **confirmed on the corporate machine**: `rg --version` succeeded (v15.2.0,
   found on PATH) yet Gemini still printed the fallback warning — because a per-user winget
   install does not resolve under any of those three prefixes. `rg` being callable from the
   shell is not sufficient; Gemini enforces its own whitelist independent of the shell PATH.

   **Two fixes, in order of preference:**

   **(a) No admin required — vendor the binary directly into the CLI's own bundle**
   (candidate path 1/2 above, which is accepted with no trust check at all):

   ```powershell
   $rg = (Get-Command rg -ErrorAction Stop).Source
   $bundleDir = Join-Path (npm root -g).Trim() "@google\gemini-cli\bundle"
   $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "ia32" }
   $binName = "rg-win32-$arch.exe"
   Copy-Item $rg -Destination (Join-Path $bundleDir $binName) -Force
   $vendorDir = Join-Path $bundleDir "vendor\ripgrep"
   New-Item -ItemType Directory -Force -Path $vendorDir | Out-Null
   Copy-Item $rg -Destination (Join-Path $vendorDir $binName) -Force
   ```

   **Must be re-run after every `npm update -g @google/gemini-cli`** — an update recreates
   the `bundle` directory and wipes the vendored copy. Fold this into whatever installs/pins
   the CLI on the corporate image (G14).

   **(b) Requires admin/elevation — install ripgrep under a trusted prefix directly:**
   `winget install BurntSushi.ripgrep.MSVC --scope machine` (installs under
   `C:\Program Files`, satisfying `isTrustedSystemPath` with no re-vendoring needed after
   CLI updates). Only usable where elevation is actually available; prefer (a) otherwise.

   Then re-run the baseline probe and confirm the `Ripgrep is not available` line is gone
   from stdout.

---

## 7. Alternatives Considered (and why rejected)

| Option | Verdict |
|--------|---------|
| Keep `pyautogui` + VS Code | **No** — already the most fragile part of the tool (P2.5); no repo context; not CI-able |
| `google-generativeai` Python SDK direct | **No** — needs an API key on a corporate machine (policy risk) and we would have to build our own file-reading/grep agent loop. Gemini CLI already *is* that agent, and reuses the corporate Code Assist licence |
| Package the prompt as a **Gemini skill** (`gemini skills link <path>`) | **Deferred** — `gemini skills` exists in 0.49.0 and would be elegant, but needs an install step on every machine and adds a version-coupled dependency. `GEMINI.md` + stdin prompt achieves the same steering with **zero installation**. Revisit once the feature is proven |
| MCP server exposing the findings | **No** — over-engineered for a one-shot review |

---

## 8. Risk Register

| # | Risk | Likelihood | Mitigation |
|---|------|-----------|------------|
| R1 | ~~Auth tier ineligible~~ | **CLEARED** | Action item 0 passed on the corporate machine (§2.1). Still applies to personal machines — keep the actionable error text and document the licence requirement in the README |
| R9 | **Corporate extensions / custom agents injected into the run** (F4) | **Confirmed present** | G16 isolation flags + §6.5 probe 1; record what was excluded in `meta.json` |
| R10 | **Silent model drift** — machine default is a `-preview` model (F3) | **Confirmed present** | G15: always pass `-m`; record the resolved model id from `stats.models` |
| R11 | **Noise-prefixed stdout breaks naive JSON parsing** (F2) | **Confirmed present** | §6.4 `raw_decode` scan; `test_stdout_with_warning_preamble_parses` |
| R12 | Gemini answers without reading any file | Medium | Reject the run when `stats.tools.totalCalls == 0` (§6.4) — a hallucination detector the CLI hands us for free |
| R2 | Corporate policy forbids sending source to Google | Medium | G11 consent gate + G12 audit trail; feature is strictly opt-in and off by default |
| R3 | CLI flag drift between versions | Medium | G14 probe + drop-unsupported; pin `0.49.x` in the corporate image |
| R4 | Large repo blows the context window | Medium | G3 `.geminiignore`; the prompt directs targeted grep rather than whole-repo reads; repo is *context*, not review surface (G4 rule 5) |
| R5 | Model hallucinates plausible-looking findings | Medium | **G5 evidence-or-drop with quote-in-source verification** — mechanical, not prompt-dependent |
| R6 | Corporate proxy blocks the CLI | Low | Preflight reports a network error distinctly from an auth error |
| R7 | Long runtime blocks the GUI | Low | Run in the existing worker thread; timeout G9; live status log |
| R8 | Cost / quota consumption | Low | One call per run (two worst case); `--gemini-dry-run` iterates the prompt at zero cost |

---

## 9. Definition of Done

- [x] **Action item 0 returns `PONG` on the corporate machine; envelope shape recorded (§2.1)**
- [ ] §6.5 probes done: extension isolation spelling settled, ripgrep installed
- [ ] A run whose `stats.tools.totalCalls == 0` is rejected rather than reported
- [ ] `--gemini-review --repo-root <r>` on `bad_example.c` produces `validated_action_report.html` with both verdicts and at least one repo-grounded opportunity naming a real caller
- [ ] `--gemini-dry-run` produces a reviewable prompt + workspace with **zero** network traffic
- [ ] `--yolo` appears nowhere; `--approval-mode plan` always present; `git status` in the repo is clean after a run (G1 proven, not assumed)
- [ ] A deliberately hallucinated quote in a mocked response is dropped by the parser
- [ ] Killing the `gemini` process mid-run leaves the static HTML report intact and the exit code unchanged
- [ ] `tests/test_gemini_cli.py` green; full suite still 330 pass / 2 known env failures
- [ ] `README.md` gains a "Gemini CLI Deep Review" section including the licence requirement
- [ ] Roadmap item **P2.5 marked done** in `cpu_load_optimizer_improvement_plan.md`

---

## 10. Not In Scope

- Fixing the 16 issues in `corner_case_audit_2026-07.md` (separate, higher-priority work —
  Gemini reviewing a buggy rule set only confirms the bugs faster)
- Auto-applying Gemini's proposed changes to source (deliberately excluded — G1)
- Phase 2/3 roadmap items other than P2.5
