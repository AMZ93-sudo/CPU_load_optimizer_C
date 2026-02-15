# How to Validate Findings with Gemini 3 Pro

## Step-by-Step Process

### Step 1: Open Gemini 3 Pro
Go to your company-approved Gemini web interface.

### Step 2: Upload Files (in this order)

**Upload 1 — The source code file(s):**
   - `bad_example.c`
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
