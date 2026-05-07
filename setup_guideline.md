# Setup Guideline — CPU Load Optimizer

This document lists every step required to install and run
`cpu_load_optimizer.py` on a fresh Windows machine, including the
dependencies needed for the **Automated LLM Verification** feature
(VS Code + Gemini Code Assist).

Follow the sections in order. Steps marked *(optional)* are only
required for specific features — you can skip them if you don't
need that feature.

---

## 1. Prerequisites

| Requirement         | Version           | Notes                                              |
|---------------------|-------------------|----------------------------------------------------|
| Python              | 3.9 or newer      | 3.11 / 3.12 / 3.13 all tested. Use 64-bit.         |
| Windows             | 10 / 11           | GUI automation targets Windows key bindings.       |
| VS Code *(optional)*| Latest stable     | Only for Automated LLM Verification.               |
| Git *(optional)*    | Any recent        | Only for Staged-Changes analysis mode.             |

`tkinter` ships with the standard Python installer on Windows — no
extra step is needed.

---

## 2. Install Python

1. Download Python from <https://www.python.org/downloads/windows/>.
2. During install, **tick "Add python.exe to PATH"**.
3. Verify:
   ```powershell
   python --version
   pip --version
   ```

---

## 3. Get the project files

Either clone with Git:
```powershell
git clone <repo-url> CPU_load_optimizer_C
cd CPU_load_optimizer_C
```
…or download and extract the ZIP so you end up with a folder
containing at minimum:

```
CPU_load_optimizer_C\
├── cpu_load_optimizer.py
├── bad_example.c              (sample input)
└── setup_guideline.md         (this file)
```

---

## 4. Install Python package dependencies

Open PowerShell / CMD in the project folder and run:

```powershell
pip install pyautogui pyperclip pygetwindow Pillow
```

What each package is for:

| Package         | Required for                                           |
|-----------------|--------------------------------------------------------|
| `pyautogui`     | **Automated LLM** — simulates keystrokes in VS Code.   |
| `pyperclip`     | **Automated LLM** — puts the prompt on the clipboard.  |
| `pygetwindow`   | **Automated LLM** — re-activates the VS Code window.   |
| `Pillow` (PIL)  | *(optional)* Code-annotation screenshots (`--annotate`). |

If you only plan to generate HTML reports (no automated LLM flow),
only `Pillow` is optionally useful. The tool itself will run without
any of these — it will just disable the features that require them.

---

## 5. Install VS Code and Gemini Code Assist *(optional, for Automated LLM)*

Skip this section if you don't plan to use the **Automated LLM
Verification** option in the GUI.

### 5.1 Install VS Code
- Download: <https://code.visualstudio.com/>
- Run the installer with defaults. In the optional tasks, keep:
  - *"Add to PATH"*
  - *"Register Code as an editor for supported file types"*

### 5.2 Make sure the `code` command is on PATH
Open PowerShell / CMD and run:
```powershell
code --version
```
If this errors with *"not recognized"*:
1. Open VS Code
2. `Ctrl+Shift+P` → **Shell Command: Install 'code' command in PATH**
3. Close and reopen your terminal, retry `code --version`.

### 5.3 Install the Gemini Code Assist extension
1. Open VS Code → Extensions (`Ctrl+Shift+X`)
2. Search for **Gemini Code Assist** (publisher: Google)
3. Click **Install**
4. Sign in with your Google account when prompted (follow the
   extension's in-editor sign-in flow)
5. Verify the extension works: `Ctrl+Shift+P` →
   `Gemini Code Assist: Open Chat` — the chat panel should appear.

### 5.4 Confirm command names
The Automated LLM flow issues these commands via the palette:
- `Gemini: Add to Context`
- `Gemini Code Assist: Open Chat`

If your installed version of the extension uses different strings,
update them in `cpu_load_optimizer.py` inside
`_run_automated_llm_verification` (search for those literals).

---

## 6. Install Git *(optional, for Staged-Changes mode)*

Skip if you only analyze single files / folders.

- Download: <https://git-scm.com/download/win>
- Install with defaults.
- Verify:
  ```powershell
  git --version
  ```

---

## 7. Run the tool

### Launch the GUI (recommended)
```powershell
python cpu_load_optimizer.py
```
or
```powershell
python cpu_load_optimizer.py --gui
```

In the GUI:
1. Pick **Analyze File(s)** or **Analyze Staged Git Changes**
2. Browse for the target file / folder / repository
3. Confirm settings:
   - **Generate LLM Validation Export** → produces the files in
     `Output/llm_validation/` (needed for Automated LLM).
   - **Automated LLM Verification** → enables the automated VS Code
     + Gemini Code Assist step offered after analysis.
4. Click **Run Analysis**
5. In the completion dialog, choose:
   - **Open HTML Report** — just view the report in your browser.
   - **Run Automated LLM** — opens the HTML report, then launches
     VS Code with the selected file and pushes the validation
     prompt into the Gemini Code Assist chat automatically.

### CLI mode
```powershell
# Analyze a single file
python cpu_load_optimizer.py bad_example.c --llm-export

# Analyze a folder
python cpu_load_optimizer.py path\to\src --llm-export

# Analyze staged git changes
python cpu_load_optimizer.py --staged path\to\repo --llm-export

# Custom output path / minimum severity
python cpu_load_optimizer.py bad_example.c -o report.html -s medium
```

---

## 8. Outputs

All generated files land under `Output/` (created on first run).

```
Output/
├── cpu_load_report.html                 ← main HTML report (file mode)
├── cpu_load_staged_report.html          ← main HTML report (staged mode)
└── llm_validation/                      ← only when --llm-export / GUI checkbox
    ├── findings_for_review.md           ← compact findings list
    ├── validation_prompt.md             ← generic manual-LLM prompt
    ├── report_template.html             ← CSS shell for LLM-generated HTML
    ├── HOW_TO_VALIDATE.md               ← manual-workflow instructions
    ├── automated_llm_prompt.md          ← self-contained prompt used by
    │                                       the Automated LLM feature
    └── findings_cache.json              ← machine-readable findings dump
```

---

## 9. Troubleshooting

### Automated LLM pastes into the editor instead of the Gemini chat
- Make sure the Gemini Code Assist extension is installed **and
  signed in**.
- Confirm the palette command `Gemini Code Assist: Open Chat` works
  manually.
- Increase the sleep after step *[5/6] Opening Gemini chat* in
  `_run_automated_llm_verification` if your machine is slower.

### `code` command not found
Run VS Code → `Ctrl+Shift+P` → **Shell Command: Install 'code'
command in PATH**, then reopen your terminal.

### `pyautogui.FailSafeException`
You moved the mouse to a screen corner during automation — that's
pyautogui's fail-safe. Just rerun; don't move the mouse during the
automated run.

### `UnicodeEncodeError` in CLI output
If running from `cmd.exe` you may hit `cp1252` encoding errors
printing arrow characters. Launch with:
```powershell
$env:PYTHONIOENCODING="utf-8"; python cpu_load_optimizer.py ...
```
or use PowerShell / Windows Terminal, which default to UTF-8.

### Tool "No staged .c/.h files found"
Stage your changes first:
```powershell
git add path\to\file.c
```
then rerun.

---

## 10. Minimal setup checklist

If you just want the fastest path to running the Automated LLM flow:

```powershell
# 1. Python + pip on PATH
python --version

# 2. Install Python deps
pip install pyautogui pyperclip pygetwindow Pillow

# 3. VS Code + 'code' on PATH
code --version

# 4. Install Gemini Code Assist extension in VS Code and sign in

# 5. Run the tool
python cpu_load_optimizer.py
```

Once the GUI opens:
- Browse → pick a `.c` file
- Keep both **Generate LLM Validation Export** and **Automated LLM
  Verification** checked
- Click **Run Analysis**
- In the completion popup, click **Run Automated LLM**

The tool will open the HTML report, then launch VS Code with the
selected file, add it to Gemini's context, open the chat, paste the
validation prompt, and submit — no further interaction required.
