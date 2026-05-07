"""Shared pytest fixtures for cpu_load_optimizer tests."""
import os
import sys
import shutil
import tempfile
from pathlib import Path

import pytest

# Make the parent directory importable so tests can do
# `from cpu_load_optimizer import ...` without installing.
sys.path.insert(0, str(Path(__file__).parent.parent))

from cpu_load_optimizer import (
    Finding,
    RulesEngine,
    Severity,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def write_c(directory: str, filename: str, content: str) -> str:
    """Write *content* to *filename* inside *directory* and return the path."""
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def rule_ids(findings) -> set:
    """Return the set of rule IDs present in *findings*."""
    return {f.rule_id for f in findings}


def make_finding(
    rule_id="C01",
    line_number=5,
    severity=Severity.CRITICAL,
    impact_score=80,
) -> Finding:
    """Build a minimal Finding object for parser / report tests."""
    return Finding(
        rule_id=rule_id,
        rule_name="Test Rule",
        severity=severity,
        category="Test",
        file_path="test.c",
        line_number=line_number,
        code_snippet="float x = 5;",
        matched_text="float x = 5;",
        description="desc",
        recommendation="rec",
        suggested_fix="fix",
        evidence="ev",
        impact_score=impact_score,
    )


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def engine() -> RulesEngine:
    return RulesEngine()


@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)
