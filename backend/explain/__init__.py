"""Explain mode: a plain-English page for every detection rule.

Each rule in backend/rules/ has a file of the same name in this folder. The
rule file is for the engine. The file here is for a person who is learning.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

EXPLAIN_DIR = Path(__file__).parent


class _Strict(BaseModel):
    # A misspelt or missing heading in a file is an error, not a blank page.
    model_config = ConfigDict(extra="forbid")


class SecurityPlus(_Strict):
    topic: str  # the Security+ exam topic the rule connects to
    text: str


class Explanation(_Strict):
    attack: str  # what the attack is
    log_shows: str  # what the log shows
    why: str  # why the rule catches it
    security_plus: SecurityPlus


def load_explanations(rule_names: set[str], folder: Path = EXPLAIN_DIR) -> dict[str, Explanation]:
    """Load every explanation, keyed by rule name.

    Like the rules, these are checked when the app starts: a rule with no
    explanation (or an explanation with no rule) stops it there.
    """
    explanations = {}
    for path in sorted(folder.glob("*.yml")):
        try:
            explanations[path.stem] = Explanation(**yaml.safe_load(path.read_text(encoding="utf-8")))
        except Exception as problem:
            raise ValueError(f"Explanation file {path.name} is not valid: {problem!r}") from problem
    if set(explanations) != rule_names:
        unmatched = sorted(set(explanations) ^ rule_names)
        raise ValueError(f"Every rule needs one explanation file with the same name. Unmatched: {unmatched}")
    return explanations
