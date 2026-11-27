"""AI triage: get a suggestion for one alert.

There are two ways to get one:

  demo mode  A stored answer from demo_responses.json. Instant, free, and
             the API is never contacted. Used when there is no API key, and
             on the public site.
  live mode  Claude is asked through the Anthropic API. This needs a key in
             the ANTHROPIC_API_KEY environment variable.

Either way the result is only a suggestion for the analyst. If the AI cannot
be reached, declines, or answers badly, Unavailable is raised and the alert
page shows the rule's own explanation instead. The app never depends on AI.
"""

import json
import logging
import os
from pathlib import Path

import anthropic

from backend.ai import guard
from backend.engine.detection import Rule
from backend.models import Alert, Log, Suggestion, Triage

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-opus-5-5"  # SENTINEL_MODEL in the environment overrides it
DEMO_FILE = Path(__file__).parent / "demo_responses.json"

# The format Claude must answer in, as a JSON schema. It is generated from
# the Suggestion class, so the two can never disagree.
ANSWER_SCHEMA = anthropic.transform_schema(Suggestion)

# If Claude's safety filters decline a request, the API can retry it on
# another Claude model before giving up. Security logs can look alarming, so
# this is worth having. The feature is in beta; this name switches it on.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class Unavailable(Exception):
    """No suggestion could be made. The message is written for the analyst
    and is safe to show: it never contains the API key."""


def demo_mode() -> bool:
    """Demo mode is on when asked for (SENTINEL_DEMO=1) or when there is no
    API key. In demo mode the API is never contacted."""
    return os.environ.get("SENTINEL_DEMO") == "1" or not os.environ.get("ANTHROPIC_API_KEY")


def load_demo_answers(rule_names: set[str], path: Path = DEMO_FILE) -> dict[str, Suggestion]:
    """Load the stored answers, keyed by rule name.

    Like the rules, these are checked when the app starts: a rule with no
    stored answer, or an answer in the wrong shape, stops it there.
    """
    stored = json.loads(path.read_text(encoding="utf-8"))["answers"]
    answers = {name: Suggestion.model_validate(answer) for name, answer in stored.items()}
    if set(answers) != rule_names:
        unmatched = sorted(set(answers) ^ rule_names)
        raise ValueError(f"Every rule needs one demo answer in {path.name}. Unmatched: {unmatched}")
    return answers


def suggest(alert: Alert, rule: Rule | None, logs: list[Log], demo_answers: dict[str, Suggestion]) -> Triage:
    """Return a triage for the alert, not yet saved. Raises Unavailable."""
    if rule is None:
        raise Unavailable("The rule that raised this alert is no longer installed, so it cannot be triaged.")
    if demo_mode():
        suggestion, source, model = _demo_answer(alert, demo_answers[rule.name]), "demo", None
    else:
        (suggestion, model), source = ask_claude(rule, logs), "live"
    return Triage(alert_id=alert.id, **suggestion.model_dump(), source=source, model=model)


def _demo_answer(alert: Alert, stored: Suggestion) -> Suggestion:
    """A stored answer with the alert's own host and user written in."""
    def fill(text: str) -> str:
        return text.replace("{host}", alert.host).replace("{user}", alert.user)

    return stored.model_copy(update={
        "summary": fill(stored.summary),
        "severity_reason": fill(stored.severity_reason),
        "next_steps": [fill(step) for step in stored.next_steps],
    })


def ask_claude(rule: Rule, logs: list[Log]) -> tuple[Suggestion, str]:
    """Send one alert to Claude. Returns its suggestion and the name of the
    model that wrote it. Raises Unavailable if anything goes wrong."""
    try:
        # The client reads the key from ANTHROPIC_API_KEY by itself, so the
        # key never appears in Sentinel's code. A short timeout and a single
        # retry stop the alert page waiting for minutes.
        client = anthropic.Anthropic(timeout=20.0, max_retries=1)
        response = client.beta.messages.create(
            model=os.environ.get("SENTINEL_MODEL") or DEFAULT_MODEL,
            # The most Claude may write, thinking included. It caps what one
            # request can cost, whatever the logs try to make it say.
            max_tokens=4096,
            # Instructions and data travel separately: see guard.py.
            system=guard.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": guard.build_prompt(rule, logs)}],
            output_config={
                # How hard Claude thinks before answering. "low" keeps the
                # answer under ten seconds. Raise it to "medium" if the
                # suggestions read as shallow.
                "effort": "low",
                # Structured output: the answer must be JSON in this shape.
                "format": {"type": "json_schema", "schema": ANSWER_SCHEMA},
            },
            betas=[FALLBACK_BETA],
            fallbacks="default",
        )
    except anthropic.AuthenticationError:
        raise Unavailable("The API key was not accepted. Check ANTHROPIC_API_KEY in the .env file.")
    except anthropic.APIStatusError as problem:  # the API answered, with an error
        logger.warning("AI triage: the API answered with status %s", problem.status_code)
        raise Unavailable(
            f"The AI service answered with an error (status {problem.status_code}). {_api_message(problem)}".strip()
        )
    except anthropic.APIConnectionError:  # no answer at all; includes timeouts
        raise Unavailable("The AI service could not be reached in time. Check the internet connection.")
    except anthropic.AnthropicError as problem:
        logger.warning("AI triage: %s", type(problem).__name__)
        raise Unavailable("The AI service could not be used.")

    # Why Claude stopped comes before what it wrote. A refusal has no answer
    # in it at all, and an answer cut off at the token limit is half a JSON.
    if response.stop_reason == "refusal":
        raise Unavailable("The AI declined to assess this alert.")
    if response.stop_reason != "end_turn":
        raise Unavailable("The AI's answer was cut short.")
    text = next((block.text for block in response.content if block.type == "text"), "")
    try:
        return Suggestion.model_validate_json(text), response.model
    except ValueError:
        raise Unavailable("The AI's answer was not in the expected format.")


def _api_message(problem: anthropic.APIStatusError) -> str:
    """The API's own one-line reason, e.g. that the account has no credit left."""
    body = problem.body if isinstance(problem.body, dict) else {}
    error = body.get("error")
    return str(error.get("message", ""))[:300] if isinstance(error, dict) else ""
