"""AI triage: get a suggestion for one alert, or a summary of one incident.

There are two ways to get either:

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
from sqlmodel import SQLModel

from backend.ai import guard
from backend.engine.detection import Rule
from backend.models import (
    Alert,
    IncidentInfo,
    IncidentSuggestion,
    IncidentSummary,
    Log,
    Suggestion,
    Triage,
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-opus-5-5"  # SENTINEL_MODEL in the environment overrides it
DEMO_FILE = Path(__file__).parent / "demo_responses.json"

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


def load_demo_summaries(rule_names: set[str], path: Path = DEMO_FILE) -> dict[frozenset[str], IncidentSuggestion]:
    """Load the stored incident summaries.

    An incident has no single rule to file its answer under, so each stored
    summary is filed under the set of rules whose alerts it describes: one
    set for each scenario the simulator can run. Checked at startup too.
    """
    summaries = {}
    for entry in json.loads(path.read_text(encoding="utf-8"))["incidents"]:
        rules = frozenset(entry["rules"])
        if not rules or not rules <= rule_names:
            raise ValueError(f"A demo incident summary in {path.name} names unknown rules: {sorted(rules - rule_names)}")
        summaries[rules] = IncidentSuggestion.model_validate(entry["answer"])
    return summaries


def suggest(alert: Alert, rule: Rule | None, logs: list[Log], demo_answers: dict[str, Suggestion]) -> Triage:
    """Return a triage for the alert, not yet saved. Raises Unavailable."""
    if rule is None:
        raise Unavailable("The rule that raised this alert is no longer installed, so it cannot be triaged.")
    if demo_mode():
        suggestion, source, model = _fill(demo_answers[rule.name], alert.host, alert.user), "demo", None
    else:
        answer = ask_claude(guard.SYSTEM_PROMPT, guard.build_prompt(rule, logs), Suggestion)
        (suggestion, model), source = answer, "live"
    return Triage(alert_id=alert.id, **suggestion.model_dump(), source=source, model=model)


def summarise(
    incident: IncidentInfo,
    alerts: list[Alert],
    rules: dict[str, Rule],
    logs: dict[int, Log],
    demo_summaries: dict[frozenset[str], IncidentSuggestion],
) -> IncidentSummary:
    """Return a summary of the incident, not yet saved. Raises Unavailable.

    `alerts` are the incident's own, oldest first. `rules` are by name and
    `logs` (the alerts' evidence) by log id.
    """
    if demo_mode():
        stored = demo_summaries.get(frozenset(alert.rule_id for alert in alerts))
        if stored is None:
            raise Unavailable(
                "Demo mode has a stored summary for each scenario, and this incident's mix of alerts "
                "matches none of them. Live mode would write one."
            )
        # Several hosts or users are written as "A and B".
        suggestion = _fill(stored, " and ".join(incident.hosts), " and ".join(incident.users))
        source, model = "demo", None
    else:
        prompt = guard.build_incident_prompt(alerts, rules, logs)
        # A whole incident is more to read and more to write than one alert,
        # so it is given longer to answer.
        answer = ask_claude(guard.INCIDENT_SYSTEM_PROMPT, prompt, IncidentSuggestion, timeout=45.0)
        (suggestion, model), source = answer, "live"
    return IncidentSummary(incident_id=incident.id, **suggestion.model_dump(), source=source, model=model)


def _fill(stored: SQLModel, host: str, user: str) -> SQLModel:
    """A stored demo answer with the real host and user written in."""
    def fill(value):
        if isinstance(value, list):
            return [fill(item) for item in value]
        return value.replace("{host}", host).replace("{user}", user)

    return stored.model_copy(update={name: fill(value) for name, value in stored.model_dump().items()})


def ask_claude(system: str, prompt: str, shape: type[SQLModel], timeout: float = 20.0) -> tuple[SQLModel, str]:
    """Ask Claude one question. `system` is Sentinel's instructions,
    `prompt` is the alert or incident, and `shape` is the class the answer
    must fit (Suggestion or IncidentSuggestion).

    Returns the answer and the name of the model that wrote it. Raises
    Unavailable if anything goes wrong.
    """
    try:
        # The client reads the key from ANTHROPIC_API_KEY by itself, so the
        # key never appears in Sentinel's code. A short timeout and a single
        # retry stop the page waiting for minutes.
        client = anthropic.Anthropic(timeout=timeout, max_retries=1)
        response = client.beta.messages.create(
            model=os.environ.get("SENTINEL_MODEL") or DEFAULT_MODEL,
            # The most Claude may write, thinking included. It caps what one
            # request can cost, whatever the logs try to make it say.
            max_tokens=4096,
            # Instructions and data travel separately: see guard.py.
            system=system,
            messages=[{"role": "user", "content": prompt}],
            output_config={
                # How hard Claude thinks before answering. "low" keeps the
                # answer under ten seconds. Raise it to "medium" if the
                # suggestions read as shallow.
                "effort": "low",
                # Structured output: the answer must be JSON in this shape.
                # The format is generated from the class itself, so the two
                # can never disagree.
                "format": {"type": "json_schema", "schema": anthropic.transform_schema(shape)},
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
        raise Unavailable("The AI declined to assess this.")
    if response.stop_reason != "end_turn":
        raise Unavailable("The AI's answer was cut short.")
    text = next((block.text for block in response.content if block.type == "text"), "")
    try:
        return shape.model_validate_json(text), response.model
    except ValueError:
        raise Unavailable("The AI's answer was not in the expected format.")


def _api_message(problem: anthropic.APIStatusError) -> str:
    """The API's own one-line reason, e.g. that the account has no credit left."""
    body = problem.body if isinstance(problem.body, dict) else {}
    error = body.get("error")
    return str(error.get("message", ""))[:300] if isinstance(error, dict) else ""
