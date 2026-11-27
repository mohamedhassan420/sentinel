"""The incident report: an HTML page, printed to PDF by WeasyPrint.

The report is designed like a web page (report.html, next to this file) and
filled in with one incident's facts. WeasyPrint then lays the page out on A4
paper and writes the PDF.

Two steps, kept apart on purpose:

  render_html()  facts in, HTML out. Plain Python, runs anywhere.
  to_pdf()       HTML in, PDF out. Needs WeasyPrint's system libraries,
                 which the Docker image has and most laptops do not.
"""

from datetime import datetime, timedelta
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from backend.engine.correlation import real_alerts
from backend.models import FALSE_POSITIVE, IncidentDetail, IncidentInfo, IncidentSummary, Indicator
from backend.reports.indicators import defang, defang_text

REPORTS_DIR = Path(__file__).parent

# autoescape=True is the security setting here. Log text ends up in the
# report (an email sender, a file name), and part of it was written by the
# attacker. Escaping turns any < or > in it into harmless text, so nothing
# from a log can become a tag in the page: no script, no image that makes
# the server fetch an address. The template never switches it off.
_templates = Environment(loader=FileSystemLoader(REPORTS_DIR), autoescape=True)

# What the report recommends when there is no AI summary to take steps from.
GENERAL_CONTAINMENT = [
    "Disconnect the affected hosts (section 3) from the network.",
    "Reset the passwords of the affected users and end their open sessions.",
    "Block the addresses and domains listed as indicators (section 4) at the firewall and the mail gateway.",
]
GENERAL_RECOVERY = [
    "Remove what the attacker added, such as accounts, files and scheduled tasks. "
    "Rebuild a host from a clean image if there is any doubt.",
    "Restore changed or lost data from a backup taken before the first alert.",
    "Search the logs of other machines for the indicators in section 4.",
    "Watch the affected hosts and accounts closely for several weeks after they return to use.",
]


class Unavailable(Exception):
    """The PDF could not be made on this computer. The message is safe to show."""


def render_html(detail: IncidentDetail, summary: IncidentSummary | None, generated: datetime) -> str:
    """Fill in the report template for one incident.

    `summary` is the stored AI summary, if there is one. `generated` is the
    time to print as "report created at".
    """
    incident = detail.incident
    alerts = [step.alert for step in detail.timeline]
    # A false positive was harmless activity, so it is not part of the story.
    real = real_alerts(alerts)
    return _templates.get_template("report.html").render(
        incident=incident,
        all_false_positive=all(alert.status == FALSE_POSITIVE for alert in alerts),
        date=_date(incident.start_time),
        start=_time(incident.start_time),
        end=_end(incident),
        duration=duration(incident.end_time - incident.start_time),
        generated=f"{_date(generated)} at {generated:%H:%M} UTC",
        steps=[
            {"time": _time(alert.time), "tactics": alert.attack_tactics, "title": alert.title,
             "host": alert.host, "user": alert.user, "severity": alert.severity}
            for alert in real
        ],
        false_positives=len(alerts) - len(real),
        techniques=detail.techniques,
        indicators=[
            {"kind": indicator.kind, "value": defang(indicator), "seen_in": indicator.alert_title}
            for indicator in detail.indicators
        ],
        prose=_defanged(_prose(summary) or _fallback_prose(incident), detail.indicators),
    )


def to_pdf(html: str) -> bytes:
    """Print the report's HTML to a PDF. Raises Unavailable where WeasyPrint
    cannot run."""
    try:
        # Imported here and not at the top of the file: loading WeasyPrint
        # fails on a computer without its system libraries, and that must
        # not stop the rest of the app from starting.
        import weasyprint
        from weasyprint.urls import URLFetcher
    except (ImportError, OSError):
        raise Unavailable(
            "PDF reports need WeasyPrint's system libraries, which this computer does not have. "
            "Run Sentinel through Docker (docker compose up) to download reports."
        )
    # The report may load files that sit beside the template (its fonts) and
    # nothing else. Whatever ends up in the page, WeasyPrint will not fetch
    # an address on the network for it.
    local_files_only = URLFetcher(allowed_protocols={"file"})
    page = weasyprint.HTML(string=html, base_url=REPORTS_DIR.as_uri() + "/", url_fetcher=local_files_only)
    return page.write_pdf()


# ------------------------------------------------------------ The wording


def _prose(summary: IncidentSummary | None) -> dict | None:
    """The written parts of the report, from the stored summary: the
    analyst's version once they have reviewed it, else the AI's draft."""
    if summary is None:
        return None
    reviewed = summary.review != "Not reviewed"
    severity = summary.final_severity or summary.severity
    written_by = {
        "Not reviewed": "AI-written draft. An analyst has not reviewed it yet.",
        "Accepted": "Written by AI, then reviewed and accepted by the analyst.",
        "Edited": "Written by the analyst, starting from an AI draft.",
    }[summary.review]
    if summary.source == "demo":
        written_by += " Demo mode: the draft is a stored example answer, not a live AI call."
    return {
        "written_by": written_by,
        "reviewed": reviewed,
        "summary": summary.final_summary or summary.summary,
        "severity": severity,
        # The AI's reason only fits the severity the AI chose.
        "severity_reason": summary.severity_reason if severity == summary.severity else "",
        # An analyst may empty a list on purpose, so "is None" and not "or".
        "containment": summary.containment if summary.final_containment is None else summary.final_containment,
        "recovery": summary.recovery if summary.final_recovery is None else summary.final_recovery,
    }


def _defanged(prose: dict, indicators: list[Indicator]) -> dict:
    """The written parts with every address they mention defanged."""
    def safe(value):
        if isinstance(value, list):
            return [safe(item) for item in value]
        return defang_text(value, indicators) if isinstance(value, str) else value

    return {name: safe(value) for name, value in prose.items()}


def _fallback_prose(incident: IncidentInfo) -> dict:
    """The written parts when there is no AI summary: a paragraph built
    from the incident's own facts, and a general checklist."""
    summary = (
        f"Sentinel grouped {_count(incident.alerts, 'alert')} into this incident because they share a host or "
        f"a user and happened close together. They were raised between {_time(incident.start_time)} and "
        f"{_end(incident)} UTC, involving {_names(incident.hosts, 'host')} and {_names(incident.users, 'user')}. "
        f"The alerts point to {_count(len(incident.tactics), 'MITRE ATT&CK tactic')}: {', '.join(incident.tactics)}."
    )
    return {
        "written_by": "Built from the alert data. There is no AI summary for this incident, "
                      "so the recommended actions are a general checklist.",
        "reviewed": True,  # nothing here is an unreviewed AI suggestion
        "summary": summary,
        "severity": incident.severity,
        "severity_reason": "The highest severity among the incident's alerts.",
        "containment": GENERAL_CONTAINMENT,
        "recovery": GENERAL_RECOVERY,
    }


def _count(number: int, word: str) -> str:
    return f"{number} {word}{'' if number == 1 else 's'}"


def _names(names: list[str], word: str) -> str:
    if not names:
        return f"no {word}"
    return f"the {word}{'' if len(names) == 1 else 's'} {', '.join(names)}"


def _date(time: datetime) -> str:
    return f"{time.day} {time:%B %Y}"  # e.g. 27 November 2026


def _time(time: datetime) -> str:
    return f"{time:%H:%M:%S}"


def _end(incident: IncidentInfo) -> str:
    """The time of the last alert, with its date if that is a later day."""
    same_day = incident.end_time.date() == incident.start_time.date()
    return _time(incident.end_time) if same_day else f"{_time(incident.end_time)} on {_date(incident.end_time)}"


def duration(length: timedelta) -> str:
    """A length of time in words, e.g. "28 minutes"."""
    minutes = round(length.total_seconds() / 60)
    if minutes < 1:
        return "under a minute"
    hours, minutes = divmod(minutes, 60)
    parts = [_count(hours, "hour")] * bool(hours) + [_count(minutes, "minute")] * bool(minutes)
    return " ".join(parts)
