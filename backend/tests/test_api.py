from datetime import datetime, timedelta


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_logs_start_empty(client):
    assert client.get("/api/logs").json() == {"total": 0, "logs": []}


def test_run_brute_force_adds_logs(client):
    result = client.post("/api/simulate/brute_force").json()
    assert result == {"added": 101, "attack": 41, "background": 60}

    page = client.get("/api/logs").json()
    assert page["total"] == 101
    # Newest first, and times carry a UTC offset so browsers read them correctly.
    times = [datetime.fromisoformat(log["time"]) for log in page["logs"]]
    assert times == sorted(times, reverse=True)
    assert times[0].utcoffset() == timedelta(0)


def test_filters_combine(client):
    client.post("/api/simulate/brute_force")

    failures = client.get("/api/logs", params={"scenario": "brute_force", "event_id": 4625}).json()
    assert failures["total"] == 40
    assert all(log["user"] == "s.ahmed" for log in failures["logs"])

    assert client.get("/api/logs", params={"host": "srv-rdp"}).json()["total"] == 41
    assert client.get("/api/logs", params={"q": "203.0.113.77"}).json()["total"] == 41
    assert client.get("/api/logs", params={"source": "Sysmon", "event_id": 4625}).json()["total"] == 0
    assert len(client.get("/api/logs", params={"limit": 5}).json()["logs"]) == 5


def test_filter_options_list_what_is_stored(client):
    client.post("/api/simulate/brute_force")
    options = client.get("/api/logs/filters").json()
    assert options["sources"] == ["Sysmon", "Windows Security"]
    assert options["event_ids"] == [1, 4624, 4625]
    assert options["scenarios"] == ["background", "brute_force"]


def test_search_text_is_not_a_sql_wildcard(client):
    client.post("/api/simulate/brute_force")
    # "%" matches everything in SQL LIKE. It must be treated as a plain character.
    assert client.get("/api/logs", params={"q": "%"}).json()["total"] == 0


def test_bad_input_is_rejected(client):
    assert client.post("/api/simulate/not_a_scenario").status_code == 404
    assert client.get("/api/logs", params={"limit": 0}).status_code == 422
    assert client.get("/api/logs", params={"event_id": "abc"}).status_code == 422
    assert client.get("/api/logs", params={"q": "x" * 201}).status_code == 422
