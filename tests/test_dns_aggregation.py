"""AdGuard parse streaming + single-pass multi-day DNS aggregation (P4)."""
import json
import types

import parsers


def _line(ts, qh, ip, filtered=False):
    return json.dumps({"T": ts, "QH": qh, "QT": "A", "IP": ip,
                       "Result": {"IsFiltered": filtered}, "Elapsed": 1000})


LINES = [
    _line("2026-05-29T10:00:00Z", "a.com", "10.0.0.5"),
    _line("2026-05-29T10:05:00Z", "b.com", "10.0.0.5", filtered=True),
    _line("2026-05-29T11:00:00Z", "a.com", "10.0.0.6"),
    _line("2026-05-28T09:00:00Z", "c.com", "10.0.0.5"),
    "",            # blank → skipped
    "{bad json",   # invalid → skipped
]


def test_iter_is_generator_and_parses():
    it = parsers.iter_adguard_lines(iter(LINES))
    assert isinstance(it, types.GeneratorType)
    rows = list(it)
    assert len(rows) == 4
    assert rows[0]["qh"] == "a.com" and rows[0]["client"] == "10.0.0.5"
    assert rows[1]["blocked"] is True


def test_parse_list_equals_iter():
    assert parsers.parse_adguard_lines(LINES) == list(parsers.iter_adguard_lines(LINES))


def test_summarise_days_single_pass_over_generator():
    entries = parsers.iter_adguard_lines(iter(LINES))   # generator: consumed once
    out = parsers.summarise_dns_days(
        entries, ["2026-05-29", "2026-05-28", "2026-05-27"], {"10.0.0.5": "host-5"})
    assert set(out) == {"2026-05-29", "2026-05-28", "2026-05-27"}

    d29 = out["2026-05-29"]
    assert d29["total_queries"] == 3
    assert d29["blocked_queries"] == 1
    assert {x["domain"]: x["count"] for x in d29["top_queried"]} == {"a.com": 2, "b.com": 1}
    assert d29["top_blocked"][0]["domain"] == "b.com"

    pc = {x["client"]: x for x in d29["per_client"]}
    assert pc["10.0.0.5"]["hostname"] == "host-5"
    assert pc["10.0.0.5"]["queries"] == 2 and pc["10.0.0.5"]["blocked"] == 1

    hours = {h["hour"]: h for h in d29["hourly"]}
    assert hours[10]["queries"] == 2 and hours[10]["blocked"] == 1
    assert hours[11]["queries"] == 1

    # requested day with no data is present and zeroed
    assert out["2026-05-27"]["total_queries"] == 0


def test_single_day_matches_multi_day():
    one = parsers.summarise_dns(parsers.parse_adguard_lines(LINES), "2026-05-29")
    multi = parsers.summarise_dns_days(
        parsers.parse_adguard_lines(LINES), ["2026-05-29"])["2026-05-29"]
    assert one == multi
