"""
Offline tests for logtriage. They use a FAKE model (dependency injection), so
they run instantly with no server and no API key. Run with:  python -m pytest
"""
import logtriage as lt


def fake_json(prompt, **kwargs):
    """A stand-in model that always returns well-formed (fenced) JSON."""
    return '```json\n{"label": "MALICIOUS", "severity": 5, "reason": "reads the shadow file"}\n```'


def test_parses_fenced_json():
    r = lt.triage_log("sudo cat /etc/shadow", fake_json)
    assert r.label is lt.Label.MALICIOUS
    assert r.severity == 5
    assert "shadow" in r.reason


def test_bad_json_falls_back_to_unknown():
    r = lt.triage_log("some line", lambda p, **k: "sorry, I cannot help")
    assert r.label is lt.Label.UNKNOWN
    assert r.severity == 0


def test_validation_rejects_bad_input():
    for bad in ["", "   ", 123, None]:
        try:
            lt.clean_line(bad)
            assert False, f"should have rejected {bad!r}"
        except lt.InvalidLogLine:
            pass


def test_batch_survives_a_bad_line():
    results = lt.triage_batch(["a real line", 123, ""], fake_json, max_workers=2)
    assert len(results) == 3
    # the non-string and empty entries become UNKNOWN, not crashes
    assert any(r.label is lt.Label.UNKNOWN for r in results)


def test_generate_rule_with_no_findings():
    benign = [lt.Triage("ok", lt.Label.BENIGN, 1, "normal")]
    out = lt.generate_rule(benign, fake_json, fmt="sigma")
    assert "No suspicious" in out


if __name__ == "__main__":
    # allow running without pytest: `python test_logtriage.py`
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"{name} passed")
    print("All tests passed.")
