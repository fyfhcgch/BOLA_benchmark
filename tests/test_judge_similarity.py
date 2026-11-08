"""消融判据：CN03 风格的字符串相似度（只用于对照，不参与默认判定）。"""

from pipeline.judge import judge_read_similarity


def _resp(body, status=200):
    return {"status": status, "body": body}


def test_identical_body_is_flagged():
    body = {"username": "alice1", "email": "alice1@example.com"}
    vuln, reason = judge_read_similarity(_resp(body), body)
    assert vuln is True
    assert reason.startswith("similarity:1.000")


def test_different_body_is_not_flagged():
    a = {"username": "alice1", "email": "alice1@example.com"}
    b = {"username": "bob2", "email": "bob2@example.com"}
    vuln, reason = judge_read_similarity(_resp(a), b)
    assert vuln is False
    assert "<" in reason


def test_no_baseline_is_not_flagged():
    vuln, reason = judge_read_similarity(_resp({"a": 1}), None)
    assert vuln is False
    assert reason == "no_baseline"


def test_error_status_is_not_flagged():
    vuln, reason = judge_read_similarity(_resp({"error": "forbidden"}, 403), {"a": 1})
    assert vuln is False
    assert reason == "status=403"


def test_empty_body_is_not_flagged():
    vuln, reason = judge_read_similarity(_resp({}), {})
    assert vuln is False
    assert reason == "empty_shell"


def test_threshold_is_respected():
    a = {"x": "a" * 10 + "b"}
    b = {"x": "a" * 10 + "c"}
    loose, _ = judge_read_similarity(_resp(a), b, threshold=0.90)
    strict, reason = judge_read_similarity(_resp(a), b, threshold=0.999)
    assert loose is True
    assert strict is False
    assert reason.startswith("similarity:0.950<")
