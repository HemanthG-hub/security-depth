import os

import pytest

os.environ.setdefault("MONGO_URL", "mongodb://127.0.0.1:27017")
os.environ.setdefault("DB_NAME", "security_corpus")

from routers.scans import analyze_code
from tests.security_corpus import REPOSITORY_CASES, REPOSITORY_EXPECTED_RULES, RULE_CASES


def matching_findings(code: str, language: str, rule: str) -> bool:
    result = analyze_code(code, language, None)
    return any(finding.title == rule for finding in result.vulnerabilities)


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case["rule"])
def test_vulnerable_corpus_examples_are_detected(case):
    assert matching_findings(case["vulnerable"], case["language"], case["rule"])


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case["rule"])
def test_safe_corpus_examples_do_not_match_their_rule(case):
    assert not matching_findings(case["safe"], case["language"], case["rule"])


def test_labeled_corpus_metrics_meet_baseline_and_print_per_rule_report():
    report = []
    totals = {"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0}
    for case in RULE_CASES:
        true_positive = int(matching_findings(case["vulnerable"], case["language"], case["rule"]))
        false_negative = 1 - true_positive
        false_positive = int(matching_findings(case["safe"], case["language"], case["rule"]))
        true_negative = 1 - false_positive
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 1.0
        recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 1.0
        false_positive_rate = false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0
        report.append(
            f"{case['rule']}: precision={precision:.2f} recall={recall:.2f} "
            f"false_positive_rate={false_positive_rate:.2f}"
        )
        totals["true_positive"] += true_positive
        totals["false_positive"] += false_positive
        totals["true_negative"] += true_negative
        totals["false_negative"] += false_negative
        assert precision == 1.0, case["rule"]
        assert recall == 1.0, case["rule"]
        assert false_positive_rate == 0.0, case["rule"]
    overall_precision = totals["true_positive"] / (totals["true_positive"] + totals["false_positive"])
    overall_recall = totals["true_positive"] / (totals["true_positive"] + totals["false_negative"])
    overall_false_positive_rate = totals["false_positive"] / (totals["false_positive"] + totals["true_negative"])
    report.append(
        f"OVERALL: precision={overall_precision:.2f} recall={overall_recall:.2f} "
        f"false_positive_rate={overall_false_positive_rate:.2f}"
    )
    print("\n".join(report))


@pytest.mark.parametrize("repository", REPOSITORY_CASES, ids=REPOSITORY_CASES.keys())
def test_repository_corpus_matches_labeled_rule_set(repository):
    findings = set()
    for file_name, code in REPOSITORY_CASES[repository].items():
        findings.update(
            finding.title
            for finding in analyze_code(code, "auto", file_name).vulnerabilities
        )

    assert findings == REPOSITORY_EXPECTED_RULES[repository]