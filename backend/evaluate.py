import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx


BASE_URL = "http://127.0.0.1:8001"

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TEST_FILE = (
    PROJECT_ROOT
    / "data"
    / "test_cases"
    / "evaluation.json"
)

RESULT_FILE = (
    PROJECT_ROOT
    / "data"
    / "evaluation_results.json"
)


def run_evaluation():
    with open(TEST_FILE, "r", encoding="utf-8") as file:
        test_cases = json.load(file)

    results = []

    correct = 0
    failures = 0
    total_latency = 0

    print()
    print("Cybersecurity Evidence Investigator")
    print("Evaluation")
    print("=" * 50)

    for case in test_cases:
        print()
        print(f"Running: {case['id']}")

        start = time.perf_counter()

        try:
            response = httpx.post(
                f"{BASE_URL}/investigate",
                json={
                    "content": case["content"]
                },
                timeout=90,
            )

            latency = time.perf_counter() - start
            total_latency += latency

            response.raise_for_status()

            data = response.json()

            actual = data["verdict"]
            expected = case["expected_verdict"]

            passed = actual == expected

            if passed:
                correct += 1

            print(f"Expected:   {expected}")
            print(f"Actual:     {actual}")
            print(
                f"Score:      {data['threat_score']}/100"
            )
            print(
                f"Confidence: {data['confidence']}%"
            )
            print(
                f"Latency:    {latency:.2f}s"
            )
            print(
                f"Result:     {'PASS' if passed else 'FAIL'}"
            )

            results.append(
                {
                    "id": case["id"],
                    "description": case["description"],
                    "expected_verdict": expected,
                    "actual_verdict": actual,
                    "threat_score": data["threat_score"],
                    "confidence": data["confidence"],
                    "insufficient_evidence": data[
                        "insufficient_evidence"
                    ],
                    "latency_seconds": round(
                        latency, 2
                    ),
                    "passed": passed,
                }
            )

        except Exception as error:
            failures += 1

            print(f"ERROR: {error}")

            results.append(
                {
                    "id": case["id"],
                    "description": case["description"],
                    "expected_verdict": case[
                        "expected_verdict"
                    ],
                    "error": str(error),
                    "passed": False,
                }
            )

    total = len(test_cases)

    accuracy = (
        correct / total * 100
        if total
        else 0
    )

    completed = total - failures

    average_latency = (
        total_latency / completed
        if completed
        else 0
    )

    summary = {
        "evaluated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "total_cases": total,
        "correct_verdicts": correct,
        "failed_requests": failures,
        "verdict_accuracy_percent": round(
            accuracy, 2
        ),
        "average_latency_seconds": round(
            average_latency, 2
        ),
        "results": results,
    }

    with open(
        RESULT_FILE,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            summary,
            file,
            indent=2,
        )

    print()
    print("=" * 50)
    print("SUMMARY")
    print("=" * 50)

    print(f"Cases:       {total}")
    print(f"Correct:     {correct}")
    print(f"Errors:      {failures}")
    print(f"Accuracy:    {accuracy:.2f}%")
    print(
        f"Avg latency: {average_latency:.2f}s"
    )

    print()
    print(
        f"Results saved to: {RESULT_FILE}"
    )


if __name__ == "__main__":
    run_evaluation()