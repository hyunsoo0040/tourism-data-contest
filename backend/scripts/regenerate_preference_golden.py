"""Regenerate fixtures/synthetic/preference-golden.json under the v2 authority."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from itda.contracts.preference import QuestionnaireSubmission
from itda.domain.preference import calculate_preference


def remap(likert: int) -> int:
    """Map legacy Likert 1..5 onto the choice scale 1..3, rounding to nearest."""

    return {1: 1, 2: 1, 3: 2, 4: 3, 5: 3}[likert]


def main() -> None:
    fixture_path = Path(sys.argv[1])
    golden = json.loads(fixture_path.read_text(encoding="utf-8"))
    golden["questionnaire_version"] = "questionnaire-v2"
    golden["scoring_version"] = "choice-bp-v2"
    created_at = datetime.fromisoformat(golden["created_at"]).astimezone(UTC)
    new_cases = []
    for case in golden["cases"]:
        answers = {f"q{i}": remap(value) for i, value in enumerate(case["answers"], start=1)}
        answers.update({f"q{i}": 2 for i in range(len(case["answers"]) + 1, 13)})
        submission = QuestionnaireSubmission.model_validate(
            {
                "request_id": f"synthetic:preference:{case['id']}",
                "trip_conditions": golden["trip_conditions"],
                "answers": answers,
            }
        )
        profile = calculate_preference(submission, created_at=created_at)
        new_cases.append(
            {
                "id": case["id"],
                "answers": [answers[f"q{i}"] for i in range(1, 13)],
                "basis_points": [score.basis_points for score in profile.scores],
                "display_scores": [score.display_score for score in profile.scores],
                "description_ko": profile.description_ko,
                "config_hash": profile.config_hash,
            }
        )
    golden["cases"] = new_cases
    golden["config_hash"] = new_cases[0]["config_hash"]
    rendered = json.dumps(golden, ensure_ascii=False, indent=2)
    fixture_path.write_text(rendered + "\n", encoding="utf-8")
    print(f"regenerated {len(new_cases)} cases; hash {golden['config_hash'][:12]}")


if __name__ == "__main__":
    main()
