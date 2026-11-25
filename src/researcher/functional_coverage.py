from typing import Any

from .models import Need


def functional_coverage(
    need: Need, contract_id: str, feedback: dict[str, Any]
) -> dict[str, Any]:
    """Report tested candidates, without asserting independent reserve parity."""
    targets: dict[str, list[str]] = {target: [] for target in need.targets}
    for row in feedback["packages"]:
        if need.capability_id not in row["capabilities"]:
            continue
        if contract_id not in row["contracts"]:
            continue
        for target in targets:
            if target in row["validated_targets"] and row["pin"] not in targets[target]:
                targets[target].append(row["pin"])
    return {
        "capability_id": need.capability_id,
        "contract_id": contract_id,
        "used_cache": feedback["used_cache"],
        "tested_candidates": {target: sorted(pins) for target, pins in targets.items()},
        "candidate_gaps": {
            target: max(
                0, need.desired_candidates - len({pin.rsplit("@", 1)[0] for pin in pins})
            )
            for target, pins in targets.items()
        },
        "independent_pair_verified": False,
    }
