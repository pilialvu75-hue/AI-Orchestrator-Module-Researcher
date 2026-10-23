from researcher.state import SQLiteStateStore


def test_candidate_recovery_queue_is_read_only_and_excludes_blocked(tmp_path):
    state = SQLiteStateStore(tmp_path / "state.db")
    for fingerprint, lifecycle in (
        ("rejected", "REJECTED"),
        ("review", "SECURITY_REVIEW"),
        ("blocked", "SECURITY_BLOCKED"),
        ("accepted", "SHORTLISTED"),
    ):
        state.upsert_candidate(
            fingerprint, "ai.local_inference", "owner/repo",
            "a" * 40, lifecycle, 0.2, "dossier.json",
            "review reason",
        )
    queue = state.candidate_recovery_queue()
    assert [item["fingerprint"] for item in queue] == ["rejected", "review"]
    assert queue[0]["recovery_action"] == "review_scoring_and_policy_then_fresh_admission"
    assert queue[1]["recovery_action"] == "repeat_security_review_with_current_evidence"
    assert all(item["automatically_admitted"] is False for item in queue)
    assert state.candidate_recovery_queue(limit=1)[0]["fingerprint"] == "rejected"
    assert len(state.candidate_rows("ai.local_inference")) == 4
