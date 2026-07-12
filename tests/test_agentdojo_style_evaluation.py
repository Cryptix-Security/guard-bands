from scripts.evaluate_agentdojo_style import run_evaluation


def test_agentdojo_style_structural_evaluation_passes():
    results = run_evaluation()

    assert len(results) == 12
    assert all(result.passed for result in results)


def test_agentdojo_style_evaluation_includes_expected_categories():
    categories = {result.category for result in run_evaluation()}

    assert {
        "authority transfer",
        "authorization",
        "channel binding",
        "context binding",
        "ingest hardening",
        "integrity",
        "multi-document",
        "provenance",
        "role separation",
        "unwrapped data",
    }.issubset(categories)
