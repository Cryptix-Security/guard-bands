"""Property-based fuzzing for the hand-rolled Guard Band parser.

The parser (`extract_guard_band_blocks` / `_parse_guard_band_block`) is pure
index arithmetic over attacker-influenced text, so it is the project's primary
attack surface. These tests assert two invariants under random input:

  1. Parsing never raises — malformed input must be rejected, not crash.
  2. No false-accept — only content that was genuinely wrapped and left intact
     verifies as valid.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from app.crypto import (
    GuardBandCrypto,
    extract_guard_band_blocks,
)


CRYPTO = GuardBandCrypto(b"fuzz-secret")

# Text that liberally includes the marker tokens/delimiters the parser keys on.
_TOKENS = ["a", "b", "0", "9", ":", "⟪", "⟫", "\n",
           "INERT", "START", "END", "mac", "kid", "iss", "v", "r", "iat", "exp"]
marker_soup = st.lists(st.sampled_from(_TOKENS), max_size=40).map("".join)


@given(text=marker_soup)
@settings(max_examples=400)
def test_extract_never_crashes_on_marker_soup(text):
    # Must not raise regardless of how the delimiters are arranged.
    blocks = extract_guard_band_blocks(text)
    assert isinstance(blocks, list)


@given(text=marker_soup)
@settings(max_examples=400)
def test_verify_never_crashes_and_never_false_accepts(text):
    result = CRYPTO.extract_and_verify(text, {"request_id": "req-001"})
    # Random soup is never a band we signed, so it must never verify.
    assert result["valid"] is False


@given(
    content=st.text(max_size=200),
    request_id=st.text(min_size=1, max_size=40),
)
@settings(max_examples=300)
def test_wrap_verify_round_trip_is_stable(content, request_id):
    context = {"request_id": request_id}
    wrapped = CRYPTO.wrap_content(content, context)

    # A clean band always verifies and yields the exact content back.
    result = CRYPTO.extract_and_verify(wrapped, context)
    if "⟪INERT:START" in content or "⟪INERT:END" in content:
        # Embedded markers are deliberately rejected as nested.
        assert result["valid"] is False
    else:
        assert result["valid"] is True
        assert result["content"] == content
        # The block extractor recovers exactly the band we produced.
        assert extract_guard_band_blocks(f"prefix\n{wrapped}\nsuffix") == [wrapped]


@given(
    content=st.text(min_size=1, max_size=80).filter(
        lambda c: "⟪INERT:START" not in c and "⟪INERT:END" not in c
    ),
    flip_at=st.integers(min_value=0, max_value=79),
)
@settings(max_examples=300)
def test_single_character_content_mutation_is_rejected(content, flip_at):
    context = {"request_id": "req-001"}
    wrapped = CRYPTO.wrap_content(content, context)

    index = flip_at % len(content)
    mutated_char = "X" if content[index] != "X" else "Y"
    mutated_content = content[:index] + mutated_char + content[index + 1:]
    if mutated_content == content:
        return

    tampered = wrapped.replace(f"⟫\n{content}\n⟪", f"⟫\n{mutated_content}\n⟪", 1)
    if tampered == wrapped:
        return  # content not uniquely locatable; skip this example

    result = CRYPTO.extract_and_verify(tampered, context)
    assert result["valid"] is False
