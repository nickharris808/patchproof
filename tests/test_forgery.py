"""Regression tests for certificate forgery and coerced parsing.

A certificate exists so a sceptic does not have to trust us.  That only works if the
checker is harder to satisfy than the claim -- and it was not.  Two defects, both of
which let a certificate that proves nothing report success:

1. `_parse_form` *scanned* for terms with `re.finditer` instead of consuming the
   string.  Anything it could not match it silently skipped, so `@@@ <= 0` parsed as
   the well-formed `0 <= 0`, and `1e9 <= 0` parsed as `e9 + 1 <= 0` -- inventing a
   variable named `e9` out of an integer literal.  Combined with a false constant
   form, a certificate of pure nonsense replayed as VERIFIED.

2. Even with strict parsing, `verify` only ever answered "do these inequalities
   contradict each other?".  Nothing tied them to the patch being claimed, so a
   certificate consisting of `5 <= 0` -- false, hence trivially infeasible -- was
   arithmetically perfect and completely meaningless.

The rule these tests hold in place: the checker reports VERIFIED only when the
arithmetic replays *and* the constraints are the canonical ones for the defect class
the certificate names.  Anything less is UNVERIFIED or REJECTED, never a pass.
"""

from __future__ import annotations

import json

import pytest

from patchproof.claims import (
    CANONICAL_FORMS,
    REJECTED,
    UNVERIFIED,
    VERIFIED,
    replay_bound,
)
from patchproof.linear import LinearForm, _parse_form, find_certificate, replay


def _cert(*pairs, claim=None):
    d = {"constraints": [{"form": f, "multiplier": m} for f, m in pairs]}
    if claim is not None:
        d["claim"] = claim
    return d


# ---------------------------------------------------------------------------
# 1. The parser must consume, not scan.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "@@@ <= 0",              # parsed as "0 <= 0"
    "1e9 <= 0",              # parsed as "e9 + 1 <= 0" — invented a variable
    "x ++ y <= 0",           # parsed as "x + y <= 0"
    "x <= 0 <= 0",           # parsed as "x <= 0", second relation dropped
    "x & y <= 0",
    "x! <= 0",
    "x <= 1",                # rhs must be exactly 0
    "x >= 0",                # not a <= relation at all
    "x",                     # no relation
    "<= 0",                  # empty lhs
    "",
    "   ",
    "x y <= 0",              # missing operator
    "2 * 3 <= 0",            # coefficient on a literal is not a linear term
    "x + <= 0",
])
def test_unparseable_forms_raise_instead_of_being_coerced(text):
    """Every one of these used to yield a well-formed LinearForm."""
    with pytest.raises(ValueError):
        _parse_form(text)


@pytest.mark.parametrize("text", [None, 5, [], {}])
def test_non_string_forms_raise(text):
    with pytest.raises(ValueError):
        _parse_form(text)


def test_legitimate_forms_still_parse():
    """Strictness must not break the certificates we actually emit."""
    f = _parse_form("index - size + 1 <= 0")
    assert dict(f.coeffs) == {"index": 1, "size": -1}
    assert f.const == 1
    assert dict(_parse_form("- index + size <= 0").coeffs) == {"index": -1, "size": 1}
    assert dict(_parse_form("2*a - 3*b <= 0").coeffs) == {"a": 2, "b": -3}
    assert _parse_form("  x  -  y  +  4  <= 0  ").const == 4


def test_the_exact_forged_certificate_that_used_to_verify():
    """The headline case: garbage + a false constant replayed as VERIFIED."""
    forged = _cert(("@@@ <= 0", 1), ("5 <= 0", 1))
    ok, msg = replay(forged)
    assert ok is False, f"forged certificate replayed as valid: {msg}"
    status, _ = replay_bound(forged)
    assert status == REJECTED


# ---------------------------------------------------------------------------
# 2. Multipliers must be integers, not rounded into integers.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mult", [1.5, 0.999, -0.0, 2.0, "1", None, [1], True, False])
def test_non_integer_multipliers_are_rejected_not_truncated(mult):
    """int(1.5) == 1 silently checks a different certificate than the one supplied."""
    ok, msg = replay(_cert(("x + 1 <= 0", mult), ("- x <= 0", 1)))
    assert ok is False, f"multiplier {mult!r} was accepted: {msg}"
    assert "multiplier" in msg


def test_negative_multipliers_are_rejected():
    """Farkas requires non-negativity; a negative multiplier is not a proof."""
    ok, msg = replay(_cert(("x + 1 <= 0", -1), ("- x <= 0", 1)))
    assert ok is False
    assert "negative" in msg.lower()


# ---------------------------------------------------------------------------
# 3. Binding: arithmetic alone is not a proof about any patch.
# ---------------------------------------------------------------------------

def test_unbound_certificate_is_unverified_not_verified():
    """A certificate naming no claim has no trust anchor to check it against."""
    status, msg = replay_bound(_cert(("x + 1 <= 0", 1), ("- x <= 0", 1)))
    assert status == UNVERIFIED
    assert status != VERIFIED
    assert "does NOT establish" in msg


def test_trivially_infeasible_constant_proves_nothing():
    """`5 <= 0` is false, so it contradicts itself. That is not a patch proof."""
    status, msg = replay_bound(_cert(("5 <= 0", 1)))
    assert status == UNVERIFIED, msg


def test_certificate_bound_to_the_wrong_class_is_rejected():
    """Class A's proof must not verify a claim about class C."""
    a_forms = CANONICAL_FORMS["A"]
    cert = find_certificate(a_forms)
    assert cert is not None
    d = cert.to_dict()
    d["claim"] = {"defect_class": "C"}          # same arithmetic, different claim
    status, msg = replay_bound(d)
    assert status == REJECTED
    assert "not that" in msg or "constraints" in msg


def test_certificate_claiming_an_unknown_class_is_not_verified():
    a_forms = CANONICAL_FORMS["A"]
    d = find_certificate(a_forms).to_dict()
    d["claim"] = {"defect_class": "Z-nonexistent"}
    status, _ = replay_bound(d)
    assert status == UNVERIFIED


@pytest.mark.parametrize("key", sorted(CANONICAL_FORMS))
def test_a_genuine_bound_certificate_verifies(key):
    """The positive control: the real thing must still pass."""
    cert = find_certificate(CANONICAL_FORMS[key])
    assert cert is not None
    cert.claim = {"defect_class": key}
    status, msg = replay_bound(cert.to_dict())
    assert status == VERIFIED, msg


def test_emitted_certificates_carry_their_claim():
    """`patchproof cert A` must produce something that can actually verify."""
    from patchproof.prover import prove

    r = prove("A")
    assert r.certificate is not None
    d = r.certificate.to_dict()
    assert d["claim"] and d["claim"]["defect_class"] == "A"
    assert d["claim"]["widths"] == {"index": 16, "size": 16}
    assert replay_bound(d)[0] == VERIFIED


def test_canonical_forms_match_the_prover(monkeypatch):
    """claims.py duplicates the forms to stay solver-free; they must not drift."""
    from patchproof.model import CLASSES
    from patchproof.prover import elimination_forms

    for key, forms in CANONICAL_FORMS.items():
        prover_forms = elimination_forms(CLASSES[key])
        assert prover_forms is not None, key
        norm = lambda fs: sorted((tuple(sorted(f.coeffs)), f.const) for f in fs)  # noqa: E731
        assert norm(forms) == norm(prover_forms), f"class {key} forms drifted"


# ---------------------------------------------------------------------------
# 4. Malformed containers.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    {},
    {"constraints": None},
    {"constraints": []},
    {"constraints": "not a list"},
    {"constraints": [None]},
    {"constraints": ["a string"]},
    {"constraints": [{"form": "x <= 0"}]},              # no multiplier
    {"constraints": [{"multiplier": 1}]},               # no form
    {"constraints": [{"form": "x <= 0", "multiplier": 0}]},   # all-zero
    [],
    "not a dict",
    None,
])
def test_malformed_certificates_are_rejected_with_a_reason(bad):
    status, msg = replay_bound(bad)
    assert status == REJECTED
    assert msg


def test_deeply_nested_json_does_not_crash():
    d = {"constraints": [{"form": "x + 1 <= 0", "multiplier": 1, "extra": {"a": {"b": {"c": [1] * 100}}}}]}
    status, _ = replay_bound(d)
    assert status in (REJECTED, UNVERIFIED)


def test_huge_multipliers_are_arithmetically_handled():
    """Big integers are fine — Python has no overflow — but must stay unbound."""
    status, _ = replay_bound(_cert(("x + 1 <= 0", 10**18), ("- x <= 0", 10**18)))
    assert status == UNVERIFIED   # correct arithmetic, but no claim named


def test_find_certificate_none_is_never_a_satisfiability_claim():
    """A bounded search returning nothing means 'not found', not 'feasible'."""
    forms = [LinearForm.of({"x": 5}, -1), LinearForm.of({"x": -5}, -1)]
    assert find_certificate(forms, max_multiplier=1) is None


def test_replay_round_trips_through_json():
    """The realistic path: certificate written to disk and read back."""
    from patchproof.prover import prove

    d = json.loads(json.dumps(prove("B").certificate.to_dict()))
    assert replay_bound(d)[0] == VERIFIED
