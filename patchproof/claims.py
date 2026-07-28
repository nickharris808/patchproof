"""Binding a certificate to the claim it purports to prove.

`verify` answers one question: do these inequalities, with these multipliers, combine
to a contradiction?  That is arithmetic, and it is genuinely checkable without a
solver.  It is also *not* the question a reader of a certificate actually cares about,
and the gap between the two is easy to miss:

    replay({"constraints": [{"form": "5 <= 0", "multiplier": 1}]})  ->  contradiction

`5 <= 0` is false, so a system containing it is trivially infeasible and the
arithmetic is impeccable.  It says nothing whatever about anybody's patch.  A
certificate proves a patch complete only if its constraints *are* the constraints of
that patch -- `corrected AND NOT safety` for a named defect class at declared widths.
Nothing in the arithmetic can establish that; it has to be checked separately, against
a canonical statement of the claim held by the verifier rather than supplied with the
proof.

So this module keeps the canonical forms, and `replay_bound` checks a certificate's
constraints against them before believing anything.  A certificate that carries no
claim is reported UNVERIFIED -- never VERIFIED -- because an unbound certificate has
no trust anchor to check it against, and saying "verified" would be asserting a
property nobody established.

Solver-free on purpose: this is the module a sceptic runs, so it must not drag in z3.
The forms are stated as literal integer inequalities and are hand-checked against the
class definitions in `model.py`; `tests/test_patchproof.py` asserts the two agree.
"""

from __future__ import annotations

from .linear import LinearForm, ReplayError, _parse_form, _parse_multiplier, verify

# Canonical `corrected AND NOT safety` forms per shipped defect class.
#
# Duplicated deliberately from prover.elimination_forms: that module imports z3, and
# a verification path that needs a solver installed to check a "solver-free"
# certificate would defeat the point.  A test cross-checks the two lists are equal, so
# the duplication cannot drift.
CANONICAL_FORMS: dict[str, list[LinearForm]] = {
    "A": [
        LinearForm.of({"index": 1, "size": -1}, 1, "corrected: index < size"),
        LinearForm.of({"size": 1, "index": -1}, 0, "not safety: index >= size"),
    ],
    "B": [
        LinearForm.of({"payload": 1, "record": -1}, 8, "corrected: payload + 8 <= record"),
        LinearForm.of({"record": 1, "payload": -1}, -7, "not safety: payload + 8 > record"),
    ],
    "C": [
        LinearForm.of({"sel": 1}, -19, "corrected: sel < 20"),
        LinearForm.of({"sel": -1}, 20, "not safety: sel >= 20"),
    ],
}

# Verdict vocabulary.  UNVERIFIED is not a soft pass: it means the tool declined to
# certify, and it is returned whenever the binding cannot be established.
VERIFIED = "VERIFIED"
UNVERIFIED = "UNVERIFIED"
REJECTED = "REJECTED"


def _key(f: LinearForm) -> tuple:
    """Identity of a form, ignoring its human-readable label."""
    return (tuple(sorted(f.coeffs)), f.const)


def _read_constraints(certificate_dict: object) -> tuple[list[LinearForm], list[int]]:
    """Parse the constraint list, raising `ReplayError` with a located reason."""
    if not isinstance(certificate_dict, dict):
        raise ReplayError("malformed certificate: expected a JSON object")
    entries = certificate_dict.get("constraints")
    if not isinstance(entries, list) or not entries:
        raise ReplayError("malformed certificate: 'constraints' must be a non-empty list")

    forms: list[LinearForm] = []
    mults: list[int] = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            raise ReplayError(f"malformed constraint entry {i}: expected an object")
        try:
            forms.append(_parse_form(e["form"], e.get("label", "")))
            mults.append(_parse_multiplier(e["multiplier"]))
        except (KeyError, ValueError, TypeError) as exc:
            raise ReplayError(f"malformed constraint entry {i}: {exc}") from exc
    return forms, mults


def replay_bound(certificate_dict: dict) -> tuple[str, str]:
    """Re-check a certificate *and* that it proves the claim it names.

    Returns (status, explanation) where status is VERIFIED, UNVERIFIED or REJECTED.

    - REJECTED   -- the arithmetic does not check out, or the constraints are not
                    those of the claimed class.  The certificate is wrong.
    - UNVERIFIED -- the arithmetic checks out but no claim is bound, so there is
                    nothing to check it against.  Not a pass.
    - VERIFIED   -- the arithmetic checks out *and* the constraints are exactly the
                    canonical `corrected AND NOT safety` forms of the named class.
    """
    try:
        forms, mults = _read_constraints(certificate_dict)
        combined = verify(forms, mults)
    except ReplayError as exc:
        return REJECTED, str(exc)

    claim = certificate_dict.get("claim")
    if not isinstance(claim, dict) or not claim.get("defect_class"):
        return UNVERIFIED, (
            f"arithmetic replays: the listed inequalities combine to "
            f"{combined.render()}, a contradiction. But the certificate names no "
            f"defect class, so there is nothing to check those inequalities against: "
            f"this does NOT establish that any patch is complete. Re-issue with "
            f"'patchproof cert <CLASS>' to get a certificate bound to its claim."
        )

    key = claim["defect_class"]
    canonical = CANONICAL_FORMS.get(key)
    if canonical is None:
        return UNVERIFIED, (
            f"arithmetic replays, but defect class {key!r} has no canonical linear "
            f"form on this installation (known: {sorted(CANONICAL_FORMS)}), so the "
            f"constraints cannot be checked against the claim."
        )

    if sorted(map(_key, forms)) != sorted(map(_key, canonical)):
        got = "; ".join(f.render() for f in forms)
        want = "; ".join(f.render() for f in canonical)
        return REJECTED, (
            f"certificate claims defect class {key} but its constraints are not that "
            f"class's. got [{got}], expected [{want}]. A contradiction among other "
            f"inequalities proves nothing about this patch."
        )

    return VERIFIED, (
        f"replayed: combination is {combined.render()}, a contradiction; "
        f"constraints match the canonical corrected-AND-NOT-safety forms of class {key}"
    )
