"""Farkas-style elimination certificates that a checker replays without a solver.

A solver saying "unsatisfiable" is an assertion. A *certificate* is an object a
third party can re-check independently, and for a conjunction of linear
inequalities over the integers that object is a vector of non-negative multipliers.

Represent every constraint in the normal form

    sum_i (c_i * x_i) + k  <=  0

Farkas' lemma (the affine form): if there are non-negative multipliers `lambda_j`
such that the combination `sum_j lambda_j * form_j` has **every variable
coefficient zero** and a **strictly positive constant**, then the system is
infeasible — because the combination asserts `positive <= 0`.

The multipliers are the whole certificate. Replaying them is integer arithmetic:
multiply, add, check the coefficients cancel, check the constant is positive. No
solver is involved in the replay, which is the point — `verify()` below does not
import z3 at all.

Strict inequalities over the integers are tightened on the way in: `e < 0` becomes
`e + 1 <= 0`.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class LinearForm:
    """`sum(coeffs[v] * v) + const <= 0` over the integers."""

    coeffs: tuple[tuple[str, int], ...] = ()
    const: int = 0
    label: str = ""

    @staticmethod
    def of(coeffs: dict[str, int], const: int = 0, label: str = "") -> LinearForm:
        items = tuple(sorted((v, c) for v, c in coeffs.items() if c != 0))
        return LinearForm(items, const, label)

    @property
    def as_dict(self) -> dict[str, int]:
        return dict(self.coeffs)

    def scale(self, k: int) -> LinearForm:
        if k < 0:
            raise ValueError("Farkas multipliers must be non-negative")
        return LinearForm.of({v: c * k for v, c in self.coeffs}, self.const * k)

    def __add__(self, other: LinearForm) -> LinearForm:
        merged = self.as_dict
        for v, c in other.coeffs:
            merged[v] = merged.get(v, 0) + c
        return LinearForm.of(merged, self.const + other.const)

    def render(self) -> str:
        parts = []
        for v, c in self.coeffs:
            sign = "+" if c > 0 else "-"
            mag = abs(c)
            parts.append(f"{sign} {v}" if mag == 1 else f"{sign} {mag}*{v}")
        body = " ".join(parts).lstrip("+ ").strip()
        if not body:
            return f"{self.const} <= 0"
        if self.const:
            body += f" {'+' if self.const > 0 else '-'} {abs(self.const)}"
        return f"{body} <= 0"


@dataclass
class Certificate:
    """A replayable proof that a conjunction of linear forms is infeasible."""

    forms: list[LinearForm]
    multipliers: list[int]
    combined: LinearForm = field(default_factory=LinearForm)
    # What this certificate purports to prove: {"defect_class": ..., "widths": {...}}.
    # Without it a verifier can confirm the arithmetic but not that the constraints
    # are the ones belonging to any patch -- see `claims.replay_bound`.
    claim: dict | None = None

    def to_dict(self) -> dict:
        return {
            "kind": "farkas-elimination",
            "claim": self.claim,
            "constraints": [
                {"label": f.label, "form": f.render(), "multiplier": m}
                for f, m in zip(self.forms, self.multipliers, strict=True)
            ],
            "combination": self.combined.render(),
            "contradiction": (
                f"the combination has no variable terms and asserts "
                f"{self.combined.const} <= 0, which is false"
            ),
        }


class ReplayError(Exception):
    """Raised when a certificate does not check out."""


def verify(forms: list[LinearForm], multipliers: list[int]) -> LinearForm:
    """Independently replay a certificate. Pure integer arithmetic, no solver.

    Returns the combined form on success; raises `ReplayError` otherwise.
    """
    if len(forms) != len(multipliers):
        raise ReplayError(
            f"certificate has {len(multipliers)} multipliers for {len(forms)} constraints"
        )
    if not any(m > 0 for m in multipliers):
        raise ReplayError("certificate is empty: every multiplier is zero")
    if any(m < 0 for m in multipliers):
        raise ReplayError("negative multiplier: Farkas requires non-negative multipliers")

    combined = LinearForm()
    for f, m in zip(forms, multipliers, strict=True):
        if m:
            combined = combined + f.scale(m)

    if combined.coeffs:
        surviving = ", ".join(f"{v}({c})" for v, c in combined.coeffs)
        raise ReplayError(f"variables did not cancel: {surviving}")
    if combined.const <= 0:
        raise ReplayError(
            f"combination yields {combined.const} <= 0, which is satisfiable; no contradiction"
        )
    return combined


def find_certificate(forms: list[LinearForm], max_multiplier: int = 4) -> Certificate | None:
    """Search for non-negative multipliers witnessing infeasibility.

    Complete only up to `max_multiplier`; returning `None` means "no certificate
    found within the search bound", never "the system is feasible". Callers must
    not read a `None` as a satisfiability claim.
    """
    n = len(forms)
    if n == 0:
        return None
    for combo in itertools.product(range(max_multiplier + 1), repeat=n):
        if not any(combo):
            continue
        try:
            combined = verify(forms, list(combo))
        except ReplayError:
            continue
        return Certificate(forms=list(forms), multipliers=list(combo), combined=combined)
    return None


def replay(certificate_dict: dict) -> tuple[bool, str]:
    """Re-check a serialised certificate using integer arithmetic only.

    This is what a sceptical third party runs. It deliberately does not use z3.
    """
    try:
        entries = certificate_dict["constraints"]
    except (KeyError, TypeError):
        return False, "malformed certificate: no 'constraints'"
    if not isinstance(entries, list) or not entries:
        return False, "malformed certificate: 'constraints' must be a non-empty list"
    forms, mults = [], []
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            return False, f"malformed constraint entry {i}: expected an object"
        try:
            forms.append(_parse_form(e["form"], e.get("label", "")))
            mults.append(_parse_multiplier(e["multiplier"]))
        except (KeyError, ValueError, TypeError) as exc:
            return False, f"malformed constraint entry {i}: {exc}"
    try:
        combined = verify(forms, mults)
    except ReplayError as exc:
        return False, str(exc)
    return True, f"replayed: combination is {combined.render()}, a contradiction"


def _parse_multiplier(value: object) -> int:
    """A Farkas multiplier, or a refusal.

    `int(1.5)` silently truncates to 1, which changes the certificate being checked
    into a different one that happens to verify.  A multiplier that is not already
    an integer is rejected rather than rounded.
    """
    if isinstance(value, bool):
        raise ValueError(f"multiplier must be an integer, got boolean {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise ValueError(
            f"multiplier must be an integer, got float {value!r} "
            f"(truncating it would silently check a different certificate)"
        )
    if isinstance(value, str):
        raise ValueError(f"multiplier must be an integer, got string {value!r}")
    raise ValueError(f"multiplier must be an integer, got {type(value).__name__}")


# One signed term: optional sign, optional integer coefficient, then a variable or
# an integer.  Anchored and consumed end-to-end by `_parse_form` -- a scan that
# merely *finds* terms silently ignores whatever it cannot match, which is how
# `@@@ <= 0` used to parse as the perfectly valid form `0 <= 0`.
_TERM = re.compile(r"\s*([+-])?\s*(?:(\d+)\s*\*\s*)?([A-Za-z_]\w*|\d+)\s*")


def _parse_form(text: str, label: str = "") -> LinearForm:
    """Parse `a - 2*b + 3 <= 0` back into a LinearForm.

    Strict by construction.  Every character must be consumed by a term; anything
    left over raises.  This function is the trust boundary of the whole package --
    it reads a certificate supplied by whoever wants a claim believed -- so
    unparseable text must never be coerced into a well-formed form.
    """
    if not isinstance(text, str):
        raise ValueError(f"form must be a string, got {type(text).__name__}")
    if text.count("<=") != 1:
        raise ValueError(
            f"unparseable form {text!r}: expected exactly one '<=' relation"
        )
    body, rhs = text.split("<=", 1)
    if rhs.strip() != "0":
        raise ValueError(
            f"unparseable form {text!r}: right-hand side must be exactly 0, got {rhs.strip()!r}"
        )
    body = body.strip()
    if not body:
        raise ValueError(f"unparseable form {text!r}: empty left-hand side")

    coeffs: dict[str, int] = {}
    const = 0
    pos = 0
    first = True
    while pos < len(body):
        m = _TERM.match(body, pos)
        if not m or m.end() == pos:
            raise ValueError(
                f"unparseable form {text!r}: cannot read a term at offset {pos} "
                f"({body[pos:pos + 12]!r})"
            )
        sign_tok, mag_tok, tok = m.group(1), m.group(2), m.group(3)
        # Only the leading term may omit its sign; `x y` and `x ++ y` are errors.
        if sign_tok is None and not first:
            raise ValueError(
                f"unparseable form {text!r}: missing '+' or '-' before {tok!r}"
            )
        sign = -1 if sign_tok == "-" else 1
        mag = int(mag_tok) if mag_tok else 1
        if tok.isdigit():
            if mag_tok:
                raise ValueError(
                    f"unparseable form {text!r}: {mag_tok}*{tok} is not a linear term"
                )
            const += sign * int(tok)
        else:
            coeffs[tok] = coeffs.get(tok, 0) + sign * mag
        pos = m.end()
        first = False
    return LinearForm.of(coeffs, const, label)
