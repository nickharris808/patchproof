"""The three questions patchproof answers about a patch.

1. `find_exploit`  — is there an input the unsound guard admits that violates safety?
2. `check_complete` — does the corrected guard admit *no* violating input at all?
3. `check_vacuity`  — is the corrected guard still useful, or does it reject everything?

Completeness is discharged on **two independent legs**:

* the **bit-precise leg**, at the declared machine widths, using fixed-size
  bit-vectors, so wrap-around is inside the model rather than assumed away;
* the **elimination leg**, over the integers, producing Farkas multipliers that a
  checker replays with integer arithmetic and no solver.

Two legs that agree is worth more than one leg twice. When they disagree, that is
reported as a discrepancy rather than resolved silently — a disagreement usually
means the integer model and the machine model genuinely differ, which is exactly
the kind of thing that ships a bug.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

from .linear import Certificate, LinearForm, find_certificate, replay
from .model import CLASSES, OUT_OF_MODEL, DefectClass


@dataclass
class Witness:
    """A concrete input that the guard admits and that violates safety."""

    values: dict[str, int]

    def render(self) -> str:
        return ", ".join(f"{k}=0x{v:X}" for k, v in sorted(self.values.items()))


@dataclass
class Result:
    defect_class: str
    title: str
    widths: dict[str, int]
    total_width: int
    exploit: Witness | None = None
    complete: bool = False
    incompleteness_witness: Witness | None = None
    certificate: Certificate | None = None
    legs_agree: bool | None = None
    vacuous: bool = False
    strictly_stronger: bool | None = None
    admits_example: Witness | None = None
    violating_measure: int | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if not self.complete:
            return "INCOMPLETE"
        if self.vacuous:
            return "VACUOUS"
        return "COMPLETE"

    def to_dict(self) -> dict:
        return {
            "class": self.defect_class,
            "title": self.title,
            "verdict": self.verdict,
            "widths": self.widths,
            "total_width": self.total_width,
            "exploit_witness": self.exploit.values if self.exploit else None,
            "incompleteness_witness": (
                self.incompleteness_witness.values if self.incompleteness_witness else None
            ),
            "bit_precise_leg": self.complete,
            "elimination_leg": self.certificate.to_dict() if self.certificate else None,
            "legs_agree": self.legs_agree,
            "non_vacuous": not self.vacuous,
            "strictly_stronger_than_unsound_guard": self.strictly_stronger,
            "violating_region_measure": self.violating_measure,
            "out_of_model": OUT_OF_MODEL,
            "notes": self.notes,
        }


def _model_values(m: z3.ModelRef, v: dict[str, z3.BitVecRef]) -> dict[str, int]:
    return {name: m.eval(var, model_completion=True).as_long() for name, var in v.items()}


def _solve(*constraints: z3.BoolRef) -> z3.ModelRef | None:
    s = z3.Solver()
    s.add(*constraints)
    return s.model() if s.check() == z3.sat else None


def find_exploit(dc: DefectClass) -> Witness | None:
    """An input the *unsound* guard admits that violates safety."""
    v = dc.vars()
    m = _solve(dc.unsound(v), z3.Not(dc.safety(v)))
    return Witness(_model_values(m, v)) if m is not None else None


def check_complete_bitprecise(dc: DefectClass) -> tuple[bool, Witness | None]:
    """Bit-precise leg: is `corrected AND NOT safety` unsatisfiable at declared widths?"""
    v = dc.vars()
    m = _solve(dc.corrected(v), z3.Not(dc.safety(v)))
    if m is None:
        return True, None
    return False, Witness(_model_values(m, v))


def check_vacuity(dc: DefectClass) -> tuple[bool, Witness | None, bool | None]:
    """Is the corrected guard still useful?

    Returns (vacuous, an admitted safe input, strictly-stronger-than-unsound).
    A guard that rejects everything is trivially complete and worthless.
    """
    v = dc.vars()
    m = _solve(dc.corrected(v), dc.safety(v))
    if m is None:
        return True, None, None
    admits = Witness(_model_values(m, v))

    # strictly stronger: corrected => unsound is valid, and some input separates them
    implies = _solve(dc.corrected(v), z3.Not(dc.unsound(v))) is None
    separates = _solve(dc.unsound(v), z3.Not(dc.corrected(v))) is not None
    return False, admits, bool(implies and separates)


def count_violating(dc: DefectClass, limit: int = 1 << 22) -> int | None:
    """Exact count of inputs the *unsound* guard admits that violate safety.

    Only attempted when the whole input space is small enough to enumerate by
    model counting; returns None otherwise rather than guessing.
    """
    if dc.total_width > 22 or (1 << dc.total_width) > limit:
        return None
    v = dc.vars()
    s = z3.Solver()
    s.add(dc.unsound(v), z3.Not(dc.safety(v)))
    n = 0
    while s.check() == z3.sat:
        m = s.model()
        vals = _model_values(m, v)
        n += 1
        s.add(z3.Or(*[var != vals[name] for name, var in v.items()]))
    return n


# ---------------------------------------------------------------------------
# The elimination leg.
# ---------------------------------------------------------------------------

def elimination_forms(dc: DefectClass) -> list[LinearForm] | None:
    """Linear normal forms of `corrected AND NOT safety` for the shipped classes.

    Returned as integer inequalities `expr <= 0`; strict `<` is tightened to
    `expr + 1 <= 0`. Only the shipped classes have a hand-checked linear reading;
    a user-supplied class returns None and the elimination leg is skipped rather
    than faked.
    """
    if dc.key == "A":
        # corrected: index < size            ->  index - size + 1 <= 0
        # not safety: index >= size          ->  size - index     <= 0
        return [
            LinearForm.of({"index": 1, "size": -1}, 1, "corrected: index < size"),
            LinearForm.of({"size": 1, "index": -1}, 0, "not safety: index >= size"),
        ]
    if dc.key == "B":
        # corrected: payload + 8 <= record   ->  payload - record + 8 <= 0
        # not safety: payload + 8 > record   ->  record - payload - 7 <= 0
        return [
            LinearForm.of({"payload": 1, "record": -1}, 8, "corrected: payload + 8 <= record"),
            LinearForm.of({"record": 1, "payload": -1}, -7, "not safety: payload + 8 > record"),
        ]
    if dc.key == "C":
        # corrected: sel < 20                ->  sel - 19 <= 0
        # not safety: sel >= 20              ->  20 - sel <= 0
        return [
            LinearForm.of({"sel": 1}, -19, "corrected: sel < 20"),
            LinearForm.of({"sel": -1}, 20, "not safety: sel >= 20"),
        ]
    return None


def prove(dc: DefectClass | str) -> Result:
    """Run all three questions and both completeness legs over one defect class."""
    if isinstance(dc, str):
        if dc not in CLASSES:
            raise KeyError(f"unknown defect class {dc!r}; have {sorted(CLASSES)}")
        dc = CLASSES[dc]

    r = Result(
        defect_class=dc.key,
        title=dc.title,
        widths={f.name: f.width for f in dc.fields},
        total_width=dc.total_width,
    )
    if dc.note:
        r.notes.append(dc.note)

    r.exploit = find_exploit(dc)
    if r.exploit is None:
        r.notes.append(
            "The unsound guard admits no violating input in this model, so there is "
            "nothing for the repair to eliminate."
        )

    r.complete, r.incompleteness_witness = check_complete_bitprecise(dc)
    r.vacuous, r.admits_example, r.strictly_stronger = check_vacuity(dc)
    r.violating_measure = count_violating(dc)

    forms = elimination_forms(dc)
    if forms is None:
        r.notes.append(
            "No hand-checked linear reading for this class; the elimination leg was "
            "skipped and completeness rests on the bit-precise leg alone."
        )
        r.legs_agree = None
    else:
        r.certificate = find_certificate(forms)
        if r.certificate is not None:
            # Bind the certificate to what it proves, so a third party can check the
            # constraints are this class's rather than merely self-consistent.
            r.certificate.claim = {
                "defect_class": dc.key,
                "widths": {f.name: f.width for f in dc.fields},
                "proves": "every violating input is eliminated by the corrected guard",
            }
        elim_says_complete = r.certificate is not None
        r.legs_agree = elim_says_complete == r.complete
        if not r.legs_agree:
            r.notes.append(
                f"DISCREPANCY: bit-precise leg says complete={r.complete} but the "
                f"elimination leg says complete={elim_says_complete}. The integer model "
                "and the machine model disagree; do not rely on either until resolved."
            )
    return r


__all__ = [n for n in dir() if not n.startswith("_")] + ["replay"]
