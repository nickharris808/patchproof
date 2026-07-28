"""Modelled defect classes: a guard condition, a safety relation, and machine widths.

A *defect class* is a small, precise model of a bounds-check bug:

  - `fields`      the machine-width integer inputs, e.g. an index and a size;
  - `safety`      the relation that must hold for the operation to be safe;
  - `unsound`     the guard the buggy code actually applies, which admits inputs
                  that violate `safety`;
  - `corrected`   the candidate repair.

Three questions can then be asked, and they are genuinely different:

  1. **Is the bug real?**  Is there an input the unsound guard admits that violates
     safety?  (An *exploit witness*.)
  2. **Is the repair complete?**  Does the corrected guard admit *no* violating
     input at all — not merely not the one you found?
  3. **Is the repair vacuous?**  A guard that rejects everything is trivially
     complete and useless.  A non-vacuous repair still admits safe inputs, and is
     ideally *strictly stronger* than the unsound guard rather than unrelated to it.

Everything is modelled at declared machine widths using fixed-size bit-vectors, so
wrap-around is part of the model rather than an unmodelled surprise.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import z3


@dataclass(frozen=True)
class Field:
    """A machine-width unsigned integer input."""

    name: str
    width: int

    def __post_init__(self) -> None:
        if self.width <= 0:
            raise ValueError(f"field {self.name!r}: width must be positive")


@dataclass
class DefectClass:
    """A modelled class of bounds-check defect."""

    key: str
    title: str
    fields: list[Field]
    safety: Callable[[dict[str, z3.BitVecRef]], z3.BoolRef]
    unsound: Callable[[dict[str, z3.BitVecRef]], z3.BoolRef]
    corrected: Callable[[dict[str, z3.BitVecRef]], z3.BoolRef]
    note: str = ""
    out_of_model: list[str] = field(default_factory=list)

    @property
    def total_width(self) -> int:
        return sum(f.width for f in self.fields)

    def vars(self) -> dict[str, z3.BitVecRef]:
        return {f.name: z3.BitVec(f.name, f.width) for f in self.fields}


def _zext(x: z3.BitVecRef, by: int) -> z3.BitVecRef:
    return z3.ZeroExt(by, x)


# ---------------------------------------------------------------------------
# The three shipped classes.  They differ in the *shape* of the defect, which is
# why three rather than one are modelled.
# ---------------------------------------------------------------------------

def _class_a() -> DefectClass:
    """Off-by-one index against a size.

    The unsound guard admits `index <= size` (signed-difference style, `index - size
    <= 0`), which lets `index == size` through — one past the end.  Safety requires
    `index < size`.  The violating region has *measure one*: exactly one input per
    size value.
    """
    return DefectClass(
        key="A",
        title="off-by-one index against a size",
        fields=[Field("index", 16), Field("size", 16)],
        safety=lambda v: z3.ULT(v["index"], v["size"]),
        unsound=lambda v: z3.ULE(v["index"], v["size"]),
        corrected=lambda v: z3.ULT(v["index"], v["size"]),
        note="The classic `<=` where `<` was meant. Exactly one violating input per size.",
    )


def _class_b() -> DefectClass:
    """Payload length against a record length, with a dropped header allowance.

    Safety requires the payload to fit *after* the header: `payload + header <=
    record`.  The unsound guard forgets the header and checks `payload <= record`.
    The corrected guard reinstates it.  Widths are unequal (16 and 17) so the
    addition is done at a width that cannot wrap, which is itself part of the fix.
    """
    H = 8  # fixed header allowance

    def safety(v):
        p = _zext(v["payload"], 2)
        r = _zext(v["record"], 1)
        return z3.ULE(p + z3.BitVecVal(H, p.size()), r)

    def unsound(v):
        return z3.ULE(_zext(v["payload"], 1), v["record"])

    def corrected(v):
        p = _zext(v["payload"], 2)
        r = _zext(v["record"], 1)
        return z3.ULE(p + z3.BitVecVal(H, p.size()), r)

    return DefectClass(
        key="B",
        title="payload length against record length with a dropped header allowance",
        fields=[Field("payload", 16), Field("record", 17)],
        safety=safety,
        unsound=unsound,
        corrected=corrected,
        note="The corrected guard is strictly stronger than the unsound one, so the "
             "elimination is non-vacuous rather than trivially achieved.",
    )


def _class_c() -> DefectClass:
    """A bounded field missing its upper-bound test.

    A 5-bit selector must lie below a limit; the unsound guard tests only the lower
    bound.  The whole input space is 2^10, so the control is exhaustively
    enumerable and every claim about it can be cross-checked by brute force.
    """
    LIMIT = 20

    return DefectClass(
        key="C",
        title="bounded field missing an upper-bound test",
        fields=[Field("sel", 5), Field("base", 5)],
        safety=lambda v: z3.ULT(v["sel"], z3.BitVecVal(LIMIT, 5)),
        unsound=lambda v: z3.UGE(v["sel"], z3.BitVecVal(0, 5)),
        corrected=lambda v: z3.ULT(v["sel"], z3.BitVecVal(LIMIT, 5)),
        note="Total input space is 2^10, so results are cross-checked by exhaustive "
             "enumeration in the test suite.",
    )


def _class_a_badfix() -> DefectClass:
    """DEMO: a repair that blocks only the witness you happened to find.

    A developer sees the crash at `index == size` for one particular size, adds
    `index != 0x800`, and declares victory. Every other `index == size` still gets
    through. This is the single most common way a real patch is incomplete, and it
    is what `patchproof check` is for.
    """
    a = _class_a()
    return DefectClass(
        key="A-badfix",
        title="off-by-one 'fixed' by excluding one witness (DEMO: incomplete)",
        fields=a.fields,
        safety=a.safety,
        unsound=a.unsound,
        corrected=lambda v: z3.And(
            z3.ULE(v["index"], v["size"]), v["index"] != z3.BitVecVal(0x800, 16)
        ),
        note="Demonstration of an INCOMPLETE verdict: the patch blocks one input, "
             "not the class.",
    )


def _class_a_vacuous() -> DefectClass:
    """DEMO: a repair that rejects everything.

    Trivially complete — no violating input gets through because no input gets
    through — and completely useless. Completeness alone is not enough, which is
    why vacuity is checked separately.
    """
    a = _class_a()
    return DefectClass(
        key="A-vacuous",
        title="off-by-one 'fixed' by rejecting all input (DEMO: vacuous)",
        fields=a.fields,
        safety=a.safety,
        unsound=a.unsound,
        corrected=lambda v: z3.BoolVal(False),
        note="Demonstration of a VACUOUS verdict: complete, but the guard admits nothing.",
    )


CLASSES: dict[str, DefectClass] = {
    c.key: c
    for c in (_class_a(), _class_b(), _class_c(), _class_a_badfix(), _class_a_vacuous())
}

#: The three real defect classes, excluding the demonstration classes.
REAL_CLASSES = ("A", "B", "C")

# Defect shapes deliberately *outside* the model, recorded so that the scope of a
# COMPLETE verdict is stated rather than implied.
OUT_OF_MODEL = [
    ("Witnesses wider than the modelled fields (e.g. ~96-bit composite offsets): the "
     "class model fixes field widths, so a defect expressible only at a larger width "
     "is not represented."),
    ("Unsigned wrap-around arising from arithmetic performed *before* the guard is "
     "reached: the model begins at the guard, so a value already corrupted upstream is "
     "outside it."),
]
