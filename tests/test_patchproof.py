"""Tests for patchproof.

The suite is built around one idea: a tool that says COMPLETE for everything is
worthless, so most of these tests check that the tool says something *other* than
COMPLETE when it should.
"""

from __future__ import annotations

import itertools
import json

import pytest
import z3

from patchproof import CLASSES, REAL_CLASSES, find_exploit, prove, replay
from patchproof.cli import main
from patchproof.linear import LinearForm, ReplayError, _parse_form, find_certificate, verify
from patchproof.model import Field
from patchproof.prover import count_violating, elimination_forms

# ---------------------------------------------------------------------------
# The three real classes.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", REAL_CLASSES)
def test_real_classes_are_complete_and_non_vacuous(key):
    r = prove(key)
    assert r.verdict == "COMPLETE"
    assert r.vacuous is False
    assert r.strictly_stronger is True


@pytest.mark.parametrize("key", REAL_CLASSES)
def test_every_real_class_has_a_genuine_exploit(key):
    """If the unsound guard admits nothing bad, the class models no defect."""
    assert find_exploit(CLASSES[key]) is not None


@pytest.mark.parametrize("key", REAL_CLASSES)
def test_exploit_witness_really_violates_safety(key):
    """Re-evaluate the witness concretely; do not take the solver's word for it."""
    dc = CLASSES[key]
    w = find_exploit(dc)
    v = dc.vars()
    subst = {name: z3.BitVecVal(w.values[name], var.size()) for name, var in v.items()}
    assert z3.is_true(z3.simplify(dc.unsound(subst))), "witness not admitted by the guard"
    assert z3.is_false(z3.simplify(dc.safety(subst))), "witness does not violate safety"


@pytest.mark.parametrize("key", REAL_CLASSES)
def test_both_legs_agree(key):
    r = prove(key)
    assert r.legs_agree is True
    assert r.certificate is not None


# ---------------------------------------------------------------------------
# Discrimination: the tool must refuse bad patches.
# ---------------------------------------------------------------------------

def test_patch_that_blocks_only_the_known_witness_is_incomplete():
    r = prove("A-badfix")
    assert r.verdict == "INCOMPLETE"
    assert r.incompleteness_witness is not None
    vals = r.incompleteness_witness.values
    assert vals["index"] == vals["size"], "the surviving witness should be an index==size case"
    assert vals["index"] != 0x800, "should find a case other than the one the patch excluded"


def test_patch_that_rejects_everything_is_vacuous_not_complete():
    r = prove("A-vacuous")
    assert r.verdict == "VACUOUS"
    assert r.vacuous is True
    assert r.admits_example is None


def test_unknown_class_raises():
    with pytest.raises(KeyError):
        prove("nope")


def test_negative_width_rejected():
    with pytest.raises(ValueError):
        Field("x", 0)


# ---------------------------------------------------------------------------
# The elimination certificate, and its independent replay.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", REAL_CLASSES)
def test_certificate_replays_without_a_solver(key):
    r = prove(key)
    ok, msg = replay(r.certificate.to_dict())
    assert ok, msg


def test_replay_module_does_not_depend_on_z3():
    """The replay path is integer arithmetic; a sceptic should not need a solver.

    Checked by importing the module in a fresh interpreter and asserting that z3
    never entered `sys.modules` — an import-graph fact, not a text search.
    """
    import subprocess
    import sys

    code = (
        "import sys; import patchproof.linear as lin;"
        "cert=[lin.LinearForm.of({'x':1},-1),lin.LinearForm.of({'x':-1},2)];"
        "assert lin.verify(cert,[1,1]).const==1;"
        "print('z3' in sys.modules)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "False", "replay path pulled in a solver"


def test_tampered_multiplier_is_rejected():
    cert = prove("A").certificate.to_dict()
    cert["constraints"][0]["multiplier"] = 0
    ok, msg = replay(cert)
    assert not ok and "cancel" in msg


def test_negative_multiplier_is_rejected():
    forms = elimination_forms(CLASSES["A"])
    with pytest.raises(ReplayError, match="non-negative"):
        verify(forms, [1, -1])


def test_all_zero_multipliers_rejected():
    forms = elimination_forms(CLASSES["A"])
    with pytest.raises(ReplayError, match="empty"):
        verify(forms, [0, 0])


def test_multiplier_count_mismatch_rejected():
    forms = elimination_forms(CLASSES["A"])
    with pytest.raises(ReplayError, match="multipliers for"):
        verify(forms, [1])


def test_combination_without_contradiction_rejected():
    """Multipliers that cancel variables but leave a satisfiable constant must fail."""
    f = [LinearForm.of({"x": 1}, -5, "x <= 5"), LinearForm.of({"x": -1}, 0, "x >= 0")]
    with pytest.raises(ReplayError, match="satisfiable"):
        verify(f, [1, 1])


def test_no_certificate_for_a_feasible_system():
    f = [LinearForm.of({"x": 1}, -5), LinearForm.of({"x": -1}, 0)]
    assert find_certificate(f) is None


def test_malformed_certificate_rejected():
    ok, msg = replay({"nonsense": True})
    assert not ok and "malformed" in msg


def test_form_roundtrips_through_text():
    f = LinearForm.of({"index": 1, "size": -1}, 1)
    assert _parse_form(f.render()).as_dict == f.as_dict
    assert _parse_form(f.render()).const == f.const


def test_form_renders_constant_only_form():
    assert LinearForm.of({}, 1).render() == "1 <= 0"


# ---------------------------------------------------------------------------
# Cross-checks against brute force, where the space is small enough.
# ---------------------------------------------------------------------------

def test_class_c_violating_count_matches_exhaustive_enumeration():
    """Class C spans 2^10 inputs, so the model-counted answer can be checked directly."""
    dc = CLASSES["C"]
    LIMIT = 20
    brute = sum(
        1
        for sel, base in itertools.product(range(32), range(32))
        if sel >= 0 and not (sel < LIMIT)
    )
    assert count_violating(dc) == brute == 384


def test_class_c_corrected_guard_admits_nothing_violating_by_brute_force():
    dc = CLASSES["C"]
    for sel, base in itertools.product(range(32), range(32)):
        subst = {"sel": z3.BitVecVal(sel, 5), "base": z3.BitVecVal(base, 5)}
        admitted = z3.is_true(z3.simplify(dc.corrected(subst)))
        safe = z3.is_true(z3.simplify(dc.safety(subst)))
        assert not (admitted and not safe), f"corrected guard admits violating sel={sel}"


def test_class_a_violating_region_is_exactly_index_equals_size():
    """The Class A defect admits exactly one violating index per size value."""
    dc = CLASSES["A"]
    v = dc.vars()
    lhs = z3.And(dc.unsound(v), z3.Not(dc.safety(v)))
    rhs = v["index"] == v["size"]
    s = z3.Solver()
    s.add(lhs != rhs)
    assert s.check() == z3.unsat, "violating region is not exactly index == size"


def test_count_violating_declines_rather_than_guessing_on_large_spaces():
    assert count_violating(CLASSES["A"]) is None  # 2^32 inputs


# ---------------------------------------------------------------------------
# Reporting and CLI.
# ---------------------------------------------------------------------------

def test_result_dict_records_out_of_model_scope():
    d = prove("A").to_dict()
    assert d["out_of_model"], "a COMPLETE verdict must state what it does not cover"
    assert d["verdict"] == "COMPLETE"


def test_cli_check_exit_codes():
    assert main(["check", "A", "--json"]) == 0
    assert main(["check", "A-badfix", "--json"]) == 1


def test_cli_classes_lists_everything(capsys):
    assert main(["classes"]) == 0
    out = capsys.readouterr().out
    for k in CLASSES:
        assert k in out


def test_cli_cert_and_replay_roundtrip(tmp_path, capsys):
    p = tmp_path / "c.json"
    assert main(["cert", "B", "-o", str(p)]) == 0
    assert main(["replay", str(p)]) == 0
    assert "VERIFIED" in capsys.readouterr().out


def test_cli_replay_rejects_tampered_file(tmp_path):
    p = tmp_path / "c.json"
    main(["cert", "B", "-o", str(p)])
    cert = json.loads(p.read_text())
    cert["constraints"][1]["multiplier"] = 3
    p.write_text(json.dumps(cert))
    assert main(["replay", str(p)]) == 1


def test_disagreeing_legs_are_reported_as_a_discrepancy():
    """The README promises a DISCREPANCY when the two legs disagree. Prove it fires.

    Constructed by giving a class the *unsound* guard as its "correction": the
    bit-precise leg correctly finds a surviving violating input, while the linear
    reading in `elimination_forms` still describes the genuine Class A repair and
    so produces a certificate. The two must not be silently reconciled.
    """
    from patchproof.model import DefectClass, Field
    from patchproof.prover import prove as prove_dc

    forced = DefectClass(
        key="A",                                   # reuses Class A's linear reading
        title="forced-disagreement probe",
        fields=[Field("index", 16), Field("size", 16)],
        safety=lambda v: z3.ULT(v["index"], v["size"]),
        unsound=lambda v: z3.ULE(v["index"], v["size"]),
        corrected=lambda v: z3.ULE(v["index"], v["size"]),   # not a fix at all
    )
    r = prove_dc(forced)
    assert r.legs_agree is False
    assert r.verdict == "INCOMPLETE"
    assert any("DISCREPANCY" in n for n in r.notes)
    assert any("do not rely on either" in n for n in r.notes)


def test_agreeing_legs_do_not_report_a_discrepancy():
    for key in REAL_CLASSES:
        r = prove(key)
        assert not any("DISCREPANCY" in n for n in r.notes)


def test_class_without_a_linear_reading_skips_the_elimination_leg():
    """An unknown class must skip the leg and say so, not fake a certificate."""
    from patchproof.model import DefectClass, Field
    from patchproof.prover import elimination_forms
    from patchproof.prover import prove as prove_dc

    custom = DefectClass(
        key="custom-nonlinear",
        title="user-supplied class with no hand-checked linear reading",
        fields=[Field("x", 8)],
        safety=lambda v: z3.ULT(v["x"], z3.BitVecVal(200, 8)),
        unsound=lambda v: z3.BoolVal(True),
        corrected=lambda v: z3.ULT(v["x"], z3.BitVecVal(200, 8)),
    )
    assert elimination_forms(custom) is None
    r = prove_dc(custom)
    assert r.certificate is None
    assert r.legs_agree is None
    assert any("skipped" in n for n in r.notes)
    assert r.verdict == "COMPLETE"          # bit-precise leg alone still decides
