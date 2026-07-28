# Contributing to patchproof

## The most valuable contribution: a new defect class

A defect class is four things — the machine-width `fields`, the `safety` relation,
the `unsound` guard that admits violations, and the `corrected` repair. Add one in
`patchproof/model.py` and it gets all three questions for free.

A class is only worth shipping if **the unsound guard genuinely admits a violating
input**. The test suite enforces this: a class whose `find_exploit` returns `None`
models no defect at all. Please also add the class to `REAL_CLASSES` only if it is
a real defect shape — the `A-badfix` and `A-vacuous` entries are demonstrations of
failing verdicts and are deliberately excluded from the default run.

## The elimination leg

If your class has a linear reading over the integers, add it to `elimination_forms`
in `patchproof/prover.py` so completeness is discharged on both legs. **Do not
invent forms you have not checked by hand** — a wrong linear reading that happens
to produce a certificate is worse than no certificate. If the legs disagree, the
tool reports a discrepancy, and that report is the feature.

If your class has no linear reading, leave it out. The tool skips the leg and says
so rather than faking it.

## Keeping the verifier solver-free

`patchproof/linear.py` must never import z3, directly or transitively. Verifying
somebody else's certificate has to be possible without installing a solver, because
that is the entire point of shipping a certificate rather than a verdict. A test
enforces this by importing the module in a fresh interpreter and checking that z3
never reaches `sys.modules`.

## Scope

Keep `OUT_OF_MODEL` honest. If your class cannot represent a defect shape, say so
there. A `COMPLETE` verdict is only as good as the stated scope, and overclaiming
here is the one thing that would make this tool worse than useless.

## Style

`ruff check .` clean, 100-column lines, `python -m pytest tests -q` green.
