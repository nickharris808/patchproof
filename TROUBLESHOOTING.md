# Troubleshooting

---

## `UNVERIFIED  arithmetic replays: ... But the certificate names no defect class`

The inequalities really do combine to a contradiction, but nothing ties them to a
patch, so the replay establishes nothing about completeness. **This is not a pass**
and it exits 1.

**Fix:** re-issue the certificate with `patchproof cert <CLASS>`, which attaches the
`claim` block. A hand-written certificate, or one produced before claim binding
existed, will always be `UNVERIFIED`.

## `REJECTED  certificate claims defect class A but its constraints are not that class's`

The certificate was relabelled, or its constraints were edited. The verifier compares
them against its own canonical statement of the class, so editing the constraints to
match a different claim does not work either.

## `REJECTED  malformed constraint entry 0: unparseable form '@@@ <= 0'`

The parser must consume the whole form. This is deliberate: a scanner that skips what
it cannot match turns `@@@ <= 0` into the perfectly valid `0 <= 0`, and a certificate
of nonsense then verifies.

Valid forms look like `index - size + 1 <= 0` — signed integer terms, optional
integer coefficients (`2*a`), a single `<=`, right-hand side exactly `0`.

## `REJECTED  malformed constraint entry 0: multiplier must be an integer, got float 1.5`

`int(1.5)` is `1`, so accepting it would silently check a *different* certificate
from the one supplied. Multipliers are non-negative integers.

## `REJECTED  variables did not cancel: index(-1), size(1)`

The multipliers do not eliminate every variable, so the combination is not a
contradiction. Usually means a multiplier was edited, or the wrong ones were paired
with the forms.

## `[INCOMPLETE] the corrected guard STILL admits a violating input`

Working as intended: your patch does not cover the class. The witness printed is a
concrete input that gets through. Fix the guard and re-run.

## `[VACUOUS] the corrected guard rejects every input, safe ones included`

Trivially complete and useless. The guard needs to be stronger than the original
without rejecting valid inputs.

## `DISCREPANCY: bit-precise leg says complete=... but the elimination leg says ...`

The integer model and the machine model disagree. Do not rely on either verdict until
it is resolved — this is exactly the situation that ships a bug.

## `no elimination certificate for class X`

Only the shipped classes have a hand-checked linear reading. A user-supplied class
returns `None` from `elimination_forms` and the elimination leg is skipped rather
than faked; completeness then rests on the bit-precise leg alone, and the run says so.

## `ImportError: no module named z3`

The proving half needs z3; the *verification* half deliberately does not.
`patchproof.linear` and `patchproof.claims` never import it, and a test enforces that
by importing them in a fresh interpreter and asserting no solver reaches
`sys.modules`. If you only need to replay certificates, you never need z3.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | `COMPLETE` (for `check`) or `VERIFIED` (for `replay`) |
| `1` | anything else — including `UNVERIFIED`, which is not a pass |

---

See [SCOPE.md](SCOPE.md) for what a verdict means.
