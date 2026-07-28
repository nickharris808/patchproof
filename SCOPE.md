# Honest scope — what a patchproof verdict does and does not mean

---

## The claim, stated precisely

A `COMPLETE` verdict says:

> For the named defect class, at the declared machine widths, there is no input
> satisfying `corrected_guard AND NOT safety` — established twice over, once with
> fixed-size bit-vectors and once as a Farkas elimination certificate over the
> integers, with the two legs cross-checked against each other.

## What it proves

- **Every violating input in the modelled class is eliminated**, not merely the
  witness you happened to find. This is the question a fuzzer structurally cannot
  answer: a fuzzer reports what it found, never what does not exist.
- **The fix is not vacuous.** A guard that rejects everything is trivially complete
  and useless; `check_vacuity` reports whether the corrected guard is *strictly
  stronger* than the original rather than simply stricter than reality.
- **The proof is independently checkable.** The elimination certificate is a list of
  non-negative integer multipliers. Replaying it is multiply, add, check the
  variables cancel, check the constant is positive — no solver, no trust.

## What it does **not** prove

- **It is not a control-flow-hijack or RCE claim**, and it targets no live system.
  The verdict concerns reachability of a violation in modelled bit semantics.
- **It says nothing about your codebase.** A class models a *guard*. Getting from
  real C to a faithful class model is on you, and it is the step where mistakes
  actually happen. A `COMPLETE` verdict about a model that does not match your code
  is a true statement about the wrong thing.
- **Two defect shapes are deliberately outside the model**, and the tool prints them
  on every run: witnesses wider than the modelled fields (e.g. ~96-bit composite
  offsets), and wrap-around arising from arithmetic performed *before* the guard is
  reached.
- **`find_certificate` searches multipliers up to a bound.** Returning no certificate
  means "none found within the bound", never "the system is satisfiable".

---

## What a certificate is, and is not

This is the subtlest part of the tool, and the easiest to over-read.

`verify` answers exactly one question: *do these inequalities, with these
multipliers, combine to a contradiction?* That is arithmetic, and it is genuinely
checkable without a solver.

It is **not** the question a reader cares about. A certificate consisting of the
single form `5 <= 0` answers it perfectly — `5 <= 0` is false, so any system
containing it is trivially infeasible — while saying nothing whatever about
anybody's patch.

So a certificate carries a `claim` block naming its defect class and field widths,
and `replay_bound` checks the constraints against a canonical statement of that
class **held by the verifier**, not supplied with the proof. Three outcomes:

| Status | Meaning | Exit |
|---|---|---|
| `VERIFIED` | arithmetic replays **and** the constraints are that class's | 0 |
| `UNVERIFIED` | arithmetic replays, but no claim is bound — nothing to check it against. **Not a pass.** | 1 |
| `REJECTED` | the arithmetic fails, or the constraints are not the claimed class's | 1 |

A class A certificate relabelled as class C is `REJECTED`.

The form parser is strict for the same reason: it must consume the entire string, so
`@@@ <= 0` is rejected rather than read as the well-formed `0 <= 0`, and a
non-integer multiplier is refused rather than truncated into a different certificate.

---

## When the two legs disagree

Completeness is discharged twice: bit-precise at the declared widths, and by linear
elimination over the integers. If they disagree, patchproof reports a `DISCREPANCY`
and tells you not to rely on either until it is resolved. A disagreement means the
integer model and the machine model genuinely differ, which is exactly the kind of
thing that ships a bug.

---

## Proving this to someone who cannot see your code

patchproof analyses guards **you hand it**. Proving to a third party that a violating
input exists — or that your fix eliminates all of them — *without revealing the input
or the code* is a zero-knowledge problem, is not what this package does, and is a
commercial capability.

---

## Sibling tools

- [`ctbench`](https://github.com/nickharris808/ctbench) — constant-time RTL.
- [`ct-mask`](https://github.com/nickharris808/ct-mask) — masking countermeasures.
- [`hw-verify-mcp`](https://github.com/nickharris808/hw-verify-mcp) — all three for agents.
- [Live demo](https://huggingface.co/spaces/nickh007/hw-verify).
