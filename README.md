# patchproof

**Your patch stops the bug you saw. This proves it stops every input in the class — and if it doesn't, it hands you one that still gets through.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Verifier](https://img.shields.io/badge/verifier-solver--free-green.svg)](#verify-without-trusting-us)
[![CI](https://github.com/nickharris808/patchproof/actions/workflows/ci.yml/badge.svg)](https://github.com/nickharris808/patchproof/actions/workflows/ci.yml)

> **▶ [Try it in your browser](https://huggingface.co/spaces/nickh007/hw-verify)** — paste Verilog, get a formal constant-time verdict with the leaking signals named. No install, nothing uploaded.


## Why this exists

You get a crash report, you find the off-by-one, you add a check, the crash goes away,
you close the ticket. Nothing you did answered the actual question: **is there another
input that still gets through?**

The usual answer is a fuzzer, which can only ever tell you it didn't find one. patchproof
answers the other way round — it tries to prove that *no* violating input survives the
corrected guard, at the declared machine widths. When it can't, it gives you the surviving
input. When it can, it emits a certificate a third party re-checks **without running a
solver at all**.

It also catches the two ways a "complete" fix is worthless:

- **Incomplete** — the patch blocks the witness you found, not the class. (`index != 0x800`
  when every `index == size` is still a bug.)
- **Vacuous** — the patch rejects everything. Trivially complete, completely useless.

## Install

> **Not yet on PyPI.** Install from a checkout:

```bash
git clone https://github.com/nickharris808/patchproof.git && cd patchproof
pip install .
```

Once published, this becomes `pip install patchproof`.

## 30-second quickstart

```bash
patchproof check          # run the three modelled defect classes
patchproof classes        # list them
patchproof cert A -o a.json && patchproof replay a.json    # emit and re-check a certificate
```

## Worked example

```console
$ patchproof check A
class A — off-by-one index against a size
====================================================================
  widths            index:16, size:16  (total 32)
  exploit witness   index=0x800, size=0x800
                    (an input the ORIGINAL guard admits that violates safety)

  [COMPLETE] every violating input is eliminated.
    bit-precise leg   discharged at declared widths (total 32 bits)
    elimination leg   multipliers [1, 1], replayed without a solver
      x1  index - size + 1 <= 0    [corrected: index < size]
      x1  - index + size <= 0    [not safety: index >= size]
      = 1 <= 0   <- contradiction
    legs agree        True
    non-vacuous       corrected guard is STRICTLY STRONGER than the original
```

That last block is the part no other tool prints. The two constraints, each multiplied by
1 and added, cancel every variable and assert `1 <= 0`. That is the proof, and it is four
integers wide.

### When the patch is not actually complete

```console
$ patchproof check A-badfix
class A-badfix — off-by-one 'fixed' by excluding one witness (DEMO: incomplete)
====================================================================
  widths            index:16, size:16  (total 32)
  exploit witness   index=0x800, size=0x800
                    (an input the ORIGINAL guard admits that violates safety)

  [INCOMPLETE] the corrected guard STILL admits a violating input:
               index=0xC92, size=0xC92
```

Exit status is `0` only for `COMPLETE`, so this drops straight into CI.

## Verify without trusting us

A solver saying "unsatisfiable" is an assertion. A certificate is an object you can
re-check yourself:

```console
$ patchproof replay a.json
VERIFIED   replayed: combination is 1 <= 0, a contradiction; constraints match the
           canonical corrected-AND-NOT-safety forms of class A

$ # flip one multiplier and try again
$ patchproof replay tampered.json
REJECTED   variables did not cancel: index(-1), size(1)
```

### Why the arithmetic alone is not enough

There are two questions here, and only one of them is arithmetic:

1. *Do these inequalities, with these multipliers, combine to a contradiction?*
2. *Are these the inequalities of the patch being claimed?*

A certificate consisting of the single form `5 <= 0` answers (1) perfectly — `5 <= 0` is
false, so any system containing it is trivially infeasible — while saying nothing whatever
about anybody's patch. Checking (1) and reporting `VERIFIED` would be certifying a claim
nobody established.

So an emitted certificate carries a `claim` block naming its defect class and field
widths, and `replay` checks the constraints against a canonical statement of that class
held by the verifier — not supplied with the proof. Three outcomes:

| Status | Meaning |
|---|---|
| `VERIFIED` | arithmetic replays **and** the constraints are that class's. Exit 0. |
| `UNVERIFIED` | arithmetic replays, but no claim is bound — nothing to check it against. **Not a pass.** Exit 1. |
| `REJECTED` | the arithmetic fails, or the constraints are not the claimed class's. Exit 1. |

A class A certificate relabelled as class C is `REJECTED`, not verified.

`patchproof.linear` and `patchproof.claims` — the modules that do this — **never import
z3**, directly or transitively. Replaying a certificate is multiply, add, check the
variables cancel, check the constant is positive, and check the constraints are the ones
the claim names. The form parser is strict: it must consume the whole string, so `@@@ <= 0`
is rejected rather than read as the well-formed `0 <= 0`, and a non-integer multiplier is
refused rather than silently truncated into a different certificate. A test enforces the property by importing the module in a fresh
interpreter and asserting a solver never reaches `sys.modules`.

```python
from patchproof.claims import replay_bound   # no solver required
status, why = replay_bound(json.load(open("a.json")))   # VERIFIED / UNVERIFIED / REJECTED
```

## The three modelled classes

| Class | Defect | Fields | Total width |
|---|---|---|---|
| **A** | off-by-one index against a size | `index:16`, `size:16` | 32 |
| **B** | payload vs record length, dropped header allowance | `payload:16`, `record:17` | 33 |
| **C** | bounded field missing an upper-bound test | `sel:5`, `base:5` | 10 |

They differ in the *shape* of the defect, which is why three rather than one are modelled.
Class A's violating region is exactly `index == size` — proved, not asserted. Class B's
corrected guard is *strictly stronger* than the unsound one, so its elimination is
non-vacuous rather than trivially achieved. Class C spans 2^10 inputs, small enough that
the test suite cross-checks every claim by exhaustive enumeration — 384 violating inputs,
counted two independent ways.

## Two legs, and what happens when they disagree

Completeness is discharged twice over:

- the **bit-precise leg** — fixed-size bit-vectors at the declared widths, so wrap-around
  is inside the model rather than assumed away;
- the **elimination leg** — linear inequalities over the integers, producing the Farkas
  multipliers above.

If they ever disagree, patchproof reports a `DISCREPANCY` and tells you not to rely on
either until it is resolved. A disagreement means the integer model and the machine model
genuinely differ, which is exactly the kind of thing that ships a bug.

## Honest scope

This is the section to read before quoting a `COMPLETE` verdict at anyone.

- Verdicts concern **reachability of a violation in modelled bit semantics**. This is
  **not** a control-flow-hijack or RCE claim, and it targets no live system.
- Two defect shapes are deliberately **outside the model**, and the tool prints them on
  every run: witnesses wider than the modelled fields (e.g. ~96-bit composite offsets),
  and wrap-around arising from arithmetic performed *before* the guard is reached.
- `find_certificate` searches multipliers up to a bound. Returning no certificate means
  "none found within the bound", never "the system is satisfiable".
- A class models a *guard*, not your codebase. Getting from real C to a faithful class
  model is on you, and it is the step where mistakes actually happen.

## Proving this to someone who cannot see your code

patchproof analyses guards **you hand it**. If you need to prove to a third party that a
violating input exists — or that your fix eliminates all of them — *without revealing the
input or the code*, that is a zero-knowledge problem and it is not what this package does.
That capability is commercial. Everything here runs on code you already control.

## Documentation

| | |
|---|---|
| [SCOPE.md](SCOPE.md) | what `COMPLETE` proves, and what a certificate is *not* |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | every verdict and error, and how to act on it |

<!-- portfolio:start -->
## Part of the hw-verify toolkit

Open tools for proving security properties of hardware and bounds checks.
They share one boundary: **everything open analyses a design you disclose in full.**

| Project | What it does |
|---|---|
| **▶ [Live demo](https://huggingface.co/spaces/nickh007/hw-verify)** | Constant-time checker in your browser — the real analyzer via Pyodide |
| [**Docs & overview**](https://huggingface.co/spaces/nickh007/hw-verify-site) | What the toolkit proves, and what it refuses to answer |
| [`hw-verify`](https://github.com/nickharris808/hw-verify) | One install, one command, all three checkers |
| [`ctbench`](https://github.com/nickharris808/ctbench) | Matched-pair constant-time RTL benchmark + [leaderboard](https://github.com/nickharris808/ctbench#the-leaderboard) |
| **`patchproof`** (you are here) | Prove a bounds-check fix eliminates *every* violating input |
| [`patchproof-verify`](https://github.com/nickharris808/patchproof-verify) | Re-check its certificates in Rust, with no shared code |
| [`ct-mask`](https://github.com/nickharris808/ct-mask) | First-order masking verification by two certificates |
| [`hw-verify-mcp`](https://github.com/nickharris808/hw-verify-mcp) | MCP server — the checkers, callable by AI agents |
| [`ct-audit-action`](https://github.com/nickharris808/ct-audit-action) | GitHub Action — fail a PR on a leaky completion signal |
| [verdicts](https://huggingface.co/datasets/nickh007/hw-verify) · [witness paths](https://huggingface.co/datasets/nickh007/hw-verify-paths) | Two datasets: what each design is, and why |

**The commercial boundary.** Proving a property to a third party who never receives
the design — a verdict bound to a commitment of a design that stays hidden — is a
different problem and a commercial one. It is not in any of these packages.
<!-- portfolio:end -->

## Citation

If you use this in academic work, please cite it — [CITATION.cff](CITATION.cff) has
the metadata, and GitHub renders a "Cite this repository" button from it.

## Contributing

New defect classes are the most valuable contribution. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contributing

New defect classes are the most valuable contribution. See [CONTRIBUTING.md](CONTRIBUTING.md).
