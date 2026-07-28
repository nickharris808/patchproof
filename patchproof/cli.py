"""patchproof command line."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .linear import replay
from .model import CLASSES, OUT_OF_MODEL, REAL_CLASSES
from .prover import prove


def _fmt(r) -> str:
    lines = [
        f"class {r.defect_class} — {r.title}",
        "=" * 68,
        "  widths            " + ", ".join(f"{k}:{v}" for k, v in sorted(r.widths.items()))
        + f"  (total {r.total_width})",
    ]
    if r.exploit:
        lines.append(f"  exploit witness   {r.exploit.render()}")
        lines.append("                    (an input the ORIGINAL guard admits that violates safety)")
    if r.violating_measure is not None:
        lines.append(f"  violating region  {r.violating_measure} inputs (exact count)")

    if r.verdict == "INCOMPLETE":
        w = r.incompleteness_witness
        lines += [
            "",
            "  [INCOMPLETE] the corrected guard STILL admits a violating input:",
            f"               {w.render() if w else '(none reported)'}",
        ]
        return "\n".join(lines)

    if r.verdict == "VACUOUS":
        lines += ["", "  [VACUOUS] the corrected guard rejects every input, safe ones included."]
        return "\n".join(lines)

    lines += [
        "",
        "  [COMPLETE] every violating input is eliminated.",
        f"    bit-precise leg   discharged at declared widths (total {r.total_width} bits)",
    ]
    if r.certificate:
        c = r.certificate
        lines.append(f"    elimination leg   multipliers {c.multipliers}, replayed without a solver")
        for entry in c.to_dict()["constraints"]:
            lines.append(f"      x{entry['multiplier']}  {entry['form']}    [{entry['label']}]")
        lines.append(f"      = {c.combined.render()}   <- contradiction")
    lines.append(f"    legs agree        {r.legs_agree}")
    if r.strictly_stronger:
        lines.append("    non-vacuous       corrected guard is STRICTLY STRONGER than the original")
    return "\n".join(lines)


def _cmd_check(args) -> int:
    results = [prove(k) for k in (args.classes or REAL_CLASSES)]
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            print(_fmt(r))
            print()
        print("out of model (a COMPLETE verdict does not cover these):")
        for o in OUT_OF_MODEL:
            print(f"  - {o}")
    return 0 if all(r.verdict == "COMPLETE" for r in results) else 1


def _cmd_cert(args) -> int:
    r = prove(args.defect_class)
    if not r.certificate:
        print(f"no elimination certificate for class {args.defect_class}", file=sys.stderr)
        return 1
    out = json.dumps(r.certificate.to_dict(), indent=2)
    if args.output:
        Path(args.output).write_text(out + "\n")
        print(f"wrote {args.output}")
    else:
        print(out)
    return 0


def _cmd_replay(args) -> int:
    cert = json.loads(Path(args.certificate).read_text())
    ok, msg = replay(cert)
    print(("VERIFIED   " if ok else "REJECTED   ") + msg)
    return 0 if ok else 1


def _cmd_classes(args) -> int:
    for k in sorted(CLASSES):
        c = CLASSES[k]
        widths = ", ".join(f"{f.name}:{f.width}" for f in c.fields)
        print(f"  {k}  {c.title}\n       fields {widths} (total {c.total_width})")
        if c.note:
            print(f"       {c.note}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="patchproof",
        description="Prove a bounds-check fix eliminates every violating input, not just the one you saw.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="run all three questions over the modelled defect classes")
    c.add_argument("classes", nargs="*", help="class keys (default: the real classes A B C)")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=_cmd_check)

    g = sub.add_parser("cert", help="emit the elimination certificate for one class")
    g.add_argument("defect_class")
    g.add_argument("-o", "--output")
    g.set_defaults(func=_cmd_cert)

    r = sub.add_parser(
        "replay",
        help="re-check a certificate using integer arithmetic only (no solver, no trust)",
    )
    r.add_argument("certificate")
    r.set_defaults(func=_cmd_replay)

    lst = sub.add_parser("classes", help="list the modelled defect classes")
    lst.set_defaults(func=_cmd_classes)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
