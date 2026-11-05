#!/usr/bin/env python3
"""Check the SeedQR spec test vectors against the upstream specification.

tests/vectors/seedqr/spec/seedsigner.txt holds SeedSigner's published SeedQR
test vectors, copied out of their specification. Run this script to prove the
copy still matches it:

    python3 scripts/check_seedqr_vectors.py              # compare (default)
    python3 scripts/check_seedqr_vectors.py --update     # rewrite the file
    python3 scripts/check_seedqr_vectors.py --ref <sha>  # pin a revision
    python3 scripts/check_seedqr_vectors.py --show       # print what's upstream

Only this script needs network access; the C test suite reads the checked-in
file and stays offline.
"""

import argparse
import ast
import datetime
import re
import subprocess
import sys
import urllib.request

REPO = "SeedSigner/seedsigner"
DOC = "docs/seed_qr/README.md"
SPEC_PATH = "tests/vectors/seedqr/spec/seedsigner.txt"

HEADER = """\
# SeedSigner SeedQR test vectors - copied from the specification, not invented.
#
# Source : https://github.com/{repo}/blob/{ref}/{doc}
# Revision: {sha} ({today})
# Section : "Test SeedQRs" (Test Vector 1-9)
#
# Do not edit by hand: run scripts/check_seedqr_vectors.py --update to
# regenerate from upstream, and scripts/check_seedqr_vectors.py to verify that
# this copy still matches it.
#
# One vector per block, blank line between blocks:
#   seeds     the BIP39 mnemonic
#   standard  Standard SeedQR: four digits a word, in order
#   compact   CompactSeedQR: the entropy bytes, as lowercase hex
"""


def fetch(ref: str) -> str:
    url = f"https://raw.githubusercontent.com/{REPO}/{ref}/{DOC}"
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.read().decode("utf-8")


def resolve_sha(ref: str) -> str:
    """Commit the ref points at, so the provenance names an immutable revision."""
    try:
        out = subprocess.run(
            ["git", "ls-remote", f"https://github.com/{REPO}.git", ref, f"refs/heads/{ref}"],
            capture_output=True, text=True, timeout=30, check=False,
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2:
                return parts[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def parse_vectors(doc: str):
    """Every ``bash block in the doc that carries the three SeedQR fields."""
    vectors = []
    for block in re.findall(r"```bash\n(.*?)```", doc, re.S):
        fields = {}
        lines = block.splitlines()
        for i, line in enumerate(lines):
            key = line.strip()
            value = lines[i + 1].strip() if i + 1 < len(lines) else ""
            if key.endswith("-word seed:"):
                fields["seeds"] = value
            elif key == "# Standard SeedQR digit stream:":
                fields["standard"] = value
            elif key == "# CompactSeedQR bitstream:":
                fields["bitstream"] = value
            elif key == "# CompactSeedQR bytestream:":
                fields["compact"] = value
        if not all(k in fields for k in ("seeds", "standard", "compact")):
            continue
        vectors.append(fields)
    return vectors


def verify(v: dict, index: int) -> list:
    """Cross-check the doc's own fields; a copy cannot fix an upstream typo."""
    problems = []
    words = v["seeds"].split()
    digits = v["standard"]
    blob = ast.literal_eval(v["compact"])
    if len(words) not in (12, 24):
        problems.append(f"vector {index}: {len(words)} words")
    if len(digits) != 4 * len(words):
        problems.append(f"vector {index}: {len(digits)} digits for {len(words)} words")
    if not digits.isdigit():
        problems.append(f"vector {index}: digit stream has non-digits")
    if len(blob) not in (16, 32):
        problems.append(f"vector {index}: {len(blob)} compact bytes")
    if "bitstream" in v:
        bits = "".join(f"{b:08b}" for b in blob)
        if v["bitstream"] != bits:
            problems.append(f"vector {index}: bitstream does not match bytestream")
    return problems


def render(vectors, ref, sha) -> str:
    today = datetime.date.today().isoformat()
    out = [HEADER.format(repo=REPO, ref=ref, doc=DOC, sha=sha, today=today)]
    for v in vectors:
        out.append(f"seeds: {v['seeds']}\n")
        out.append(f"standard: {v['standard']}\n")
        out.append(f"compact: {ast.literal_eval(v['compact']).hex()}\n")
        out.append("\n")
    return "".join(out).rstrip("\n") + "\n"


def parse_local(text: str):
    """Read the checked-in file back into the same shape for comparison."""
    vectors, current = [], {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key in ("seeds", "standard", "compact"):
            current[key] = value
        if "compact" in current and "standard" in current and "seeds" in current:
            vectors.append(current)
            current = {}
    return vectors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ref", default="dev", help="branch, tag or commit (default: dev)")
    ap.add_argument("--update", action="store_true", help="rewrite the vendored file")
    ap.add_argument("--show", action="store_true", help="print the upstream vectors")
    args = ap.parse_args()

    doc = fetch(args.ref)
    upstream = parse_vectors(doc)
    if not upstream:
        print("error: no SeedQR test vectors found in the specification", file=sys.stderr)
        return 1

    problems = [p for i, v in enumerate(upstream, 1) for p in verify(v, i)]
    for p in problems:
        print(f"upstream: {p}", file=sys.stderr)

    if args.show:
        for i, v in enumerate(upstream, 1):
            print(f"vector {i}: {len(v['seeds'].split())} words")
            print(f"  seeds:    {v['seeds']}")
            print(f"  standard: {v['standard']}")
            print(f"  compact:  {ast.literal_eval(v['compact']).hex()}")

    if args.update:
        sha = resolve_sha(args.ref)
        with open(SPEC_PATH, "w", encoding="utf-8") as f:
            f.write(render(upstream, args.ref, sha))
        print(f"wrote {SPEC_PATH}: {len(upstream)} vectors from {args.ref} ({sha})")
        return 1 if problems else 0

    local = parse_local(open(SPEC_PATH, encoding="utf-8").read())
    if not local:
        print(f"error: {SPEC_PATH} holds no vectors", file=sys.stderr)
        return 1

    mismatches = 0
    for i in range(max(len(local), len(upstream))):
        want = upstream[i] if i < len(upstream) else None
        have = local[i] if i < len(local) else None
        if want is None or have is None:
            print(f"vector {i + 1}: present in only one side", file=sys.stderr)
            mismatches += 1
            continue
        want = {
            "seeds": want["seeds"],
            "standard": want["standard"],
            "compact": ast.literal_eval(want["compact"]).hex(),
        }
        if want == have:
            print(f"vector {i + 1}: matches")
            continue
        mismatches += 1
        for key in ("seeds", "standard", "compact"):
            if want[key] != have[key]:
                print(f"vector {i + 1} {key}:\n  upstream: {want[key]}\n  local   : {have[key]}",
                      file=sys.stderr)

    if mismatches or problems:
        print(f"\n{mismatches} vector mismatch(es), {len(problems)} upstream problem(s)"
              f" - run --update to refresh {SPEC_PATH}")
        return 1

    print(f"\nall {len(local)} vectors match the specification ({args.ref} @ {resolve_sha(args.ref)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
