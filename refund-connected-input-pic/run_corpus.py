#!/usr/bin/env python3
"""Score the `input_pic` reader against every vector the corpus scores for that layer.

    python3 run_corpus.py <path-to-corpora/vectors-refund-connected> [--python <interpreter>]

Reads MANIFEST.json, runs pic_reader.py over each `source/<run>/cases/<case>`, compares
with `expected.steps.input_pic`, prints one line per vector and a final count. Exit 0
only when every scored vector matches.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
READER = os.path.join(HERE, "pic_reader.py")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", help="path to corpora/vectors-refund-connected")
    ap.add_argument("--python", default=sys.executable)
    args = ap.parse_args()

    manifest = json.load(open(os.path.join(args.corpus, "MANIFEST.json"), encoding="utf-8"))
    print("corpus digest: %s" % manifest["corpusDigest"])
    good = total = 0
    for vector in manifest["vectors"]:
        expected = vector["expected"]["steps"].get("input_pic")
        if expected is None or expected == "NOT_REACHED":
            continue
        total += 1
        case_dir = os.path.join(args.corpus, vector["path"], "cases", vector["case"])
        proc = subprocess.run(
            [args.python, READER, case_dir, "--json"], capture_output=True, text=True
        )
        stdout = proc.stdout.strip().splitlines()
        got = json.loads(stdout[-1])["verdict"] if stdout else "no verdict line"
        ok = got == expected
        good += ok
        print("%-22s expected=%-28s got=%-28s %s exit=%d"
              % (vector["id"], expected, got, "ok" if ok else "MISMATCH", proc.returncode))
    print("%d/%d scored vectors match" % (good, total))
    return 0 if good == total else 1


if __name__ == "__main__":
    sys.exit(main())
