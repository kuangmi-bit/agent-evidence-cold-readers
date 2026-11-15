#!/usr/bin/env python3
"""Seam harness for the input_pic contract.

Builds one-field variants of the retained case j01, runs:
  * pic_reader.py   (this cold read, from the contract text only)
  * the packaged reference reader's check_pic (black box oracle)
and prints where the two disagree. Where a variant needs a valid signature the
harness mints its own Ed25519 key and re-signs the attestation.
"""
import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

AEV = os.environ.get("AEV_REPO", "/tmp/aev")
sys.path.insert(0, os.path.join(AEV, "packaging"))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_evidence_vectors.refundconnected import (  # noqa: E402
    Admission,
    Case,
    Finding,
    RunDir,
    Streams,
    check_pic,
    case_ctx_store,
    jcs,
    judge_case,
    sha_hex,
)

SRC = Path(os.environ.get("AEV_REPO", "/tmp/aev")) / "corpora/vectors-refund-connected/source/j01-connected-20261028-r1"
WORK = Path(os.environ.get("PROBE_WORK", "/tmp/probe/run"))
MINE = str(Path(__file__).resolve().parent.parent / "pic_reader.py")
PY = "/tmp/aevvenv/bin/python"


def load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def dump(p, v):
    Path(p).write_text(json.dumps(v, ensure_ascii=False, sort_keys=False, indent=2) + "\n", encoding="utf-8")


class Ctx:
    def __init__(self, d):
        self.d = Path(d)
        self.prop_p = self.d / "inputs/pic-proposal.json"
        self.ver_p = self.d / "inputs/pic-verification.json"
        self.trust_p = self.d / "trust/pic-keys.json"

    def prop(self):
        return load(self.prop_p)

    def put_prop(self, v):
        dump(self.prop_p, v)

    def ver(self):
        return load(self.ver_p)

    def put_ver(self, v):
        dump(self.ver_p, v)

    def trust(self):
        return load(self.trust_p)

    def put_trust(self, v):
        dump(self.trust_p, v)

    def resign(self, att, key_id):
        """Mint a key, trust it under key_id, sign JCS(att), fix the two file refs."""
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ).hex()
        t = self.trust()
        t["trusted_keys"][key_id] = pub
        t["revoked_keys"] = [k for k in t["revoked_keys"] if k != key_id]
        self.put_trust(t)

        prop = self.prop()
        entry = prop["evidence"][0]
        entry["key_id"] = key_id
        entry["signer"] = key_id
        entry["alg"] = "ed25519"
        entry["payload"] = jcs(att).decode("utf-8")
        entry["signature"] = base64.b64encode(priv.sign(jcs(att))).decode()
        self.put_prop(prop)

        v = self.ver()
        v["proposal_file_ref"] = "sha256:" + sha_hex(self.prop_p.read_bytes())
        v["pic_trust_file_ref"] = "sha256:" + sha_hex(self.trust_p.read_bytes())
        self.put_ver(v)
        return att

    def resign_with_claims(self, key_id, claims):
        """Re-sign after changing prop.claims (claims digest depends on it)."""
        prop = self.prop()
        prop["claims"] = claims
        self.put_prop(prop)
        att = json.loads(prop["evidence"][0]["payload"])
        att["claims_digest"] = sha_hex(jcs(claims))
        return self.resign(att, key_id)


def run_mine(case_dir):
    p = subprocess.run([PY, MINE, str(case_dir), "--json"], capture_output=True, text=True)
    line = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
    try:
        return json.loads(line)["verdict"]
    except Exception:
        return "ERR:" + (p.stderr.strip().splitlines()[-1] if p.stderr.strip() else "?")


def run_theirs(name):
    """The packaged reader's own layer verdict — judge_case applies the runner-allowed
    rewriting that a bare check_pic call skips."""
    case_ctx_store.clear()
    run = RunDir(WORK)
    try:
        steps = judge_case(run, name, Admission(run), Streams(run), None)
        return steps["input_pic"]
    except Exception as e:  # noqa: BLE001
        return "ERR:" + type(e).__name__ + ":" + str(e)[:80]


def variant(name, mutate, fresh_run_dir=False):
    d = WORK / "cases" / name
    if d.exists():
        shutil.rmtree(d)
    shutil.copytree(WORK / "cases" / "j01", d)
    mutate(Ctx(d))
    mine = run_mine(d)
    theirs = run_theirs(name)
    flag = "SAME" if mine == theirs else "**DIFF**"
    return (name, mine, theirs, flag)


def main():
    if WORK.exists():
        pass
    else:
        WORK.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(SRC, WORK)

    KEY = "kid_probe_1"
    cases = []

    def reg(name, fn):
        cases.append((name, fn))

    reg("m00-baseline", lambda c: None)

    def m01(c):
        (c.d / "inputs/pic-verification.json").unlink()

    reg("m01-file-missing", m01)

    def m02(c):
        (c.ver_p).write_bytes(b"\xff\xfe{}")

    reg("m02-not-utf8", m02)

    def m03(c):
        p = c.d / "inputs/aps-intent.json"
        p.write_text('{"a":1,"a":2}\n', encoding="utf-8")

    reg("m03-dup-member", m03)

    def m04(c):
        p = c.prop()
        p["evidence"] = p["evidence"] + p["evidence"]
        c.put_prop(p)

    reg("m04-two-evidence", m04)

    def m05(c):
        p = c.prop()
        p["evidence"][0]["type"] = "pkg"
        c.put_prop(p)

    reg("m05-evidence-type", m05)

    def m06(c):
        p = c.prop()
        entry = p["evidence"][0]
        att = json.loads(entry["payload"])
        entry["payload"] = entry["payload"].replace('"tool":"refund"', '"tool":"refund","x":1.5', 1)
        if entry["payload"] == json.loads(p["evidence"][0]["payload"]):
            pass
        c.put_prop(p)

    reg("m06-payload-float", m06)

    def m07(c):
        p = c.prop()
        entry = p["evidence"][0]
        att = json.loads(entry["payload"])
        att["extra"] = "x"
        att = c.resign(att, KEY)
        c.put_prop(p)

    reg("m07-att-extra-member", m07)

    def m08(c):
        t = c.trust()
        t["revoked_keys"] = list(t["revoked_keys"]) + [c.prop()["evidence"][0]["key_id"]]
        c.put_trust(t)

    reg("m08-key-revoked", m08)

    def m09(c):
        t = c.trust()
        t["trusted_keys"].pop(c.prop()["evidence"][0]["key_id"], None)
        c.put_trust(t)

    reg("m09-key-untrusted", m09)

    def m10(c):
        t = c.trust()
        kid = c.prop()["evidence"][0]["key_id"]
        t["trusted_keys"][kid] = {"note": "no public key here"}
        c.put_trust(t)

    reg("m10-key-no-pubkey", m10)

    def m11(c):
        p = c.prop()
        p["evidence"][0]["signature"] = "not base64!!"
        c.put_prop(p)

    reg("m11-sig-not-b64", m11)

    def m12(c):
        p = c.prop()
        p["evidence"][0]["alg"] = "ED25519"
        c.put_prop(p)

    reg("m12-alg-uppercase", m12)

    def m13(c):
        p = c.prop()
        p["action"]["tool"] = "refund "
        c.put_prop(p)

    reg("m13-action-tool", m13)

    def m14(c):
        p = c.prop()
        att = json.loads(p["evidence"][0]["payload"])
        att["provenance_ids"] = ["other"]
        c.resign(att, KEY)

    reg("m14-provenance", m14)

    def m15(c):
        p = c.prop()
        p["action"]["args"]["amount_minor"] = 2 ** 53
        c.put_prop(p)

    reg("m15-amount-2^53", m15)

    def m16(c):
        p = c.prop()
        p["action"]["args"]["amount_minor"] = True
        c.put_prop(p)

    reg("m16-amount-bool", m16)

    def m17(c):
        p = c.prop()
        p["action"]["args"]["currency"] = "eur"
        c.put_prop(p)

    reg("m17-currency-lower", m17)

    def m18(c):
        p = c.prop()
        p["action"]["args"]["payee"] = "x"
        c.put_prop(p)

    reg("m18-args-extra", m18)

    def m19(c):
        p = c.prop()
        p["action"]["args"]["amount_minor"] = 4100
        c.put_prop(p)

    reg("m19-amount-changed", m19)

    def m20(c):
        p = c.prop()
        p["intent"] = p["intent"] + " "
        c.put_prop(p)

    reg("m20-intent-changed", m20)

    def m21(c):
        p = c.prop()
        p["claims"] = "not a list"
        c.put_prop(p)

    reg("m21-claims-string", m21)

    def m22(c):
        v = c.ver()
        v["extra"] = 1
        c.put_ver(v)

    reg("m22-result-extra", m22)

    def m23(c):
        v = c.ver()
        v["error_code"] = "PIC_X"
        c.put_ver(v)

    reg("m23-result-error", m23)

    def m24(c):
        v = c.ver()
        v["schema"] = "refund-sandbox-pic-result/0.2"
        c.put_ver(v)

    reg("m24-result-schema", m24)

    def m25(c):
        v = c.ver()
        v["proposal_file_ref"] = "sha256:" + "0" * 64
        c.put_ver(v)

    reg("m25-proposal-ref", m25)

    def m26(c):
        v = c.ver()
        v["pic_trust_file_ref"] = "sha256:" + "0" * 64
        c.put_ver(v)

    reg("m26-trust-ref", m26)

    def m27(c):
        v = c.ver()
        v["args_digest"] = "0" * 64
        c.put_ver(v)

    reg("m27-result-digests", m27)

    def m28(c):
        v = c.ver()
        v["tool"] = "payout"
        c.put_ver(v)

    reg("m28-result-tool", m28)

    def m29(c):
        p = c.prop()
        p["action"]["args"]["amount_minor"] = 4100
        c.put_prop(p)
        v = c.ver()
        v["result"] = "allow"
        v["error_code"] = None
        c.put_ver(v)

    reg("m29-runner-allowed", m29)

    def m30(c):
        p = c.prop()
        p["action"]["args"]["payment_id"] = "pay C"
        c.put_prop(p)

    reg("m30-payment-id-space", m30)

    def m31(c):
        p = c.prop()
        att = json.loads(p["evidence"][0]["payload"])
        att["attestation_version"] = "PIC-ATT/1.0".replace("1.0", "1.1")
        c.resign(att, KEY)

    reg("m31-att-version", m31)

    def m32(c):
        """payload formatted non-canonically; the key signs the RAW string only."""
        p = c.prop()
        entry = p["evidence"][0]
        att = json.loads(entry["payload"])
        pretty = json.dumps(att, indent=2)
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ).hex()
        t = c.trust()
        t["trusted_keys"][KEY] = pub
        t["revoked_keys"] = [k for k in t["revoked_keys"] if k != KEY]
        c.put_trust(t)
        entry["key_id"] = entry["signer"] = KEY
        entry["payload"] = pretty
        entry["signature"] = base64.b64encode(priv.sign(pretty.encode())).decode()
        c.put_prop(p)
        v = c.ver()
        v["proposal_file_ref"] = "sha256:" + sha_hex(c.prop_p.read_bytes())
        v["pic_trust_file_ref"] = "sha256:" + sha_hex(c.trust_p.read_bytes())
        c.put_ver(v)

    reg("m32-payload-not-canonical", m32)

    def m33(c):
        p = c.prop()
        claims = copy.deepcopy(p["claims"])
        claims[0]["evidence"] = []
        c.resign_with_claims(KEY, claims)

    reg("m33-claim-evidence-empty", m33)

    def m34(c):
        p = c.prop()
        claims = copy.deepcopy(p["claims"])
        claim = json.loads(claims[0]["text"])
        claims[0]["text"] = json.dumps(claim, sort_keys=False) if False else '{"decision_id":%s,"approval_ref":%s}' % (
            json.dumps(claim["decision_id"]), json.dumps(claim["approval_ref"]))
        c.resign_with_claims(KEY, claims)

    reg("m34-claim-not-canonical", m34)

    def m35(c):
        p = c.prop()
        claims = copy.deepcopy(p["claims"])
        claim = json.loads(claims[0]["text"])
        claim["approval_ref"] = claim["approval_ref"].upper()
        claims[0]["text"] = json.dumps(claim, separators=(",", ":"), sort_keys=True)
        c.resign_with_claims(KEY, claims)

    reg("m35-approval-ref-upper", m35)

    def m36(c):
        p = c.prop()
        claims = copy.deepcopy(p["claims"])
        claim = json.loads(claims[0]["text"])
        claim["extra"] = 1
        claims[0]["text"] = json.dumps(claim, separators=(",", ":"), sort_keys=True)
        c.resign_with_claims(KEY, claims)

    reg("m36-claim-extra", m36)

    def m37(c):
        p = c.prop()
        claims = copy.deepcopy(p["claims"])
        claim = json.loads(claims[0]["text"])
        claim["decision_id"] = "dec\t1"
        claims[0]["text"] = json.dumps(claim, separators=(",", ":"), sort_keys=True)
        c.resign_with_claims(KEY, claims)

    reg("m37-decision-id-tab", m37)

    def m38(c):
        p = c.prop()
        entry = p["evidence"][0]
        sig = base64.b64decode(entry["signature"])
        entry["signature"] = base64.b64encode(sig[:63]).decode()
        c.put_prop(p)

    reg("m38-sig-63-bytes", m38)

    rows = []
    for name, fn in cases:
        try:
            rows.append(variant(name, fn))
        except Exception as e:  # noqa: BLE001
            rows.append((name, "HARNESS_ERR:" + type(e).__name__, str(e)[:60], "**DIFF**"))
    w = max(len(r[0]) for r in rows)
    print(f'{"variant".ljust(w)}  {"cold read":32s} {"packaged":32s} flag')
    for name, mine, theirs, flag in rows:
        print(f"{name.ljust(w)}  {mine:32s} {theirs:32s} {flag}")
    diffs = [r for r in rows if r[3] == "**DIFF**"]
    print(f"\n{len(rows)} variants, {len(diffs)} disagreements")


if __name__ == "__main__":
    main()
