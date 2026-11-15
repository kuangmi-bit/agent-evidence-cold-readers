#!/usr/bin/env python3
"""Independent reader for the `input_pic` layer of refund-connected/v1.

Written from `docs/reference/refund-connected-input-pic.md` alone. The document is
pinned at commit 250de75575a945d00211415d7af41894d15427fa of
probityai/agent-evidence-vectors; the corpus bytes it is scored against carry digest
1588224056bb6f7f5971386164b4a737c422ec6b16bcdea3ca8dc559adb5f9a5.

Where the text leaves a reading to the verifier, this reader takes it and says so:

1. Steps 1-20 are evaluated in the order the table gives them, and the first failing
   step decides the layer. Every member read is read through `member()`, which fails
   the step when the value it reads from is not an object or when the member is
   absent -- the paragraph under "Procedure" says exactly that.
2. `JCS(v)` is RFC 8785 canonical JSON. A JSON value containing a lone surrogate
   escape has no UTF-8 encoding and therefore no canonical form, so a step that needs
   `JCS` of such a value fails that step. This is a reading: the text does not name
   the case, and the alternative -- letting the encoder raise -- produces no verdict
   line at all.
3. Step 8's `[A-Za-z0-9_-]+` is read as a whole-string match (`fullmatch`). The text
   writes "a string matching", not "containing", and a payment id with a space in the
   middle is not a payment id.
4. `hex64` is lower case only, as the "matches" table states: `0-9a-f`.
5. The runner-allowed rule is applied to steps 0b-13 and to nothing else. It is not
   applied to `NOT_ESTABLISHED:input-files-missing`, which the text calls out, and it
   is not applied when `inputs/pic-verification.json` itself did not strict-parse, for
   which the text says the refusal stands.

Usage:
    pic_reader.py <case-dir> [--json]

The last non-empty stdout line is one JSON object. Exit status is 0 for ESTABLISHED
and nonzero otherwise.
"""
import base64
import hashlib
import json
import os
import re
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ELEVEN = [
    "inputs/pic-proposal.json",
    "trust/pic-keys.json",
    "inputs/pic-verification.json",
    # not read by this layer, but each must be present and must strict-parse (step 0)
    "inputs/aps-intent.json",
    "inputs/aps-approval.json",
    "inputs/aps-action.json",
    "inputs/aps-payload.json",
    "inputs/decision-evidence.json",
    "trust/aps-consumption.json",
    "trust/handoff-issuance.json",
    "trust/handoff-evaluation.json",
]

HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
PAYMENT_ID = re.compile(r"\A[A-Za-z0-9_-]+\Z")
PRINTABLE_ASCII = re.compile(r"\A[\x20-\x7e]+\Z")
B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
INT64_MAX = 2 ** 53 - 1

ATT_MEMBERS = {
    "attestation_version", "tool", "impact", "provenance_ids",
    "args_digest", "claims_digest", "intent_digest", "expires_at",
}
RESULT_MEMBERS = {
    "schema", "contract_revision", "run_id", "pic_sdk_commit", "proposal_file_ref",
    "pic_trust_file_ref", "evaluated_at", "result", "tool", "impact",
    "args_digest", "claims_digest", "intent_digest", "error_code",
}


class Refuse(Exception):
    """Steps 0b to 13 refuse; the runner-allowed rule may rewrite the verdict."""

    def __init__(self, code, step):
        super().__init__(code)
        self.code = code          # e.g. PIC_ARGS_DIGEST
        self.step = step


class Contradict(Exception):
    """Steps 14 to 20 contradict; the runner-allowed rule never applies."""

    def __init__(self, code, step):
        super().__init__(code)
        self.code = code
        self.step = step


class StrictParseError(Exception):
    pass


def _no_dupes(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise StrictParseError("duplicate member name: %r" % (k,))
        seen.add(k)
    return dict(pairs)


def _no_float(s):
    raise StrictParseError("number with a fraction or exponent part: %r" % (s,))


def _no_const(s):
    raise StrictParseError("constant refused: %r" % (s,))


def strict_parse(raw):
    """UTF-8; duplicate member names refused at every depth; numbers with a fraction
    or exponent refused; integers of any size accepted; NaN/Infinity refused."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictParseError("not UTF-8: %s" % (exc,))
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_dupes,
            parse_float=_no_float,
            parse_constant=_no_const,
        )
    except StrictParseError:
        raise
    except ValueError as exc:
        raise StrictParseError(str(exc))


def _jcs_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value):
    """RFC 8785 canonical JSON as UTF-8 bytes."""
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if value is None:
        return b"null"
    if isinstance(value, int):
        return str(value).encode()
    if isinstance(value, str):
        return _jcs_string(value).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(jcs(v) for v in value) + b"]"
    if isinstance(value, dict):
        items = sorted(value.items())
        return b"{" + b",".join(jcs(k) + b":" + jcs(v) for k, v in items) + b"}"
    raise TypeError("no canonical form for %r" % (type(value),))


def sha_hex(b):
    return hashlib.sha256(b).hexdigest()


def file_ref(raw):
    return "sha256:" + sha_hex(raw)


def is_hex64(x):
    return isinstance(x, str) and bool(HEX64.match(x))


def is_printable_ascii_id(x):
    return isinstance(x, str) and bool(PRINTABLE_ASCII.match(x))


def is_integer(x):
    return isinstance(x, int) and not isinstance(x, bool)


def member(obj, name):
    if not isinstance(obj, dict) or name not in obj:
        raise KeyError(name)
    return obj[name]


def b64_strict(s):
    """RFC 4648 section 4 standard alphabet with '=' padding."""
    if not isinstance(s, str):
        raise ValueError("not a string")
    if len(s) % 4 != 0:
        raise ValueError("wrong padding")
    if any(c not in B64_CHARS for c in s):
        raise ValueError("a character outside the alphabet")
    if "=" in s[:-2]:
        raise ValueError("wrong padding")
    return base64.b64decode(s, validate=True)


def jcs_or_fail(value, refuse_code, step):
    try:
        return jcs(value)
    except UnicodeEncodeError:
        raise Refuse(refuse_code, step)


def runner_says_allow(raws):
    raw = raws.get("inputs/pic-verification.json")
    if raw is None:
        return False
    try:
        parsed = strict_parse(raw)
    except StrictParseError:
        return False
    return isinstance(parsed, dict) and parsed.get("result") == "allow"


def read_layer(case_dir):
    """Return (verdict, detail)."""
    raws = {}

    # step 0a
    missing = [p for p in ELEVEN if not os.path.isfile(os.path.join(case_dir, p))]
    if missing:
        return "NOT_ESTABLISHED:input-files-missing", {"missing": missing}

    # step 0b
    for p in ELEVEN:
        with open(os.path.join(case_dir, p), "rb") as fh:
            raws[p] = fh.read()
        try:
            strict_parse(raws[p])
        except StrictParseError as exc:
            return replay("STRICT_PARSE", 0, raws, {"file": p, "why": str(exc)})

    prop = strict_parse(raws["inputs/pic-proposal.json"])
    keys = strict_parse(raws["trust/pic-keys.json"])
    result = strict_parse(raws["inputs/pic-verification.json"])

    try:
        _picture(prop, keys, result, raws)
    except Refuse as refused:
        return replay(refused.code, refused.step, raws)
    except Contradict as contradicted:
        return "CONTRADICTED:" + contradicted.code, {"step": contradicted.step}
    return "ESTABLISHED", {}


def replay(code, step, raws, detail=None):
    """A refusal in steps 0b to 13 becomes CONTRADICTED:runner-allowed-X when the
    runner's own result file parsed to `"result": "allow"`. `NOT_ESTABLISHED` is not a
    refusal and never reaches here."""
    if runner_says_allow(raws) and 0 <= step <= 13:
        return "CONTRADICTED:runner-allowed-" + code, detail or {}
    return "REFUSED:" + code, detail or {}


def _picture(prop, keys, result, raws):
    # step 1
    try:
        evidence = member(prop, "evidence")
        if not isinstance(evidence, list) or len(evidence) != 1:
            raise Refuse("PIC_EVIDENCE", 1)
        entry = evidence[0]
        if not isinstance(entry, dict) or member(entry, "type") != "sig":
            raise Refuse("PIC_EVIDENCE", 1)
    except KeyError:
        raise Refuse("PIC_EVIDENCE", 1)

    # step 2
    try:
        payload = member(entry, "payload")
        if not isinstance(payload, str):
            raise Refuse("PIC_ATTESTATION", 2)
        try:
            att = strict_parse(payload.encode("utf-8"))
        except StrictParseError:
            raise Refuse("PIC_ATTESTATION", 2)
        if not isinstance(att, dict) or set(att) != ATT_MEMBERS:
            raise Refuse("PIC_ATTESTATION", 2)
        if att["attestation_version"] != "PIC-ATT/1.0":
            raise Refuse("PIC_ATTESTATION", 2)
    except KeyError:
        raise Refuse("PIC_ATTESTATION", 2)

    # step 3
    if not isinstance(keys, dict) or set(keys) != {"trusted_keys", "revoked_keys"}:
        raise Refuse("PIC_KEYRING", 3)
    if not isinstance(keys["trusted_keys"], dict) or not isinstance(keys["revoked_keys"], list):
        raise Refuse("PIC_KEYRING", 3)

    # step 4
    try:
        key_id = member(entry, "key_id")
        signer = member(entry, "signer")
    except KeyError:
        raise Refuse("PIC_KEY", 4)
    if key_id != signer or key_id in keys["revoked_keys"]:
        raise Refuse("PIC_KEY", 4)

    # step 5
    if not isinstance(key_id, str) or key_id not in keys["trusted_keys"]:
        raise Refuse("PIC_KEY", 5)
    keyed = keys["trusted_keys"][key_id]
    public_key = None
    if is_hex64(keyed):
        public_key = keyed
    elif isinstance(keyed, dict) and is_hex64(keyed.get("public_key")):
        public_key = keyed["public_key"]
    if public_key is None:
        raise Refuse("PIC_KEY", 5)

    # step 6
    try:
        signature_b64 = member(entry, "signature")
        alg = member(entry, "alg")
    except KeyError:
        raise Refuse("PIC_SIGNATURE", 6)
    try:
        signature = b64_strict(signature_b64)
    except ValueError:
        raise Refuse("PIC_SIGNATURE", 6)
    if alg != "ed25519" or len(signature) != 64:
        raise Refuse("PIC_SIGNATURE", 6)
    message = jcs_or_fail(att, "PIC_SIGNATURE", 6)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(signature, message)
    except Exception:  # noqa: BLE001 - any verification failure is the same refusal
        raise Refuse("PIC_SIGNATURE", 6)

    # step 7
    try:
        action = member(prop, "action")
        if not isinstance(action, dict) or member(action, "tool") != "refund":
            raise Refuse("PIC_PROFILE", 7)
        if member(prop, "impact") != "money":
            raise Refuse("PIC_PROFILE", 7)
        if att["tool"] != "refund" or att["impact"] != "money":
            raise Refuse("PIC_PROFILE", 7)
        if att["provenance_ids"] != [member(entry, "id")]:
            raise Refuse("PIC_PROFILE", 7)
    except KeyError:
        raise Refuse("PIC_PROFILE", 7)

    # step 8
    try:
        args = member(action, "args")
    except KeyError:
        raise Refuse("PIC_PROFILE", 8)
    if not isinstance(args, dict) or set(args) != {"payment_id", "amount_minor", "currency"}:
        raise Refuse("PIC_PROFILE", 8)
    if not isinstance(args["payment_id"], str) or not PAYMENT_ID.match(args["payment_id"]):
        raise Refuse("PIC_PROFILE", 8)
    if not is_integer(args["amount_minor"]) or not 0 < args["amount_minor"] <= INT64_MAX:
        raise Refuse("PIC_PROFILE", 8)
    if args["currency"] != "EUR":
        raise Refuse("PIC_PROFILE", 8)

    # step 9
    if sha_hex(jcs_or_fail(args, "PIC_ARGS_DIGEST", 9)) != att["args_digest"]:
        raise Refuse("PIC_ARGS_DIGEST", 9)

    # step 10 -- taken before the claims' shape is checked
    try:
        claims = member(prop, "claims")
    except KeyError:
        raise Refuse("PIC_CLAIMS_DIGEST", 10)
    if sha_hex(jcs_or_fail(claims, "PIC_CLAIMS_DIGEST", 10)) != att["claims_digest"]:
        raise Refuse("PIC_CLAIMS_DIGEST", 10)

    # step 11
    try:
        intent = member(prop, "intent")
    except KeyError:
        raise Refuse("PIC_INTENT_DIGEST", 11)
    if not isinstance(intent, str):
        raise Refuse("PIC_INTENT_DIGEST", 11)
    if sha_hex(intent.encode("utf-8")) != att["intent_digest"]:
        raise Refuse("PIC_INTENT_DIGEST", 11)

    # step 12
    if not isinstance(claims, list) or len(claims) != 1:
        raise Refuse("PIC_CLAIM", 12)
    claim_entry = claims[0]
    if not isinstance(claim_entry, dict) or set(claim_entry) != {"text", "evidence"}:
        raise Refuse("PIC_CLAIM", 12)
    if claim_entry["evidence"] != [entry["id"]] or not isinstance(claim_entry["text"], str):
        raise Refuse("PIC_CLAIM", 12)

    # step 13
    text = claim_entry["text"]
    try:
        claim = strict_parse(text.encode("utf-8"))
    except (StrictParseError, UnicodeEncodeError):
        raise Refuse("PIC_CLAIM", 13)
    if not isinstance(claim, dict) or set(claim) != {"approval_ref", "decision_id"}:
        raise Refuse("PIC_CLAIM", 13)
    canonical = jcs_or_fail(claim, "PIC_CLAIM", 13).decode("utf-8")
    if canonical != text:
        raise Refuse("PIC_CLAIM", 13)
    if not is_hex64(claim["approval_ref"]) or not is_printable_ascii_id(claim["decision_id"]):
        raise Refuse("PIC_CLAIM", 13)

    # step 14
    if not isinstance(result, dict) or set(result) != RESULT_MEMBERS:
        raise Contradict("PIC_RESULT_SHAPE", 14)

    # step 15
    if result["result"] != "allow" or result["error_code"] is not None:
        raise Contradict("PIC_RESULT_BLOCKS", 15)

    # step 16
    if (result["schema"] != "refund-sandbox-pic-result/0.1"
            or result["contract_revision"] != "review-2026-10-23"
            or result["pic_sdk_commit"] != "330fdd817ef81d43461ea1787939e0d1cc87d589"):
        raise Contradict("PIC_RESULT_SCHEMA", 16)

    # step 17
    if result["proposal_file_ref"] != file_ref(raws["inputs/pic-proposal.json"]):
        raise Contradict("PIC_RESULT_PROPOSAL_REF", 17)

    # step 18
    if result["pic_trust_file_ref"] != file_ref(raws["trust/pic-keys.json"]):
        raise Contradict("PIC_RESULT_TRUST_REF", 18)

    # step 19
    if (result["args_digest"], result["claims_digest"], result["intent_digest"]) != (
            att["args_digest"], att["claims_digest"], att["intent_digest"]):
        raise Contradict("PIC_RESULT_DIGESTS", 19)

    # step 20
    if result["tool"] != "refund" or result["impact"] != "money":
        raise Contradict("PIC_RESULT_TOOL", 20)


def main(argv):
    if len(argv) < 2:
        print("usage: pic_reader.py <case-dir> [--json]", file=sys.stderr)
        return 2
    verdict, _detail = read_layer(argv[1])
    print(json.dumps({"verdict": verdict}))
    return 0 if verdict == "ESTABLISHED" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
