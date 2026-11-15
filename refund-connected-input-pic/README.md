# A cold read of the `input_pic` layer

An independent implementation of one layer of `vectors-refund-connected`: the
`input_pic` contract stated in
[`docs/reference/refund-connected-input-pic.md`](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/reference/refund-connected-input-pic.md)
of `probityai/agent-evidence-vectors`.

It answers for `input_pic` only. It says nothing about `input_aps`, `admission`,
`signature_trust`, `execution` or `observed_effect`, and it is not a run of the
complete refund flow.

## Pins

| | |
| --- | --- |
| Contract text | `docs/reference/refund-connected-input-pic.md` at `probityai/agent-evidence-vectors` commit `250de75575a945d00211415d7af41894d15427fa` (2026-11-14) |
| Corpus | `corpora/vectors-refund-connected`, corpus digest `1588224056bb6f7f5971386164b4a737c422ec6b16bcdea3ca8dc559adb5f9a5` |
| Reader | `pic_reader.py` in this directory |
| Label, by its author | **directed** — the contract document was read as the target text; the packaged reader's source was opened only after this reader had been written and scored, for the probe comparison in `probes/` |

## Result

All twelve vectors the manifest scores for this layer match, in both runs:

```
j01, n1b-aps-payload, n3-reissue, n3b-old-pic, n4-lost-ack   ESTABLISHED   (r1 and r2)
n1a-pic-args                                                REFUSED:PIC_ARGS_DIGEST   (r1 and r2)
```

Reproduce it with the corpus checked out at any commit carrying that digest:

```sh
pip install cryptography
python3 run_corpus.py /path/to/corpora/vectors-refund-connected
```

One vector per line, then `12/12 scored vectors match`. The reader prints one JSON
object on the last non-empty stdout line and exits 0 exactly for `ESTABLISHED`, as
the contract's "Running an independent verifier" section asks.

## Readings the text left to the verifier

These are decisions, not corrections. Each is stated in the module docstring of
`pic_reader.py` beside the step it belongs to.

1. **A lone surrogate escape has no canonical form.** A claim text containing
   `\ud800` strict-parses as JSON but cannot be encoded as UTF-8, so `JCS(claim)`
   cannot exist and the step-13 comparison cannot hold. The reader refuses with
   `PIC_CLAIM`. The alternative — letting the encoder raise — produces no verdict line
   at all.
2. **`[A-Za-z0-9_-]+` for `payment_id` is a whole-string match.** The text says "a
   string matching", not "containing".
3. **`hex64` is lower case only**, as the forms table states (`0-9a-f`).
4. **Steps 1-20 are evaluated in the order the table gives**, first failure decides.
   Reading a member of a non-object, or an absent member, fails that step, per the
   paragraph under "Procedure".

## What the probe run found

`probes/` holds the harness: it builds one-field variants of the retained case `j01`
(minting its own Ed25519 key and re-signing where a variant has to reach a later
step) and runs both this reader and the packaged reference reader
(`judge_case(...)["input_pic"]`) over each. 53 variants: 51 agree, 2 do not, and
those two are the findings below. No variant is a claim about the corpus; they are
probes of the text.

**F1 — `att.expires_at` has no type at either layer, and the packaged reader raises
on the case the text permits.** A proposal whose attestation carries
`"expires_at": null` is `ESTABLISHED` at `input_pic` by the text (step 2 fixes the
member set, never the member's type; "What this contract does not do" says the value
is handed to `input_aps` to compare). This reader returns `ESTABLISHED`; the packaged
reader returns `ESTABLISHED` for `input_pic` and then raises `AttributeError:
'NoneType' object has no attribute 'replace'` in `check_aps`
(`refundconnected.py:837` at `250de755`), because `input_aps` step 25 calls
`.replace("Z", ".000Z")` on that value. A layer that establishes hands the next layer
a value the next layer cannot consume, and the failure surfaces as an exception rather
than a verdict.

**F2 — a lone surrogate in the claim text raises instead of refusing.** The same input
makes the packaged reader raise `UnicodeEncodeError` out of its JCS encoder; this
reader refuses with `PIC_CLAIM` (reading 1 above). Whichever reading is intended, the
text does not say, and one of the two shapes — verdict or exception — has to be named.

**A note that is not a finding.** `JCS` here is not RFC 8785 for integers at or above
`1e21`: both this reader and the packaged one serialise `10**21` as
`1000000000000000000000`, where RFC 8785 §3.2.2.3 (ECMAScript `Number::toString`)
gives `1e+21`. It is unreachable through the fields whose types the contract fixes —
`amount_minor` is bounded by `2**53 - 1`, and the claim object has two string members —
and reachable only through F1's unconstrained `expires_at`. It is a consistency point
between "strict parse accepts integers of any size" and "`JCS(v)` means RFC 8785", not
a disagreement between readers.

## Files

```
pic_reader.py            the layer reader (steps 0a-20 plus the runner-allowed rule)
run_corpus.py            scores it against every vector the manifest scores
probes/seams.py          39 one-field variants, first wave
probes/seams2.py        14 variants, thin-type second wave
probes/results.txt      both runs' output, as produced
```
