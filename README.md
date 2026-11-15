# agent-evidence cold readers

Independent readers for contracts published by
[`probityai/agent-evidence-vectors`](https://github.com/probityai/agent-evidence-vectors),
written by someone who did not write that repository's code.

One directory per contract. Each carries the reader, the corpus runner that scores it,
the exact pins it was run against, the readings the text left to the verifier, and the
probes that produced any finding against it.

| Directory | Layer | Figure |
| --- | --- | --- |
| [`refund-connected-input-pic/`](refund-connected-input-pic/README.md) | `input_pic` of `vectors-refund-connected` | 12/12 scored vectors match, both runs |

These are directed runs: the contract document in each case is the target text. Where a
run is blind, the directory says so and says what was not opened.
