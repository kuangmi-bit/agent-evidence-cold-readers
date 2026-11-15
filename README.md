# agent-evidence cold readers

[![input_pic corpus run](https://github.com/kuangmi-bit/agent-evidence-cold-readers/actions/workflows/corpus-run.yml/badge.svg)](https://github.com/kuangmi-bit/agent-evidence-cold-readers/actions/workflows/corpus-run.yml)

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

Each directory's figure is re-derived by CI on every push against the corpus commit that
directory pins, rather than trusted from the day it was posted: the workflow fails when the
corpus digest moves or when the last line of the run stops matching the posted figure. The
probe table runs beside it as advisory output, because it describes upstream behaviour this
repository does not control.
