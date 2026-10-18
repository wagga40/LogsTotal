# Tool output compatibility fixtures

`inputs.json` contains synthetic native output for all five engines. `expected.json`
was captured from commit `eda3e7a5`, before the shared output-mapping implementation.
The capture and assertions live in `tests/test_output_parity.py`; tests never rewrite
these expectations.

The fixtures deliberately retain existing differences, including Zircolite's reported
counts and empty evidence blocks, title collisions, Hayabusa detail projections and raw
identity fallbacks, Chainsaw's unflattened raw envelope, Rsigma aliases, and zero/negative
detail limits. JSON values and raw output bytes must survive normalization unchanged.

The references cover findings, raw matches, histogram buckets, alert markers, analytics,
relationship evidence, process forests, key events, and rule-text attribution. Integration
tests additionally compare persisted finding counts, match totals, and public JSON exports.
The existing storage, worker, cancellation, and real-engine tests cover those boundaries.

Extraction corrections belong in separately reviewed changes with an explanation of each
expected-result difference. Do not regenerate snapshots merely to make a refactor pass.

Next-release correction: `zircolite_legacy_junk` now rejects the `matches: null` and
string-valued evidence blocks, instead of inventing empty findings or counting their
reported matches. Its final valid block is still read by analytics: two raw events and
seven engine-reported matches, with no reader exception. The resulting timeline,
entities, relationships and markers are intentional additions; all other cases retain
the original compatibility reference.
