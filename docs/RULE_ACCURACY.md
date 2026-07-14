# Rule accuracy evaluation

Evaluation date: 2026-07-14. Tool version: 1.0.0. Corpus:
[`evaluation/rule_accuracy_v1.jsonl`](../evaluation/rule_accuracy_v1.jsonl).

## Method

Each JSONL case contains one tool card plus explicit `expected_rules` and `forbidden_rules` labels.
Only these reviewed rule/case pairs enter the confusion matrix; unlabelled pairs are excluded.
Metrics are micro-averaged:

- precision = TP / (TP + FP)
- recall = TP / (TP + FN)
- F1 = harmonic mean of precision and recall

The evaluator rejects duplicate IDs, unknown/overlapping rules, unknown fields, blank or oversized
records, malformed JSON and non-finite thresholds. The CI gate requires precision and recall of at
least 0.95 and also requires an empty per-case failure list.

## Result

| Measure | Result |
| --- | ---: |
| Cases | 12 |
| Explicitly labelled pairs | 21 |
| True positives | 8 |
| False positives | 0 |
| True negatives | 13 |
| False negatives | 0 |
| Micro precision | 1.000000 |
| Micro recall | 1.000000 |
| Micro F1 | 1.000000 |

Corpus SHA-256:
`7645f07e45f2c02a924d57d081821f57fda2dfcc3796c61de951d261ab9fe901`.

Run the published gate:

```bash
mcp-tool-card-linter evaluate \
  --corpus evaluation/rule_accuracy_v1.jsonl \
  --min-precision 0.95 --min-recall 0.95
```

## Interpretation limits

This is a transparent regression corpus, not a statistically representative production sample.
Its prevalence is synthetic, it currently labels eight high-value deterministic security rules,
and a 1.0 score must not be generalized to all 106 rules or all real MCP servers. Metadata rules
cannot establish runtime behavior. Future releases should grow the corpus with independently
reviewed, de-identified real-world cards and publish results by rule and corpus version.
