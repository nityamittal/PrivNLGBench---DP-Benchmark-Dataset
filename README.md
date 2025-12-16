# PrivNLGBench

PrivNLGBench is a benchmarking framework for studying **privacy–utility trade-offs** in synthetic text generation and private adaptation. It standardizes multiple text domains into a **shared JSON schema** that cleanly separates **privacy-relevant fields (PII/quasi-identifiers)** from **utility-facing fields (task labels and summaries)**, then evaluates both privacy and utility under consistent protocols.

## What’s in this project

- **Unified schema** across domains
  - **Privacy fields:** names, emails, IDs, timestamps/dates, locations/addresses, employment details, etc.
  - **Utility fields:** category/topic, sentiment, rating (when available), keywords, and a **strictly PII-free summary**
- **Feature population pipeline**
  - Hybrid extraction: deterministic detectors (regex/NER/header parsing) + schema-constrained LLM extraction for semantic fields
  - Automated validation + targeted human review for flagged cases
- **Evaluation suite**
  - **Utility:** accuracy, macro-F1; ordinal metrics (MAE / QWK) where applicable; length-sliced reporting
  - **Calibration:** ECE + temperature scaling
  - **Robustness/Fairness:** stress tests (noise/dropout/format changes), worst-group and gap metrics
  - **Privacy:** PII leakage checks on generated text + exposure-style proxies (e.g., nearest-neighbor similarity)

## Datasets

This benchmark currently uses three domains spanning short, medium, and long text:

- **Yelp reviews** (short → long): main supervised benchmark (utility + privacy prediction)
- **Enron emails** (medium): corporate email stress set
- **Clinton FOIA emails** (long): long-form, PII-dense stress set

### Where to find the data
The dataset is located **[here](https://docs.google.com/spreadsheets/d/1_cQs2e1XqbPSwAkb8e-SCiqCaqEq1WV0OMZPmg_Q_-s/edit?gid=1900866215#gid=1900866215)**


## Schema (high level)

Each example is represented as a single JSON record with:
- `text` (or `header+body` for emails)
- `word_count` + optional `length_bucket`
- **privacy fields** (PII/quasi-identifiers)
- **utility fields** (task labels + PII-free summary + keywords)

Domain-specific schemas (Yelp vs. email) keep the same *types* and conventions (strings / lists / `"N/A"`), while adjusting which fields are active.

## Key results (from this report)

- Strong Yelp baselines: bag-of-words is competitive; DistilRoBERTa improves sentiment and especially ordinal rating.
- Privacy prediction is imbalanced: macro-F1 is the real signal; pretrained models help most on minority-class separation.
- Privacy defenses behave differently:
  - Hard redaction can **wreck utility**
  - Noise-based synthetic generation provides a **smoother fidelity knob**, but email domains can behave weird due to templated text
