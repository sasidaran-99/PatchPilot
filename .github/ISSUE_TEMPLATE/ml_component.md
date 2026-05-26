---
name: ML component
about: Adding or improving an ML model, training pipeline, or data layer
title: "[ML-Tier?] "
labels: ml
assignees: ''
---

## ML tier
- [ ] Tier 1 — Triage
- [ ] Tier 2 — Predictive
- [ ] Tier 3 — Autonomous

## Summary
<!-- One sentence describing the model or ML component being added. -->

## Problem this solves
<!-- What limitation in the current rule-based pipeline does this address? -->

## Proposed approach

**Model / algorithm:**
<!-- e.g. GradientBoostingClassifier, DBSCAN, fine-tuned CodeBERT, Ollama + qwen2.5-coder -->

**Input features:**
<!-- List the features the model uses. Be specific — include where each feature comes from (scanner output, git metadata, AST, etc.) -->

**Training data source:**
<!-- Where does the labeled data come from? e.g. "findings + verify outcomes persisted in SQLite by Issue #1" -->

**Approximate data requirement:**
<!-- How many labeled examples are needed before the model is useful? e.g. ~200 scan jobs -->

## New files / modules
<!-- List the files you plan to add or modify. -->
- `backend/app/ml/` — 
- `scripts/` — 
- Other: 

## API changes
<!-- Does this add or modify any endpoints? If yes, describe the request/response shape. -->
- [ ] No API changes
- [ ] New endpoint: `POST /`
- [ ] Modified endpoint: 

## Prerequisites
<!-- List any issues that must be merged before this one. -->
- Requires #

## Acceptance criteria
- [ ] Model trains without error on a local SQLite DB with sufficient data
- [ ] Falls back gracefully if model file is absent (no crash, original behaviour preserved)
- [ ] Training script documented with `--help` output
- [ ] New fields added to API response are documented in `backend/README.md`
- [ ] Model file (`.pkl`, `.pt`, etc.) is added to `.gitignore`

## Additional context
<!-- Links to relevant papers, HuggingFace model cards, benchmark results, or prior art. -->
