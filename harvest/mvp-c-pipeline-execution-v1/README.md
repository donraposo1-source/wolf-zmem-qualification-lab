# MVP-C Pipeline Execution V1 — PUBLIC_SAFE synthetic fixture

Realistic but synthetic invoice fixtures only; no customer/private data.
Proves deterministic semantics from invoice-like extracted lines through verified mapping, normalized unit cost, price delta, recipe cost impact, menu margin impact and human-readable evidence fields.
The fixture intentionally uses 1 cl at 20→24 euro-cents-equivalent minor units to make a 20% unit-price change and deterministic propagation visible.
Unresolved mappings produce REVIEW_REQUIRED with zero alerts. Replay uses deterministic source identity. Corrected source versions remain separate immutable events.
LAB ONLY. No external OCR and no canonical Wolf integration.
