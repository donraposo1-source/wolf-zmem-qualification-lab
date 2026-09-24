# MVP-C Price History + Alert Policy V1

Deterministic, non-ML lab policy. Selects the latest prior compatible observation as baseline, applies a configurable absolute percentage threshold, finds recipes that consume the ingredient, estimates monthly economic impact from explicit recipe consumption × monthly serves, ranks by absolute impact, and retains baseline/current invoice evidence.

Default threshold 5% is a LAB PARAMETER, not a canonical business decision.

PUBLIC_SAFE synthetic tests only. No OCR, no canonical integration.
