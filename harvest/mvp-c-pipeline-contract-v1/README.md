# MVP-C Pipeline Contract V1 — lab

Pipeline boundary:
OCRInvoiceLine → SupplierProductIdentity → IngredientMapping → NormalizedPurchase → IngredientPriceObservation → PriceDelta → AffectedRecipe[] → RecipeCostImpact[] → MenuMarginImpact[] → EvidencePayload.

Truth rule: OCR confidence is evidence metadata, never authority to create a VERIFIED ingredient mapping. Unresolved mapping is REVIEW_REQUIRED and blocks price-impact propagation.

Idempotency: processing key binds tenant + bar + invoice + line + source object. Observations are intended immutable; corrected source evidence produces a new source identity/observation rather than mutating history.

Money: integer minor units for stored paid/selling/recipe amounts. Unit-cost ratios may be NUMERIC/decimal in persistence; never floating money storage.

Isolation: every observation binds tenant_id + bar_id; lab table has RLS enabled and intentionally no permissive policy.

This is a contract lab only. No canonical Wolf migration or integration is authorized.
