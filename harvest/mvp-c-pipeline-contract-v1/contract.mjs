import{createHash}from"node:crypto";
export function processingKey(x){return createHash("sha256").update([x.tenantId,x.barId,x.invoiceId,x.lineId,x.sourceObject].join("\u001f")).digest("hex")}
export function gateMapping(mapping){if(mapping.status!=="VERIFIED"||!mapping.ingredientId)return{status:"REVIEW_REQUIRED",reason:"UNRESOLVED_INGREDIENT_MAPPING"};return{status:"VERIFIED",ingredientId:mapping.ingredientId}}
export function assertTenantBar(a,b){if(a.tenantId!==b.tenantId||a.barId!==b.barId)throw new Error("TENANT_BAR_BOUNDARY")}
export function assertCurrency(a,b){if(a.currency!==b.currency)throw new Error("CURRENCY_MISMATCH")}
export function evidence(line,mapping){return Object.freeze({processingKey:processingKey(line),tenantId:line.tenantId,barId:line.barId,invoiceId:line.invoiceId,sourceObject:line.sourceObject,ocrLineId:line.lineId,mappingEvidence:[...(mapping.evidence||[])],status:mapping.status==="VERIFIED"&&mapping.ingredientId?"VERIFIED":"REVIEW_REQUIRED"})}
