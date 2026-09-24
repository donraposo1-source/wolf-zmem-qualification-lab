import test from"node:test";import assert from"node:assert/strict";import{processingKey,gateMapping,assertTenantBar,assertCurrency,evidence}from"./contract.mjs";
const line={tenantId:"t1",barId:"b1",invoiceId:"i1",lineId:"l1",sourceObject:"invoice/sha256:abc",ocrConfidence:.99};
test("processing key deterministic and identity-sensitive",()=>{assert.equal(processingKey(line),processingKey({...line}));assert.notEqual(processingKey(line),processingKey({...line,lineId:"l2"}))});
test("OCR confidence never promotes unresolved mapping",()=>assert.deepEqual(gateMapping({status:"REVIEW_REQUIRED",ingredientId:null,evidence:["ocr:.99"]}),{status:"REVIEW_REQUIRED",reason:"UNRESOLVED_INGREDIENT_MAPPING"}));
test("verified mapping requires ingredient identity",()=>assert.equal(gateMapping({status:"VERIFIED",ingredientId:"ing1"}).ingredientId,"ing1"));
test("tenant/bar boundary fails closed",()=>assert.throws(()=>assertTenantBar({tenantId:"t1",barId:"b1"},{tenantId:"t2",barId:"b1"}),/TENANT_BAR_BOUNDARY/));
test("currency mismatch fails closed",()=>assert.throws(()=>assertCurrency({currency:"EUR"},{currency:"USD"}),/CURRENCY_MISMATCH/));
test("evidence preserves immutable source references and review state",()=>{const e=evidence(line,{status:"REVIEW_REQUIRED",ingredientId:null,evidence:["manual:pending"]});assert.equal(e.sourceObject,line.sourceObject);assert.equal(e.ocrLineId,"l1");assert.equal(e.status,"REVIEW_REQUIRED");assert.ok(Object.isFrozen(e))});
