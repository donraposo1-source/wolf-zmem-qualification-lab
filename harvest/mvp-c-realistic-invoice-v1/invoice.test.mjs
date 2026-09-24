import test from"node:test";import assert from"node:assert/strict";import{invoice,prior,recipes}from"./invoice.fixture.mjs";import{process}from"./engine.mjs";
const r=process(invoice,prior,recipes);
test("three mapped purchase lines become observations",()=>assert.deepEqual(r.observations.map(x=>x.ingredientId),["GIN","VERMOUTH","CAMPARI"]));
test("units normalize 1L 75cl 70cl",()=>assert.deepEqual(r.observations.map(x=>x.ml),[1000,750,700]));
test("unknown product is quarantined and never priced",()=>{assert.equal(r.quarantine.length,1);assert.equal(r.quarantine[0].lineId,"4");assert.equal(r.observations.some(x=>x.lineId==="4"),false)});
test("discount and VAT lines are classified not ingredients",()=>assert.deepEqual(r.ignored.map(x=>x.kind),["discount","tax"]));
test("affected recipes receive aggregate cost and margin deltas",()=>{assert.deepEqual(r.impacts.map(x=>x.recipeId),["NEGRONI","AMERICANO"]);assert.ok(r.impacts.every(x=>x.marginDeltaMinor===-x.costDeltaMinor))});
test("owner-readable evidence retains invoice source lines and quarantine",()=>{const j=JSON.parse(r.reportText);assert.equal(j.invoiceId,"SUP-2026-1042");assert.equal(j.sourceObject,"fixture/supplier-2026-1042-v1");assert.equal(j.observations.length,3);assert.equal(j.quarantine[0].reason,"UNRESOLVED_INGREDIENT")});
