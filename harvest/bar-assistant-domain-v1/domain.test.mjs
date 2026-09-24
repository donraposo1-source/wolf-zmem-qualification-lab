import test from "node:test";import assert from "node:assert/strict";import{abv,dilution,normalizeUnit,convertAmount,amountWithUnits}from "./domain.mjs";
test("ABV accepts boundaries and nominal",()=>{assert.equal(abv(0),0);assert.equal(abv(42.5),42.5);assert.equal(abv(100),100)});
test("ABV rejects outside range",()=>{assert.throws(()=>abv(-.01),RangeError);assert.throws(()=>abv(100.01),RangeError)});
test("dilution percent and decimal",()=>{assert.deepEqual(dilution(50),{percent:50,decimal:.5});assert.equal(dilution(0).decimal,0);assert.equal(dilution(100).decimal,1)});
test("dilution rejects outside range",()=>{assert.throws(()=>dilution(-.1),RangeError);assert.throws(()=>dilution(100.1),RangeError)});
test("units normalize and bounded conversion",()=>{assert.equal(normalizeUnit(" ML "),"ml");assert.equal(convertAmount(1,"oz","ml"),30);assert.equal(convertAmount(10,"ml","invalid"),null)});
test("amount contract",()=>{assert.deepEqual(amountWithUnits(10,"ml"),{amount:10,units:"ml",amount_max:null});assert.deepEqual(amountWithUnits(10,"ml",20),{amount:10,units:"ml",amount_max:20})});
