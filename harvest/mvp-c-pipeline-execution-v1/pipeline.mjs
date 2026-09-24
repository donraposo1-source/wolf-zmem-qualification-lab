import{createHash}from"node:crypto";
const ml={ml:1,cl:10,oz:30};
const key=x=>createHash("sha256").update([x.tenantId,x.barId,x.invoiceId,x.lineId,x.sourceObject].join("\u001f")).digest("hex");
export function execute({previous,current,mapping,recipe,sellingPriceMinor=1200}){
 if(mapping.status!=="VERIFIED"||!mapping.ingredientId)return{status:"REVIEW_REQUIRED",alerts:[],reason:"UNRESOLVED_INGREDIENT_MAPPING"};
 for(const x of[previous,current]){if(x.tenantId!==current.tenantId||x.barId!==current.barId)throw Error("TENANT_BAR_BOUNDARY");if(x.currency!==current.currency)throw Error("CURRENCY_MISMATCH");if(!(x.unit in ml)||x.quantity<=0||!Number.isSafeInteger(x.paidMinor)||x.paidMinor<0)throw Error("INVALID_OBSERVATION")}
 const pk=key(current),prevUnit=previous.paidMinor/(previous.quantity*ml[previous.unit]),currUnit=current.paidMinor/(current.quantity*ml[current.unit]);
 const pct=prevUnit===0?(currUnit===0?0:null):Math.round((((currUnit-prevUnit)/prevUnit)*100)*1e9)/1e9;
 const prevRecipe=Math.round(prevUnit*recipe.amountMl),currRecipe=Math.round(currUnit*recipe.amountMl);
 const alert={ingredientId:mapping.ingredientId,previousUnitCostMinorPerMl:prevUnit,currentUnitCostMinorPerMl:currUnit,percentageDelta:pct,recipeId:recipe.id,recipeCostDeltaMinor:currRecipe-prevRecipe,menuMarginDeltaMinor:(sellingPriceMinor-currRecipe)-(sellingPriceMinor-prevRecipe),evidence:{processingKey:pk,previousInvoice:previous.invoiceId,currentInvoice:current.invoiceId,currentSource:current.sourceObject,currentLine:current.lineId,mappingEvidence:mapping.evidence}};
 return{status:"VERIFIED",processingKey:pk,alerts:[alert]};
}
export function appendOnce(history,event){const k=key(event);if(history.some(x=>key(x)===k))return{history,replayed:true};return{history:Object.freeze([...history,Object.freeze({...event})]),replayed:false}}
