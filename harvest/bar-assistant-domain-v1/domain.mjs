export function abv(value){if(!Number.isFinite(value)||value<0||value>100)throw new RangeError("ABV strength must be between 0.0 and 100.0");return value}
export function dilution(value){if(!Number.isFinite(value)||value<0||value>100)throw new RangeError("Dilution must be between 0.0 and 100.0");return {percent:value,decimal:value/100}}
export function normalizeUnit(value){return String(value??"").trim().toLowerCase()}
export function convertAmount(amount,from,to){from=normalizeUnit(from);to=normalizeUnit(to);if(from===to)return amount;const ml={ml:1,cl:10,oz:30};if(!(from in ml)||!(to in ml))return null;return Math.round((amount*ml[from]/ml[to])*10000)/10000}
export function amountWithUnits(amountMin,units,amountMax=null){const u=normalizeUnit(units);return {amount:amountMin,units:u,amount_max:amountMax}}
