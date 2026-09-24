export const prior={GIN:{paidMinor:1800,ml:1000},VERMOUTH:{paidMinor:900,ml:750},CAMPARI:{paidMinor:1400,ml:700}};
export const invoice={tenantId:"tenant-demo",barId:"bar-demo",invoiceId:"SUP-2026-1042",sourceObject:"fixture/supplier-2026-1042-v1",supplierId:"SUP-DEMO",currency:"EUR",lines:[
{lineId:"1",sku:"GIN-1L",description:"London Dry Gin 1L",qty:1,unit:"L",lineMinor:1950,map:"GIN"},
{lineId:"2",sku:"VERM-75",description:"Rosso Vermouth 75cl",qty:1,unit:"cl",size:75,lineMinor:960,map:"VERMOUTH"},
{lineId:"3",sku:"BIT-70",description:"Campari Bitter 70cl",qty:1,unit:"cl",size:70,lineMinor:1540,map:"CAMPARI"},
{lineId:"4",sku:null,description:"House Botanical Special 50cl",qty:1,unit:"cl",size:50,lineMinor:700,map:null},
{lineId:"5",kind:"discount",description:"Commercial discount",lineMinor:-100},
{lineId:"6",kind:"tax",description:"VAT 23%",lineMinor:1161}
]};
export const recipes=[{id:"NEGRONI",ingredients:{GIN:30,VERMOUTH:30,CAMPARI:30},sellingMinor:1200},{id:"AMERICANO",ingredients:{VERMOUTH:30,CAMPARI:30},sellingMinor:900}];
