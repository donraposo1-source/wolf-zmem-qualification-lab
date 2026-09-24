# Invoice price impact bounded harvest v1

Reference donor: karlomikus/bar-assistant@ef64de6dc679a09b928e543d08e455efba73640a (MIT, Copyright (c) 2022 Karlo Mikuš).
Referenced concepts: Price, IngredientPrice, PriceCategory, AmountWithUnits, CocktailIngredient, MaterializedPath.
This implementation is a Wolf-oriented behavioral/domain reimplementation for laboratory evaluation. It deliberately does not import Laravel, Eloquent, PHP runtime, BarInventory, or Menu implementation.
Currency amounts use integer minor units. Unit-cost and margin-impact semantics are Wolf MVP-C-specific additions and require independent verification before canonical integration.
