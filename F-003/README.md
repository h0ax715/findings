# F-003: Permanent Oracle Cache Without Invalidation

**Severity:** Medium  
**Protocol Type:** Lending (Index-based, K2 Stellar/Soroban)  
**Invariant Violated:** ORA-3 (Stale Price → Revert)  
**Date:** 2026

---

## Description

The lending protocol's interest rate model fetches an oracle price but caches the result indefinitely. Once cached, the value is never refreshed unless a specific manual operation is triggered. Between manual refreshes, any change in the underlying oracle price is completely ignored — the protocol operates on stale data.

This differs from TWAP staleness checks (where a price older than X seconds causes a revert). Here, there is no staleness threshold at all — the cache has no TTL.

## Impact

**Direct:** If the oracle price drops significantly, borrowers using the stale (higher) cached price can borrow more than their collateral is worth. If the oracle price rises, depositors receive fewer shares than fair.

**Attack scenario:** An attacker monitors the oracle price, identifies a favorable divergence between the real price and the cached price, and opens a position at the favorable rate before anyone triggers a cache refresh.

**Real-world likelihood:** Medium. The protocol relies on keepers/automation to refresh the cache, but between refreshes there is a window where the protocol's internal price diverges from the market.

## Root Cause

The oracle value is computed once during initialization and stored in a contract field. It is only updated when a specific `refresh()` function is called. There is no staleness check — any accounting operation (deposit, borrow, withdraw, liquidate) uses whatever value is currently cached, regardless of when it was last updated.

```
┌─────────────┐     refresh()      ┌──────────────┐
│   Oracle    │ ────────────────→  │   Protocol   │
│  (external) │                    │  (uses cache) │
└─────────────┘                    └──────────────┘
        │                                  │
   Price changes                     deposit()  
   (ignored)                         borrow()
                                     liquidate()
                                     → all use stale cache
```

## Recommended Mitigation

Add a staleness threshold to the cached value. Ideally, every accounting operation should check whether the cache is fresh:

```
if block.timestamp - last_refresh > STALENESS_THRESHOLD:
    revert StalePrice()
```

Alternatively, refresh the cache automatically on every accounting operation before using the price, with a reasonable freshness requirement.

## Invariant Reference

ORA-3 — Stale Price → Revert: operations using a stale price must revert if `current_time - last_update > staleness_threshold`.

---

## References

- K2 Lending Protocol (Stellar/Soroban)
- Response to this finding: rate oracles now refresh automatically on every borrow/repay
