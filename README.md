# Findings — Solana DeFi Security

Selected vulnerability discoveries with reproducible Proof of Concept.

Each finding follows a standard structure:
- **Root cause** — what invariant is violated and why
- **Impact** — concrete financial loss assessment
- **Proof of Concept** — self-contained Anchor test reproducing the bug
- **Mitigation** — specific code fix, not generic advice

---

## Findings Index

| ID | Protocol Type | Severity | Invariant | Description |
|----|---------------|----------|-----------|-------------|
| [F-001](./F-001/) | Lending (Compound-style) | Critical | I2 (No Mint Inflation) | Exchange rate formula uses deposit_tokens instead of vault_balance — enables mint inflation |
| [F-002](./F-002/) | Oracle Integration | Critical | CROSS-1 (Manipulation Cost) | TWAP window configurable to 1 slot — enables atomic oracle manipulation + borrow |
| [F-003](./F-003/) | Lending (Index-based) | Medium | ORA-3 (Stale Price) | Permanent oracle cache without staleness check — protocol operates on stale price data |

---

## Methodology

All findings are discovered through a combination of:

1. **Invariant specification** — formalizing the protocol's expected mathematical properties
2. **Differential analysis** — modeling the protocol state machine and checking invariants across random state transitions
3. **Manual code review** — verifying invariant-sensitive paths in the Anchor source code
4. **Edge case testing** — first deposit, full withdrawal, maximum utilization, oracle boundary conditions

---

## Disclosure

All findings were responsibly disclosed to the affected protocols through their respective bug bounty platforms before publication. Proof of Concept tests are self-contained and do not target any live deployment.
