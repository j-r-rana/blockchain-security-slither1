# Slither report (how to generate the REAL one)

Run on your laptop and paste the real output here before submitting:

```bash
pip install slither-analyzer solc-select
solc-select install 0.8.20 && solc-select use 0.8.20
slither contracts/vulnerable.sol  > slither_report.txt 2>&1
slither contracts/fixed.sol       > slither_report_fixed.txt 2>&1
```

Expected main finding on `vulnerable.sol`: **reentrancy-eth** (High) in `VulnerableBank.withdraw()` –
external call at line 16 and state variable `balances[msg.sender]` written after it at line 19.
On `fixed.sol` the reentrancy finding disappears.
