# Blockchain Security – Slither Tool Discovery

Group project (VGEC): Goswami Manik, Rana Jaydeep, Solanki Sharang, Vahya Vivek.

Tool discovered: **Slither** (Trail of Bits) – static analysis for Solidity smart contracts.

## What is in this repo
- `index.html`, `styles.css`, `app.js` – interactive demo page (hosted on GitHub Pages)
  - Scan view of `vulnerable.sol` vs `fixed.sol`
  - Live reentrancy attack simulator (vulnerable vs fixed)
- `contracts/vulnerable.sol` – bank with a reentrancy bug
- `contracts/fixed.sol` – same bank patched with Checks-Effects-Interactions
- `slither_report.md` – commands to generate the real Slither output

## Run Slither yourself
```bash
pip install slither-analyzer solc-select
solc-select install 0.8.20 && solc-select use 0.8.20
slither contracts/vulnerable.sol
```

## Deploy on GitHub Pages
1. Push all files to a repo. 2. Settings -> Pages -> Deploy from branch `main` / root. 3. Open the generated link.
