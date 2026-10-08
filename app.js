const $ = id => document.getElementById(id);
const esc = s => s.replace(/&/g,"&amp;").replace(/</g,"&lt;");
const sleep = ms => new Promise(r => setTimeout(r, ms));

const CONTRACTS = {
  vuln: { name:"vulnerable.sol", bad:[16,19], good:[], src:null },
  fixed:{ name:"fixed.sol",      bad:[],      good:[16,19], src:null }
};
// Embedded copies so the page also works when opened from disk (file://)
CONTRACTS.vuln.src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: sends ether BEFORE updating the balance (Reentrancy)
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }
}`;
CONTRACTS.fixed.src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // FIXED: Checks-Effects-Interactions (update state first, then send)
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }
}`;
// In fixed.sol the reset is line 16 and the call is line 18
CONTRACTS.fixed.good = [16,18];

let current = "vuln", scanning = false;

function renderCode() {
  const c = CONTRACTS[current];
  $("fileName").textContent = c.name;
  $("code").innerHTML = c.src.split("\n").map((l,i) => {
    const n = i+1, cls = c.bad.includes(n) ? "bad" : c.good.includes(n) ? "good" : "";
    return `<span class="ln ${cls}">${String(n).padStart(2," ")}  ${esc(l)}</span>`;
  }).join("");
}
function pick(btnOn, btnOff, key) {
  $(btnOn).setAttribute("aria-pressed","true"); $(btnOff).setAttribute("aria-pressed","false");
}
$("tabVuln").onclick = () => { current="vuln"; pick("tabVuln","tabFixed"); renderCode(); $("term").innerHTML='<span class="mute">$ press "Run slither"</span>'; };
$("tabFixed").onclick = () => { current="fixed"; pick("tabFixed","tabVuln"); renderCode(); $("term").innerHTML='<span class="mute">$ press "Run slither"</span>'; };

const OUT = {
  vuln: [
    ["$ slither contracts/vulnerable.sol","mute"],
    ["","" ],
    ["Reentrancy in VulnerableBank.withdraw() (vulnerable.sol#12-20):","red"],
    ["\tExternal calls:","" ],
    ["\t- (success) = msg.sender.call{value: balance}() (vulnerable.sol#16)","amber"],
    ["\tState variables written after the call(s):","" ],
    ["\t- balances[msg.sender] = 0 (vulnerable.sol#19)","amber"],
    ["Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities","mute"],
    ["","" ],
    ["Low level call in VulnerableBank.withdraw() (vulnerable.sol#16):","amber"],
    ["\t- (success) = msg.sender.call{value: balance}() (vulnerable.sol#16)","" ],
    ["","" ],
    ["vulnerable.sol analyzed (1 contracts with 100 detectors), findings: reentrancy-eth (High), low-level-calls (Info)","red"]
  ],
  fixed: [
    ["$ slither contracts/fixed.sol","mute"],
    ["","" ],
    ["Low level call in SafeBank.withdraw() (fixed.sol#18):","amber"],
    ["\t- (success) = msg.sender.call{value: balance}() (fixed.sol#18)","" ],
    ["","" ],
    ["fixed.sol analyzed (1 contracts with 100 detectors), no High findings. Reentrancy is gone.","green"]
  ]
};

$("runScan").onclick = async () => {
  if (scanning) return; scanning = true;
  const t = $("term"); t.innerHTML = "";
  for (const [line, cls] of OUT[current]) {
    t.innerHTML += `<span class="${cls}">${esc(line)}</span>\n`;
    await sleep(line ? 260 : 80);
  }
  scanning = false;
};

// ---------- Live reentrancy attack simulation ----------
let target = "vuln", attacking = false;
$("atkVuln").onclick = () => { target="vuln"; pick("atkVuln","atkFixed"); resetAtk(); };
$("atkFixed").onclick = () => { target="fixed"; pick("atkFixed","atkVuln"); resetAtk(); };

function resetAtk(){
  $("bankBal").textContent = 31; $("atkBal").textContent = 0; $("depth").textContent = 0;
  $("atkLog").innerHTML = '<span class="mute">Pick a bank and launch the attack.</span>';
}
function simulate(kind) {
  // Faithful model of the two withdraw() implementations.
  const bank = { bal: 31, balances: { attacker: 1 } };
  let atk = 0, depth = 0; const log = [];
  function withdraw() {
    const b = bank.balances.attacker;
    if (b <= 0) { log.push(["withdraw() reverted: Insufficient balance","green"]); return; }
    if (kind === "fixed") { bank.balances.attacker = 0; log.push(["balances[attacker] = 0  (effect first)","green"]); }
    if (bank.bal >= b) {
      bank.bal -= b; atk += b; depth++;
      log.push([`send ${b} ETH to attacker  | bank=${bank.bal} attacker=${atk}`,"red", bank.bal, atk, depth]);
      if (depth < 40) withdraw();          // attacker's receive() calls withdraw() again
    }
    if (kind === "vuln") bank.balances.attacker = 0;
  }
  withdraw();
  return log;
}
$("runAtk").onclick = async () => {
  if (attacking) return; attacking = true; resetAtk();
  const L = $("atkLog"); L.innerHTML = "";
  L.innerHTML += `<span class="blue">attacker deposits 1 ETH, calls withdraw() on ${target==="vuln"?"VulnerableBank":"SafeBank"}</span>\n`;
  for (const [text, cls, bb, ab, d] of simulate(target)) {
    L.innerHTML += `<span class="${cls}">${esc(text)}</span>\n`;
    if (bb !== undefined) { $("bankBal").textContent = bb; $("atkBal").textContent = ab; $("depth").textContent = d; }
    await sleep(110); L.scrollTop = L.scrollHeight;
  }
  L.innerHTML += target==="vuln"
    ? `<span class="red">Attacker walked away with 31 ETH from a 1 ETH deposit. The bank is empty.</span>`
    : `<span class="green">Only the attacker's own 1 ETH came back. Honest users' 30 ETH is safe.</span>`;
  attacking = false;
};

renderCode();
