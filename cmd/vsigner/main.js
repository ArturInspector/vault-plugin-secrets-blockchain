const { ethers } = require("ethers");
const fs = require("fs");
const COUNT = 10000;
let wallets = [];

for (let i = 0; i < COUNT; i++) {
    const wallet = ethers.Wallet.createRandom();
    wallets.push({
        address: wallet.address,
        privateKey: wallet.privateKey
    });
}
fs.writeFileSync("wallets.json", JSON.stringify(wallets, null, 2));
console.log("Done");