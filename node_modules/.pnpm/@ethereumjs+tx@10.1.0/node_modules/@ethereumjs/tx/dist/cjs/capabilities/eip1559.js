"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getUpfrontCost = getUpfrontCost;
exports.getEffectivePriorityFee = getEffectivePriorityFee;
const util_1 = require("@ethereumjs/util");
function getUpfrontCost(tx, baseFee) {
    const prio = tx.maxPriorityFeePerGas;
    const maxBase = tx.maxFeePerGas - baseFee;
    const inclusionFeePerGas = prio < maxBase ? prio : maxBase;
    const gasPrice = inclusionFeePerGas + baseFee;
    return tx.gasLimit * gasPrice + tx.value;
}
function getEffectivePriorityFee(tx, baseFee) {
    if (baseFee === undefined || baseFee > tx.maxFeePerGas) {
        throw (0, util_1.EthereumJSErrorWithoutCode)('Tx cannot pay baseFee');
    }
    // The remaining fee for the coinbase, which can take up to this value, capped at `maxPriorityFeePerGas`
    const remainingFee = tx.maxFeePerGas - baseFee;
    return tx.maxPriorityFeePerGas < remainingFee ? tx.maxPriorityFeePerGas : remainingFee;
}
//# sourceMappingURL=eip1559.js.map