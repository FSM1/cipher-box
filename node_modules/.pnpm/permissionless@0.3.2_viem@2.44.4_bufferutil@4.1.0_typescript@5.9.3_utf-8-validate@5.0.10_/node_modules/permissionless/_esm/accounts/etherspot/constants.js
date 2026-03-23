export const DUMMY_ECDSA_SIGNATURE = "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c";
export const VALIDATOR_TYPE = {
    ROOT: "0x00",
    VALIDATOR: "0x01",
    PERMISSION: "0x02"
};
export var VALIDATOR_MODE;
(function (VALIDATOR_MODE) {
    VALIDATOR_MODE["DEFAULT"] = "0x00";
    VALIDATOR_MODE["ENABLE"] = "0x01";
})(VALIDATOR_MODE || (VALIDATOR_MODE = {}));
export const DEFAULT_CONTRACT_ADDRESS = {
    metaFactoryAddress: "0x2A40091f044e48DEB5C0FCbc442E443F3341B451", // modularEtherspotWalletFactory
    bootstrapAddress: "0x0D5154d7751b6e2fDaa06F0cC9B400549394C8AA",
    validatorAddress: "0x0740Ed7c11b9da33d9C80Bd76b826e4E90CC1906" // multipleOwnerECDSAValidator
};
//# sourceMappingURL=constants.js.map