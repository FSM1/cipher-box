"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InjectFlowProducer = void 0;
const common_1 = require("@nestjs/common");
const utils_1 = require("../utils");
/**
 * Injects Bull's flow producer instance with the given name
 * @param name flow producer name
 *
 * @publicApi
 */
const InjectFlowProducer = (name) => (0, common_1.Inject)((0, utils_1.getFlowProducerToken)(name));
exports.InjectFlowProducer = InjectFlowProducer;
