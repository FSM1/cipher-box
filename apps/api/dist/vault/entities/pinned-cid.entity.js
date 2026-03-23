"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PinnedCid = void 0;
const typeorm_1 = require("typeorm");
const user_entity_1 = require("../../auth/entities/user.entity");
let PinnedCid = class PinnedCid {
    id;
    userId;
    user;
    /**
     * IPFS CID (Content Identifier) for the pinned content
     * CIDv1 format (base32 encoded)
     */
    cid;
    /**
     * Size of the pinned content in bytes
     * Used for quota tracking (500 MiB limit)
     */
    sizeBytes; // TypeORM returns bigint as string
    pinnedAt;
};
exports.PinnedCid = PinnedCid;
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)('uuid'),
    __metadata("design:type", String)
], PinnedCid.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Index)(),
    (0, typeorm_1.Column)({ type: 'uuid', name: 'user_id' }),
    __metadata("design:type", String)
], PinnedCid.prototype, "userId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => user_entity_1.User, { onDelete: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'user_id' }),
    __metadata("design:type", user_entity_1.User)
], PinnedCid.prototype, "user", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'varchar', length: 255 }),
    __metadata("design:type", String)
], PinnedCid.prototype, "cid", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bigint', name: 'size_bytes' }),
    __metadata("design:type", String)
], PinnedCid.prototype, "sizeBytes", void 0);
__decorate([
    (0, typeorm_1.CreateDateColumn)({ name: 'pinned_at' }),
    __metadata("design:type", Date)
], PinnedCid.prototype, "pinnedAt", void 0);
exports.PinnedCid = PinnedCid = __decorate([
    (0, typeorm_1.Entity)('pinned_cids'),
    (0, typeorm_1.Unique)(['userId', 'cid'])
], PinnedCid);
//# sourceMappingURL=pinned-cid.entity.js.map