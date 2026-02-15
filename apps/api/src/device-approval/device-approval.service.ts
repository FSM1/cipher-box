import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, MoreThan } from 'typeorm';
import { DeviceApproval } from './device-approval.entity';
import { CreateApprovalDto } from './dto/create-approval.dto';
import { RespondApprovalDto } from './dto/respond-approval.dto';

/** Approval request TTL: 5 minutes */
const TTL_MS = 5 * 60 * 1000;

@Injectable()
export class DeviceApprovalService {
  constructor(
    @InjectRepository(DeviceApproval)
    private readonly repo: Repository<DeviceApproval>
  ) {}

  /**
   * Create a new approval request for a device.
   * Sets expiresAt to 5 minutes from now.
   */
  async createRequest(userId: string, dto: CreateApprovalDto): Promise<{ requestId: string }> {
    const approval = this.repo.create({
      userId,
      deviceId: dto.deviceId,
      deviceName: dto.deviceName,
      ephemeralPublicKey: dto.ephemeralPublicKey,
      status: 'pending',
      expiresAt: new Date(Date.now() + TTL_MS),
    });

    const saved = await this.repo.save(approval);
    return { requestId: saved.id };
  }

  /**
   * Get the status of an approval request.
   * Auto-expires pending requests that have passed their TTL.
   */
  async getStatus(
    requestId: string,
    userId: string
  ): Promise<{
    status: string;
    encryptedFactorKey?: string;
  }> {
    const approval = await this.repo.findOne({
      where: { id: requestId, userId },
    });

    if (!approval) {
      throw new NotFoundException('Approval request not found');
    }

    // Auto-expire pending requests past TTL
    if (approval.status === 'pending' && approval.expiresAt < new Date()) {
      approval.status = 'expired';
      await this.repo.save(approval);
    }

    return {
      status: approval.status,
      ...(approval.encryptedFactorKey ? { encryptedFactorKey: approval.encryptedFactorKey } : {}),
    };
  }

  /**
   * Get all pending (non-expired) approval requests for a user.
   */
  async getPending(userId: string): Promise<
    Array<{
      requestId: string;
      deviceId: string;
      deviceName: string;
      ephemeralPublicKey: string;
      createdAt: Date;
      expiresAt: Date;
    }>
  > {
    const approvals = await this.repo.find({
      where: {
        userId,
        status: 'pending' as const,
        expiresAt: MoreThan(new Date()),
      },
      order: { createdAt: 'DESC' },
    });

    return approvals.map((a) => ({
      requestId: a.id,
      deviceId: a.deviceId,
      deviceName: a.deviceName,
      ephemeralPublicKey: a.ephemeralPublicKey,
      createdAt: a.createdAt,
      expiresAt: a.expiresAt,
    }));
  }

  /**
   * Respond to an approval request (approve or deny).
   * On approve, stores the ECIES-encrypted factor key.
   */
  async respond(requestId: string, userId: string, dto: RespondApprovalDto): Promise<void> {
    const approval = await this.repo.findOne({
      where: { id: requestId, userId },
    });

    if (!approval) {
      throw new NotFoundException('Approval request not found');
    }

    if (approval.status !== 'pending') {
      throw new BadRequestException('Approval request has already been responded to');
    }

    if (approval.expiresAt < new Date()) {
      approval.status = 'expired';
      await this.repo.save(approval);
      throw new BadRequestException('Approval request has expired');
    }

    // H-02: Prevent self-approval — responding device must differ from requesting device
    if (dto.respondedByDeviceId === approval.deviceId) {
      throw new BadRequestException('A device cannot approve its own request');
    }

    if (dto.action === 'approve') {
      // H-03: Require encryptedFactorKey when approving (defense-in-depth)
      if (!dto.encryptedFactorKey) {
        throw new BadRequestException('encryptedFactorKey is required when approving');
      }
      approval.encryptedFactorKey = dto.encryptedFactorKey;
    }

    approval.status = dto.action === 'approve' ? 'approved' : 'denied';
    approval.respondedBy = dto.respondedByDeviceId;
    await this.repo.save(approval);
  }

  /**
   * Cancel a pending approval request.
   * Only works for pending requests owned by the calling user.
   */
  async cancel(requestId: string, userId: string): Promise<void> {
    const approval = await this.repo.findOne({
      where: { id: requestId, userId },
    });

    if (!approval) {
      throw new NotFoundException('Approval request not found');
    }

    if (approval.status !== 'pending') {
      throw new NotFoundException('Only pending requests can be cancelled');
    }

    await this.repo.remove(approval);
  }
}
