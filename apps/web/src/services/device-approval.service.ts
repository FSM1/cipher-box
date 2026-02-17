/**
 * Device Approval API Client
 *
 * Thin wrapper around the generated Orval client for the bulletin board API
 * used in cross-device factor transfer. Maintains the same external API surface
 * (deviceApprovalApi object with 5 methods) consumed by useDeviceApproval hook.
 *
 * Types are re-exported from the generated models for backward compatibility.
 */

import {
  deviceApprovalControllerCreateRequest,
  deviceApprovalControllerGetStatus,
  deviceApprovalControllerGetPending,
  deviceApprovalControllerRespond,
  deviceApprovalControllerCancel,
} from '../api/device-approval/device-approval';

import type { CreateApprovalDto, RespondApprovalDto } from '../api/models';
import type { DeviceApprovalControllerGetStatus200 } from '../api/models/deviceApprovalControllerGetStatus200';
import type { DeviceApprovalControllerGetPending200Item } from '../api/models/deviceApprovalControllerGetPending200Item';

// Re-export types with original names for backward compatibility
export type CreateApprovalRequest = CreateApprovalDto;

export type ApprovalStatusResponse = DeviceApprovalControllerGetStatus200;

export type PendingApproval = DeviceApprovalControllerGetPending200Item;

export type RespondApprovalRequest = RespondApprovalDto;

export const deviceApprovalApi = {
  /**
   * Create a new device approval request on the bulletin board.
   * Called by the new (requesting) device.
   */
  createRequest: async (dto: CreateApprovalDto): Promise<{ requestId: string }> => {
    const result = await deviceApprovalControllerCreateRequest(dto);
    if (!result.requestId) {
      throw new Error('Server did not return a requestId');
    }
    return { requestId: result.requestId };
  },

  /**
   * Poll the status of an approval request.
   * Called by the new device to check if approved/denied/expired.
   */
  getStatus: async (requestId: string): Promise<ApprovalStatusResponse> => {
    return deviceApprovalControllerGetStatus(requestId);
  },

  /**
   * Get all pending approval requests for the current user.
   * Called by existing (approving) devices.
   */
  getPending: async (): Promise<PendingApproval[]> => {
    return deviceApprovalControllerGetPending();
  },

  /**
   * Respond to a pending approval request (approve or deny).
   * Called by the existing device.
   */
  respond: async (requestId: string, dto: RespondApprovalDto): Promise<void> => {
    await deviceApprovalControllerRespond(requestId, dto);
  },

  /**
   * Cancel a pending approval request.
   * Called by the requesting device to clean up.
   */
  cancel: async (requestId: string): Promise<void> => {
    await deviceApprovalControllerCancel(requestId);
  },
};
