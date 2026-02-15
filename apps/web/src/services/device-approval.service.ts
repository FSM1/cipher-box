/**
 * Device Approval API Client
 *
 * Provides typed methods for the bulletin board API used in cross-device
 * factor transfer. Uses apiClient which automatically attaches the Bearer
 * token from useAuthStore.
 *
 * NOTE: After Plan 05 runs `pnpm api:generate`, these may be replaced by
 * the generated client. For now, manual apiClient calls are used.
 */

import { apiClient } from '../lib/api/client';

export type CreateApprovalRequest = {
  deviceId: string;
  deviceName: string;
  ephemeralPublicKey: string;
};

export type ApprovalStatusResponse = {
  status: 'pending' | 'approved' | 'denied' | 'expired';
  encryptedFactorKey?: string;
};

export type PendingApproval = {
  requestId: string;
  deviceId: string;
  deviceName: string;
  ephemeralPublicKey: string;
  createdAt: string;
  expiresAt: string;
};

export type RespondApprovalRequest = {
  action: 'approve' | 'deny';
  encryptedFactorKey?: string;
  respondedByDeviceId: string;
};

export const deviceApprovalApi = {
  /**
   * Create a new device approval request on the bulletin board.
   * Called by the new (requesting) device.
   */
  createRequest: async (dto: CreateApprovalRequest): Promise<{ requestId: string }> => {
    const response = await apiClient.post<{ requestId: string }>('/device-approval/request', dto);
    return response.data;
  },

  /**
   * Poll the status of an approval request.
   * Called by the new device to check if approved/denied/expired.
   */
  getStatus: async (requestId: string): Promise<ApprovalStatusResponse> => {
    const response = await apiClient.get<ApprovalStatusResponse>(
      `/device-approval/${requestId}/status`
    );
    return response.data;
  },

  /**
   * Get all pending approval requests for the current user.
   * Called by existing (approving) devices.
   */
  getPending: async (): Promise<PendingApproval[]> => {
    const response = await apiClient.get<PendingApproval[]>('/device-approval/pending');
    return response.data;
  },

  /**
   * Respond to a pending approval request (approve or deny).
   * Called by the existing device.
   */
  respond: async (requestId: string, dto: RespondApprovalRequest): Promise<void> => {
    await apiClient.post(`/device-approval/${requestId}/respond`, dto);
  },

  /**
   * Cancel a pending approval request.
   * Called by the requesting device to clean up.
   */
  cancel: async (requestId: string): Promise<void> => {
    await apiClient.delete(`/device-approval/${requestId}`);
  },
};
