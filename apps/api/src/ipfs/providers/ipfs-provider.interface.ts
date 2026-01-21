export interface IpfsProvider {
  pinFile(data: Buffer, metadata?: Record<string, string>): Promise<{ cid: string; size: number }>;
  unpinFile(cid: string): Promise<void>;
  getFile(cid: string): Promise<Buffer>;
}

export const IPFS_PROVIDER = 'IPFS_PROVIDER';
