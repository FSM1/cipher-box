import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { RegisterCidDto } from './register-cid.dto';

describe('RegisterCidDto', () => {
  async function validateDto(plain: Partial<RegisterCidDto>) {
    const dto = plainToInstance(RegisterCidDto, plain);
    return validate(dto);
  }

  it('accepts a valid CIDv1 (D-02 invariant — CIDv1 must be kept)', async () => {
    const errors = await validateDto({
      cid: 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi',
      sizeBytes: 100,
    });
    expect(errors).toHaveLength(0);
  });

  // RED: the current loose {44,} regex wrongly accepts a CIDv0 with 47 base58 chars after Qm
  it('rejects a CIDv0 with {44,} overflow — 47 chars after Qm (D-01)', async () => {
    // 47 base58 chars after Qm = 49 total chars (one too many for a real CIDv0)
    const overflowCidv0 = 'Qm' + '1'.repeat(47);
    const errors = await validateDto({ cid: overflowCidv0, sizeBytes: 100 });
    const cidErrors = errors.filter((e) => e.property === 'cid');
    expect(cidErrors.length).toBeGreaterThanOrEqual(1);
  });

  // RED: current DTO has no @MaxLength(255) so a 256+ char string slips through
  it('rejects a cid string longer than 255 chars (D-01 @MaxLength)', async () => {
    const longCid = 'b' + 'a'.repeat(300);
    const errors = await validateDto({ cid: longCid, sizeBytes: 100 });
    const cidErrors = errors.filter((e) => e.property === 'cid');
    expect(cidErrors.length).toBeGreaterThanOrEqual(1);
  });

  it('accepts a canonical 46-char CIDv0 (D-01 sanity)', async () => {
    // A real CIDv0: Qm + exactly 44 base58 chars = 46 total chars
    const validCidv0 = 'QmPK1s3pNYLi9ERiq3BDxKa4XosgWwFRQUydHUtz4YgpqB';
    const errors = await validateDto({ cid: validCidv0, sizeBytes: 100 });
    expect(errors).toHaveLength(0);
  });
});
