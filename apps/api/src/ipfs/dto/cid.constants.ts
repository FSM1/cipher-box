// IN-02: CID format regex covers CIDv0 (Qm... base58, 46 chars) and
// CIDv1 (b... base32, 59+ chars). MaxLength(255) bounds the input to
// prevent oversized-string DoS at the route boundary (T-50-12).
export const CID_REGEX = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/;
