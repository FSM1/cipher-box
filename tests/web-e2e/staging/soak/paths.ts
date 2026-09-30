/** The soak folder names both vaults share. A leaf module, so a desktop leg imports it without the web fixtures. */

/** The top-level folder of the soak, in both vaults. */
export const SOAK_FOLDER = 'soak';

/** The ledger file name, in `soak/` for the owner and in the desktop folder for the grantee. */
export const LEDGER_FILE = 'ledger.txt';

/** The grantee's desktop folder, from the vault root. The web bootstrap builds it. */
export const DESKTOP_FOLDER: readonly string[] = [SOAK_FOLDER, 'desktop'];
