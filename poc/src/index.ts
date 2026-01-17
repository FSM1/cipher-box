import { create } from "ipfs-http-client";
import dotenv from "dotenv";
import { randomBytes, createCipheriv, createDecipheriv } from "crypto";
import { encrypt as eciesEncrypt, decrypt as eciesDecrypt } from "eciesjs";
import { getPublicKey } from "@noble/secp256k1";
import { mkdir, readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import path from "path";

dotenv.config({ override: true });

type FolderEntry = {
    type: "folder";
    nameEncrypted: string;
    nameIv: string;
    ipnsName: string;
    folderKeyEncrypted: string;
    ipnsKeyNameEncrypted: string;
    created: number;
    modified: number;
};

type FileEntry = {
    type: "file";
    nameEncrypted: string;
    nameIv: string;
    cid: string;
    fileKeyEncrypted: string;
    fileIv: string;
    size: number;
    created: number;
    modified: number;
};

type FolderMetadata = {
    children: Array<FolderEntry | FileEntry>;
    metadata: {
        created: number;
        modified: number;
    };
};

type FolderState = {
    name: string;
    key: Uint8Array;
    ipnsName: string;
    ipnsKeyName: string;
    metadata: FolderMetadata;
    latestMetadataCid?: string;
};

type PinataConfig = {
    apiKey: string;
    apiSecret: string;
};

type HarnessContext = {
    ipfs: ReturnType<typeof create>;
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    stateDir: string;
    pinnedCids: Set<string>;
    ipnsKeyNames: Set<string>;
    pinata?: PinataConfig;
    pollIntervalMs: number;
    pollTimeoutMs: number;
    stressChildrenCount: number;
    stressChildType: "file" | "folder";
};

const TAG_SIZE = 16;
const IV_SIZE = 12;

const logStep = (message: string) => {
    console.log(`\n=== ${message} ===`);
};

const formatBytes = (value: number): string => {
    if (value < 1024) return `${value} B`;
    const kb = value / 1024;
    if (kb < 1024) return `${kb.toFixed(2)} KiB`;
    const mb = kb / 1024;
    return `${mb.toFixed(2)} MiB`;
};

const getRecordSize = (record: unknown): number | null => {
    if (record instanceof Uint8Array) {
        return record.byteLength;
    }
    if (record && typeof record === "object" && "value" in record) {
        const value = (record as { value?: unknown }).value;
        if (value instanceof Uint8Array) {
            return value.byteLength;
        }
    }
    return null;
};

const logIpnsRecordSize = async (ctx: HarnessContext, ipnsName: string, label: string): Promise<void> => {
    try {
        const record = await ctx.ipfs.routing.get(ipnsName);
        const size = getRecordSize(record);
        if (size === null) {
            console.warn(`IPNS record size unavailable for ${label}`);
            return;
        }
        console.log(`IPNS record size for ${label}: ${formatBytes(size)}`);
    } catch (error) {
        console.warn(`IPNS record size fetch failed for ${label}: ${(error as Error).message}`);
    }
};

const hexToBytes = (hex: string): Uint8Array => {
    const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
    return Uint8Array.from(Buffer.from(normalized, "hex"));
};

const bytesToHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

const utf8ToBytes = (value: string): Uint8Array => Buffer.from(value, "utf8");
const bytesToUtf8 = (value: Uint8Array): string => Buffer.from(value).toString("utf8");

const aesGcmEncrypt = (data: Uint8Array, key: Uint8Array): { ciphertext: Uint8Array; iv: Uint8Array } => {
    const iv = randomBytes(IV_SIZE);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);
    return { ciphertext, iv };
};

const aesGcmDecrypt = (ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array => {
    const data = Buffer.from(ciphertext);
    const tag = data.subarray(data.length - TAG_SIZE);
    const body = data.subarray(0, data.length - TAG_SIZE);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]);
};

const eciesEncryptBytes = (publicKey: Uint8Array, data: Uint8Array): Uint8Array => {
    return eciesEncrypt(publicKey, data);
};

const eciesDecryptBytes = (privateKey: Uint8Array, data: Uint8Array): Uint8Array => {
    return eciesDecrypt(privateKey, data);
};

const encryptName = (name: string, folderKey: Uint8Array): { nameEncrypted: string; nameIv: string } => {
    const { ciphertext, iv } = aesGcmEncrypt(utf8ToBytes(name), folderKey);
    return {
        nameEncrypted: bytesToHex(ciphertext),
        nameIv: bytesToHex(iv),
    };
};

const decryptName = (nameEncrypted: string, nameIv: string, folderKey: Uint8Array): string => {
    const plaintext = aesGcmDecrypt(hexToBytes(nameEncrypted), folderKey, hexToBytes(nameIv));
    return bytesToUtf8(plaintext);
};

const encryptMetadata = (metadata: FolderMetadata, folderKey: Uint8Array): { encryptedMetadata: string; iv: string } => {
    const payload = utf8ToBytes(JSON.stringify(metadata));
    const { ciphertext, iv } = aesGcmEncrypt(payload, folderKey);
    return { encryptedMetadata: bytesToHex(ciphertext), iv: bytesToHex(iv) };
};

const decryptMetadata = (payload: { encryptedMetadata: string; iv: string }, folderKey: Uint8Array): FolderMetadata => {
    const plaintext = aesGcmDecrypt(hexToBytes(payload.encryptedMetadata), folderKey, hexToBytes(payload.iv));
    return JSON.parse(bytesToUtf8(plaintext));
};

const collectChunks = async (iterable: AsyncIterable<Uint8Array>): Promise<Uint8Array> => {
    const chunks: Uint8Array[] = [];
    for await (const chunk of iterable) {
        chunks.push(chunk);
    }
    return Buffer.concat(chunks);
};

const resolveIpnsToCid = async (
    ctx: HarnessContext,
    ipnsName: string,
    options?: { nocache?: boolean }
): Promise<string> => {
    for await (const result of ctx.ipfs.name.resolve(ipnsName, options)) {
        if (typeof result === "string") {
            return result.replace("/ipfs/", "");
        }
        if (typeof result === "object" && result !== null && "path" in result) {
            const { path: resolvedPath } = result as { path: string };
            return resolvedPath.replace("/ipfs/", "");
        }
    }
    throw new Error(`Failed to resolve IPNS name ${ipnsName}`);
};

const waitForIpns = async (ctx: HarnessContext, ipnsName: string, expectedCid: string): Promise<number> => {
    const start = Date.now();
    let attempts = 0;
    while (Date.now() - start < ctx.pollTimeoutMs) {
        const resolvedCid = await resolveIpnsToCid(ctx, ipnsName, { nocache: true });
        if (resolvedCid === expectedCid) {
            return Date.now() - start;
        }
        attempts += 1;
        if (attempts % 5 === 0) {
            const elapsed = Date.now() - start;
            console.log(`Waiting for IPNS ${ipnsName} -> ${expectedCid} (${elapsed}ms elapsed)`);
        }
        await new Promise((resolve) => setTimeout(resolve, ctx.pollIntervalMs));
    }
    throw new Error(`Timed out waiting for IPNS ${ipnsName} to resolve to ${expectedCid}`);
};

const pinCid = async (ctx: HarnessContext, cid: string): Promise<void> => {
    if (!ctx.pinnedCids.has(cid)) {
        await ctx.ipfs.pin.add(cid);
        ctx.pinnedCids.add(cid);
        if (ctx.pinata) {
            await pinataPin(ctx.pinata, cid);
        }
    }
};

const unpinCid = async (ctx: HarnessContext, cid: string): Promise<void> => {
    try {
        await ctx.ipfs.pin.rm(cid);
    } catch (error) {
        console.warn(`Pin rm skipped for ${cid}: ${(error as Error).message}`);
    }
    if (ctx.pinata) {
        await pinataUnpin(ctx.pinata, cid);
    }
};

const pinataPin = async (pinata: PinataConfig, cid: string): Promise<void> => {
    const response = await fetch("https://api.pinata.cloud/pinning/pinByHash", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            pinata_api_key: pinata.apiKey,
            pinata_secret_api_key: pinata.apiSecret,
        },
        body: JSON.stringify({ hashToPin: cid }),
    });
    if (!response.ok) {
        const text = await response.text();
        if (response.status === 403 && text.includes("PAID_FEATURE_ONLY")) {
            console.warn(`Pinata pin skipped for ${cid}: paid plan required.`);
            return;
        }
        throw new Error(`Pinata pin failed for ${cid}: ${response.status} ${text}`);
    }
};

const pinataUnpin = async (pinata: PinataConfig, cid: string): Promise<void> => {
    const response = await fetch(`https://api.pinata.cloud/pinning/unpin/${cid}`, {
        method: "DELETE",
        headers: {
            pinata_api_key: pinata.apiKey,
            pinata_secret_api_key: pinata.apiSecret,
        },
    });
    if (!response.ok && response.status !== 404) {
        const text = await response.text();
        throw new Error(`Pinata unpin failed for ${cid}: ${response.status} ${text}`);
    }
};

const publishFolderMetadata = async (
    ctx: HarnessContext,
    folder: FolderState
): Promise<{ cid: string; delayMs: number }> => {
    console.log(`Publishing metadata for ${folder.name}...`);
    const encrypted = encryptMetadata(folder.metadata, folder.key);
    const payload = JSON.stringify({ version: "1.0", ...encrypted });
    console.log(
        `Metadata size for ${folder.name}: ${formatBytes(Buffer.byteLength(payload, "utf8"))}`
    );
    const { cid } = await ctx.ipfs.add(utf8ToBytes(payload), { pin: false });
    const cidString = cid.toString();
    await pinCid(ctx, cidString);
    await ctx.ipfs.name.publish(`/ipfs/${cidString}`, {
        key: folder.ipnsKeyName,
        allowOffline: true,
    });
    const delayMs = await waitForIpns(ctx, folder.ipnsName, cidString);
    folder.latestMetadataCid = cidString;
    await logIpnsRecordSize(ctx, folder.ipnsName, folder.name);
    return { cid: cidString, delayMs };
};

const fetchFolderMetadata = async (
    ctx: HarnessContext,
    folder: FolderState,
    expectedCid?: string
): Promise<FolderMetadata> => {
    const cid = expectedCid ?? (await resolveIpnsToCid(ctx, folder.ipnsName, { nocache: true }));
    const data = await collectChunks(ctx.ipfs.cat(cid));
    const parsed = JSON.parse(bytesToUtf8(data));
    return decryptMetadata(parsed, folder.key);
};

const generateFolder = async (ctx: HarnessContext, name: string): Promise<FolderState> => {
    const now = Date.now();
    const key = randomBytes(32);
    const keyName = `poc-${name.toLowerCase()}-${now}`;
    const ipnsKey = await ctx.ipfs.key.gen(keyName, { type: "ed25519" as unknown as "Ed25519" });
    ctx.ipnsKeyNames.add(ipnsKey.name);

    const metadata: FolderMetadata = {
        children: [],
        metadata: { created: now, modified: now },
    };

    return {
        name,
        key,
        ipnsName: ipnsKey.id,
        ipnsKeyName: ipnsKey.name,
        metadata,
    };
};

const addSubfolder = async (
    ctx: HarnessContext,
    parent: FolderState,
    child: FolderState
): Promise<void> => {
    const now = Date.now();
    const { nameEncrypted, nameIv } = encryptName(child.name, parent.key);
    const folderKeyEncrypted = bytesToHex(eciesEncryptBytes(ctx.publicKey, child.key));
    const ipnsKeyNameEncrypted = bytesToHex(eciesEncryptBytes(ctx.publicKey, utf8ToBytes(child.ipnsKeyName)));

    const entry: FolderEntry = {
        type: "folder",
        nameEncrypted,
        nameIv,
        ipnsName: child.ipnsName,
        folderKeyEncrypted,
        ipnsKeyNameEncrypted,
        created: now,
        modified: now,
    };

    parent.metadata.children.push(entry);
    parent.metadata.metadata.modified = now;
};

const addFileToFolder = (
    ctx: HarnessContext,
    folder: FolderState,
    fileName: string,
    ciphertext: Uint8Array,
    fileKey: Uint8Array,
    fileIv: Uint8Array
): FileEntry => {
    const now = Date.now();
    const { nameEncrypted, nameIv } = encryptName(fileName, folder.key);
    const fileKeyEncrypted = bytesToHex(eciesEncryptBytes(ctx.publicKey, fileKey));

    return {
        type: "file",
        nameEncrypted,
        nameIv,
        cid: "",
        fileKeyEncrypted,
        fileIv: bytesToHex(fileIv),
        size: ciphertext.length,
        created: now,
        modified: now,
    };
};

const addSyntheticChildren = async (ctx: HarnessContext, folder: FolderState): Promise<void> => {
    const count = ctx.stressChildrenCount;
    if (count <= 0) return;

    const now = Date.now();
    if (ctx.stressChildType === "file") {
        for (let i = 0; i < count; i += 1) {
            const name = `stress-file-${String(i + 1).padStart(5, "0")}.txt`;
            const fileKey = randomBytes(32);
            const { ciphertext, iv } = aesGcmEncrypt(utf8ToBytes("x"), fileKey);
            const entry = addFileToFolder(ctx, folder, name, ciphertext, fileKey, iv);
            entry.cid = "QmStressPlaceholder";
            entry.size = 1;
            entry.created = now;
            entry.modified = now;
            folder.metadata.children.push(entry);
        }
    } else {
        for (let i = 0; i < count; i += 1) {
            const name = `stress-folder-${String(i + 1).padStart(5, "0")}`;
            const { nameEncrypted, nameIv } = encryptName(name, folder.key);
            const folderKey = randomBytes(32);
            const folderKeyEncrypted = bytesToHex(eciesEncryptBytes(ctx.publicKey, folderKey));
            const ipnsKeyNameEncrypted = bytesToHex(
                eciesEncryptBytes(ctx.publicKey, utf8ToBytes(`stress-ipns-${i + 1}`))
            );
            const entry: FolderEntry = {
                type: "folder",
                nameEncrypted,
                nameIv,
                ipnsName: "k51qzi5uqu5dstressplaceholder",
                folderKeyEncrypted,
                ipnsKeyNameEncrypted,
                created: now,
                modified: now,
            };
            folder.metadata.children.push(entry);
        }
    }

    folder.metadata.metadata.modified = Date.now();
    console.log(`Added ${count} synthetic ${ctx.stressChildType} entries to ${folder.name}`);
};

const findFileEntry = (metadata: FolderMetadata, fileName: string, folderKey: Uint8Array): FileEntry => {
    const entry = metadata.children.find((child) => {
        if (child.type !== "file") return false;
        return decryptName(child.nameEncrypted, child.nameIv, folderKey) === fileName;
    });
    if (!entry || entry.type !== "file") {
        throw new Error(`File entry not found for ${fileName}`);
    }
    return entry;
};

const removeFileEntry = (metadata: FolderMetadata, fileName: string, folderKey: Uint8Array): FileEntry => {
    const index = metadata.children.findIndex((child) => {
        if (child.type !== "file") return false;
        return decryptName(child.nameEncrypted, child.nameIv, folderKey) === fileName;
    });
    if (index === -1) {
        throw new Error(`File entry not found for ${fileName}`);
    }
    const [removed] = metadata.children.splice(index, 1);
    return removed as FileEntry;
};

const buildFolderTree = async (
    ctx: HarnessContext,
    folder: FolderState,
    depth = 0,
    maxDepth = 10
): Promise<string[]> => {
    const lines: string[] = [];
    const indent = "  ".repeat(depth);
    lines.push(`${indent}- folder: ${folder.name}`);

    if (depth >= maxDepth) {
        lines.push(`${indent}  - ... depth limit reached`);
        return lines;
    }

    const metadataCid = await resolveIpnsToCid(ctx, folder.ipnsName, { nocache: true });
    folder.latestMetadataCid = metadataCid;
    const metadata = await fetchFolderMetadata(ctx, folder, metadataCid);

    for (const child of metadata.children) {
        if (child.type === "file") {
            const name = decryptName(child.nameEncrypted, child.nameIv, folder.key);
            lines.push(`${indent}  - file: ${name} (size: ${child.size} bytes, cid: ${child.cid})`);
            continue;
        }

        const name = decryptName(child.nameEncrypted, child.nameIv, folder.key);
        const folderKey = eciesDecryptBytes(ctx.privateKey, hexToBytes(child.folderKeyEncrypted));
        const ipnsKeyName = bytesToUtf8(eciesDecryptBytes(ctx.privateKey, hexToBytes(child.ipnsKeyNameEncrypted)));

        const childFolder: FolderState = {
            name,
            key: folderKey,
            ipnsName: child.ipnsName,
            ipnsKeyName,
            metadata: {
                children: [],
                metadata: {
                    created: child.created,
                    modified: child.modified,
                },
            },
        };

        const childLines = await buildFolderTree(ctx, childFolder, depth + 1, maxDepth);
        lines.push(...childLines);
    }

    return lines;
};

const logFolderTree = async (
    ctx: HarnessContext,
    root: FolderState,
    label: string
): Promise<void> => {
    console.log(`\n--- File tree (${label}) ---`);
    const lines = await buildFolderTree(ctx, root);
    console.log(lines.join("\n"));
};

const downloadAndVerifyFile = async (
    ctx: HarnessContext,
    folder: FolderState,
    expectedName: string,
    expectedContent: Uint8Array,
    expectedMetadataCid?: string
): Promise<void> => {
    const metadataCid = expectedMetadataCid ?? (await resolveIpnsToCid(ctx, folder.ipnsName, { nocache: true }));
    if (expectedMetadataCid) {
        const resolvedCid = await resolveIpnsToCid(ctx, folder.ipnsName, { nocache: true });
        if (resolvedCid !== expectedMetadataCid) {
            throw new Error(
                `IPNS resolved to ${resolvedCid} but expected ${expectedMetadataCid} for ${folder.name}`
            );
        }
    }
    const data = await collectChunks(ctx.ipfs.cat(metadataCid));
    const parsed = JSON.parse(bytesToUtf8(data));
    const metadata = decryptMetadata(parsed, folder.key);
    const entry = findFileEntry(metadata, expectedName, folder.key);
    const fileKey = eciesDecryptBytes(ctx.privateKey, hexToBytes(entry.fileKeyEncrypted));
    const encryptedFile = await collectChunks(ctx.ipfs.cat(entry.cid));
    const plaintext = aesGcmDecrypt(encryptedFile, fileKey, hexToBytes(entry.fileIv));

    if (bytesToHex(plaintext) !== bytesToHex(expectedContent)) {
        throw new Error(`File content mismatch for ${expectedName}`);
    }
};

const ensureStateDir = async (dirPath: string): Promise<void> => {
    if (!existsSync(dirPath)) {
        await mkdir(dirPath, { recursive: true });
    }
};

const writeState = async (ctx: HarnessContext, root: FolderState): Promise<void> => {
    await ensureStateDir(ctx.stateDir);
    const state = {
        rootIpnsName: root.ipnsName,
        rootIpnsKeyName: root.ipnsKeyName,
        rootFolderKey: bytesToHex(root.key),
        updatedAt: new Date().toISOString(),
    };
    await writeFile(path.join(ctx.stateDir, "state.json"), JSON.stringify(state, null, 2));
};

const main = async (): Promise<void> => {
    const privateKeyHex = process.env.ECDSA_PRIVATE_KEY;
    if (!privateKeyHex) {
        throw new Error("ECDSA_PRIVATE_KEY is required");
    }

    const ipfsApiUrl = process.env.IPFS_API_URL ?? "http://127.0.0.1:5001";
    const stateDir = process.env.POC_STATE_DIR ?? path.join(process.cwd(), "state");
    const pollIntervalMs = Number(process.env.IPNS_POLL_INTERVAL_MS ?? "1500");
    const pollTimeoutMs = Number(process.env.IPNS_POLL_TIMEOUT_MS ?? "120000");
    const stressChildrenCount = Number(process.env.STRESS_CHILDREN_COUNT ?? "0");
    const stressChildType = (process.env.STRESS_CHILD_TYPE ?? "file") as "file" | "folder";

    const pinataEnabled = (process.env.PINATA_ENABLED ?? "false").toLowerCase() === "true";
    const pinataApiKey = process.env.PINATA_API_KEY;
    const pinataApiSecret = process.env.PINATA_API_SECRET;

    const privateKey = hexToBytes(privateKeyHex);
    const publicKey = getPublicKey(privateKey, false);

    const ctx: HarnessContext = {
        ipfs: create({ url: ipfsApiUrl }),
        privateKey,
        publicKey,
        stateDir,
        pinnedCids: new Set<string>(),
        ipnsKeyNames: new Set<string>(),
        pinata:
            pinataEnabled && pinataApiKey && pinataApiSecret
                ? { apiKey: pinataApiKey, apiSecret: pinataApiSecret }
                : undefined,
        pollIntervalMs,
        pollTimeoutMs,
        stressChildrenCount,
        stressChildType,
    };

    logStep("Initialize root folder");
    const rootFolder = await generateFolder(ctx, "root");
    await writeState(ctx, rootFolder);
    const rootPublish = await publishFolderMetadata(ctx, rootFolder);
    console.log(`Root published CID: ${rootPublish.cid} (IPNS delay ${rootPublish.delayMs}ms)`);

    logStep("Create subfolders");
    const docsFolder = await generateFolder(ctx, "Docs");
    const archiveFolder = await generateFolder(ctx, "Archive");

    await publishFolderMetadata(ctx, docsFolder);
    await publishFolderMetadata(ctx, archiveFolder);

    await addSubfolder(ctx, rootFolder, docsFolder);
    await addSubfolder(ctx, rootFolder, archiveFolder);
    const rootAfterFolders = await publishFolderMetadata(ctx, rootFolder);
    console.log(`Root updated CID: ${rootAfterFolders.cid} (IPNS delay ${rootAfterFolders.delayMs}ms)`);
    await logFolderTree(ctx, rootFolder, "after folder creation");

    if (ctx.stressChildrenCount > 0) {
        logStep(`Stress test: ${ctx.stressChildrenCount} ${ctx.stressChildType} children in Docs`);
        await addSyntheticChildren(ctx, docsFolder);
        const docsAfterStress = await publishFolderMetadata(ctx, docsFolder);
        console.log(
            `Docs stress CID: ${docsAfterStress.cid} (IPNS delay ${docsAfterStress.delayMs}ms)`
        );
    }

    logStep("Upload and verify file in Docs");
    const fileName = "hello.txt";
    const fileContent = utf8ToBytes("Hello, CipherBox PoC!");
    const fileKey = randomBytes(32);
    const { ciphertext: encryptedFile, iv: fileIv } = aesGcmEncrypt(fileContent, fileKey);

    const fileEntry = addFileToFolder(ctx, docsFolder, fileName, encryptedFile, fileKey, fileIv);
    const { cid: fileCid } = await ctx.ipfs.add(encryptedFile, { pin: false });
    fileEntry.cid = fileCid.toString();
    await pinCid(ctx, fileEntry.cid);
    docsFolder.metadata.children.push(fileEntry);
    docsFolder.metadata.metadata.modified = Date.now();

    const docsAfterUpload = await publishFolderMetadata(ctx, docsFolder);
    console.log(`Docs updated CID: ${docsAfterUpload.cid} (IPNS delay ${docsAfterUpload.delayMs}ms)`);
    await downloadAndVerifyFile(ctx, docsFolder, fileName, fileContent, docsAfterUpload.cid);
    console.log("File verified after upload");
    await logFolderTree(ctx, rootFolder, "after upload");

    logStep("Modify file content");
    const updatedContent = utf8ToBytes("Hello, CipherBox PoC! (updated)");
    const newFileKey = randomBytes(32);
    const { ciphertext: updatedEncrypted, iv: updatedIv } = aesGcmEncrypt(updatedContent, newFileKey);
    const { cid: updatedCid } = await ctx.ipfs.add(updatedEncrypted, { pin: false });
    const updatedCidStr = updatedCid.toString();
    await pinCid(ctx, updatedCidStr);

    const docMetadata = await fetchFolderMetadata(ctx, docsFolder, docsFolder.latestMetadataCid);
    const entryToUpdate = findFileEntry(docMetadata, fileName, docsFolder.key);
    const oldCid = entryToUpdate.cid;
    entryToUpdate.cid = updatedCidStr;
    entryToUpdate.fileKeyEncrypted = bytesToHex(eciesEncryptBytes(ctx.publicKey, newFileKey));
    entryToUpdate.fileIv = bytesToHex(updatedIv);
    entryToUpdate.size = updatedEncrypted.length;
    entryToUpdate.modified = Date.now();
    docMetadata.metadata.modified = Date.now();
    docsFolder.metadata = docMetadata;

    const docsAfterUpdate = await publishFolderMetadata(ctx, docsFolder);
    await unpinCid(ctx, oldCid);
    await downloadAndVerifyFile(ctx, docsFolder, fileName, updatedContent, docsAfterUpdate.cid);
    console.log("File verified after update");
    await logFolderTree(ctx, rootFolder, "after update");

    logStep("Rename file");
    const renameMetadata = await fetchFolderMetadata(ctx, docsFolder, docsFolder.latestMetadataCid);
    const renameEntry = findFileEntry(renameMetadata, fileName, docsFolder.key);
    const renamedFile = "hello-renamed.txt";
    const renamed = encryptName(renamedFile, docsFolder.key);
    renameEntry.nameEncrypted = renamed.nameEncrypted;
    renameEntry.nameIv = renamed.nameIv;
    renameEntry.modified = Date.now();
    renameMetadata.metadata.modified = Date.now();
    docsFolder.metadata = renameMetadata;
    const docsAfterRename = await publishFolderMetadata(ctx, docsFolder);
    await downloadAndVerifyFile(ctx, docsFolder, renamedFile, updatedContent, docsAfterRename.cid);
    console.log("File verified after rename");
    await logFolderTree(ctx, rootFolder, "after rename");

    logStep("Move file to Archive");
    const docsMetaForMove = await fetchFolderMetadata(ctx, docsFolder, docsFolder.latestMetadataCid);
    const fileToMove = removeFileEntry(docsMetaForMove, renamedFile, docsFolder.key);
    const archiveMeta = await fetchFolderMetadata(ctx, archiveFolder, archiveFolder.latestMetadataCid);

    const archiveName = encryptName(renamedFile, archiveFolder.key);
    const movedEntry: FileEntry = {
        ...fileToMove,
        nameEncrypted: archiveName.nameEncrypted,
        nameIv: archiveName.nameIv,
        modified: Date.now(),
    };
    archiveMeta.children.push(movedEntry);
    archiveMeta.metadata.modified = Date.now();
    docsMetaForMove.metadata.modified = Date.now();
    docsFolder.metadata = docsMetaForMove;
    archiveFolder.metadata = archiveMeta;

    const archiveAfterMove = await publishFolderMetadata(ctx, archiveFolder);
    await publishFolderMetadata(ctx, docsFolder);
    await downloadAndVerifyFile(ctx, archiveFolder, renamedFile, updatedContent, archiveAfterMove.cid);
    console.log("File verified after move");
    await logFolderTree(ctx, rootFolder, "after move");

    logStep("Delete file from Archive");
    const archiveMetaForDelete = await fetchFolderMetadata(ctx, archiveFolder, archiveFolder.latestMetadataCid);
    const deletedEntry = removeFileEntry(archiveMetaForDelete, renamedFile, archiveFolder.key);
    archiveMetaForDelete.metadata.modified = Date.now();
    archiveFolder.metadata = archiveMetaForDelete;
    await publishFolderMetadata(ctx, archiveFolder);
    await unpinCid(ctx, deletedEntry.cid);
    console.log("File deleted and unpinned");
    await logFolderTree(ctx, rootFolder, "after delete");

    logStep("Teardown (unpin all created CIDs, remove IPNS keys)");
    for (const cid of ctx.pinnedCids) {
        await unpinCid(ctx, cid);
    }
    for (const keyName of ctx.ipnsKeyNames) {
        try {
            await ctx.ipfs.key.rm(keyName);
        } catch (error) {
            console.warn(`Key rm skipped for ${keyName}: ${(error as Error).message}`);
        }
    }

    console.log("PoC harness completed successfully.");
};

main().catch((error) => {
    console.error("PoC harness failed:", error);
    process.exit(1);
});
