import type { Manifest, AssetDecl } from "../model/manifest.js";
import type { Policy } from "../model/policy.js";
export declare class ConfigError extends Error {
    constructor(file: string, msg: string);
}
export interface Loaded<T> {
    readonly value: T;
    readonly path: string;
    readonly sha256: string;
}
export declare function validateManifest(json: unknown, file?: string): Manifest;
export declare function validatePolicy(json: unknown, file?: string): Policy;
export declare function loadManifest(path: string): Loaded<Manifest>;
export declare function loadPolicy(path: string): Loaded<Policy>;
export declare function assetById(m: Manifest, id: string): AssetDecl | undefined;
