/**
 * Zero-dependency, read-only HFS+ (and HFSX) volume reader: the filesystem
 * inside a typical macOS .dmg.
 *
 * It walks the catalog B-tree, reads every file's data fork, including extents
 * stored in the extents-overflow B-tree, and resolves hard links to their
 * iNode files so each file is reported under its real path. Resource forks,
 * extended attributes and non-zero unallocated blocks are reported as their
 * own entries, so every shipped byte is either inspected or reported
 * unsupported. HFS+-compressed (decmpfs) files are reported unsupported,
 * never as empty.
 */
export interface HfsEntry {
    readonly name: string;
    readonly data: Buffer | null;
    readonly reason?: string;
}
export interface HfsLimits {
    readonly maxEntries: number;
    readonly maxEntryBytes: number;
}
export declare function looksLikeHfsPlus(part: Buffer): boolean;
export declare function readHfsPlus(part: Buffer, limits: HfsLimits): {
    volume: string;
    entries: HfsEntry[];
    notes: string[];
};
