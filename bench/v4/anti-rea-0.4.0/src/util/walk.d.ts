export interface WalkEntry {
    readonly abs: string;
    readonly rel: string;
    readonly isSymlink: boolean;
    /** Set when the entry (file or directory) could not be read; it must become a coverage gap. */
    readonly error?: string;
}
/** Recursively list regular files; symlinks are recorded, not followed; read errors are recorded, not thrown. */
export declare function walkFiles(root: string): WalkEntry[];
