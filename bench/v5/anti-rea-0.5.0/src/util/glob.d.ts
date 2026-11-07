/**
 * Minimal, dependency-free glob matcher for posix relative paths.
 * Supports: `**` (any number of path segments), `*` (any chars within a segment),
 * `?` (one char within a segment), and `{a,b}` alternation.
 */
export declare function globToRegExp(glob: string): RegExp;
export declare function matchesAny(path: string, globs: readonly string[]): boolean;
