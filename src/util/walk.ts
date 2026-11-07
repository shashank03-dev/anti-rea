import { readdirSync, lstatSync } from "node:fs";
import { join, relative, sep } from "node:path";

export interface WalkEntry {
  readonly abs: string;
  readonly rel: string; // posix, relative to root
  readonly isSymlink: boolean;
  /** Set when the entry (file or directory) could not be read; it must become a coverage gap. */
  readonly error?: string;
}

/** Recursively list regular files; symlinks are recorded, not followed; read errors are recorded, not thrown. */
export function walkFiles(root: string): WalkEntry[] {
  const out: WalkEntry[] = [];
  const stack = [root];
  const rel = (abs: string) => relative(root, abs).split(sep).join("/");
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let names: string[];
    try {
      names = readdirSync(dir).sort();
    } catch (e) {
      out.push({ abs: dir, rel: rel(dir) || ".", isSymlink: false, error: `unreadable directory (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})` });
      continue;
    }
    for (const name of names) {
      const abs = join(dir, name);
      let st;
      try {
        st = lstatSync(abs);
      } catch (e) {
        out.push({ abs, rel: rel(abs), isSymlink: false, error: `cannot stat (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})` });
        continue;
      }
      if (st.isSymbolicLink()) out.push({ abs, rel: rel(abs), isSymlink: true });
      else if (st.isDirectory()) stack.push(abs);
      else if (st.isFile()) out.push({ abs, rel: rel(abs), isSymlink: false });
    }
  }
  return out.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
}
