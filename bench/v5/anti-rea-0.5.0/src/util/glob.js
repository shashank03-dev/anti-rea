/**
 * Minimal, dependency-free glob matcher for posix relative paths.
 * Supports: `**` (any number of path segments), `*` (any chars within a segment),
 * `?` (one char within a segment), and `{a,b}` alternation.
 */
export function globToRegExp(glob) {
    let re = "^";
    let i = 0;
    while (i < glob.length) {
        const c = glob[i];
        if (c === "*") {
            if (glob[i + 1] === "*") {
                // `**/` matches zero or more segments; trailing `**` matches anything.
                if (glob[i + 2] === "/") {
                    re += "(?:.*/)?";
                    i += 3;
                }
                else {
                    re += ".*";
                    i += 2;
                }
            }
            else {
                re += "[^/]*";
                i += 1;
            }
        }
        else if (c === "?") {
            re += "[^/]";
            i += 1;
        }
        else if (c === "{") {
            const end = glob.indexOf("}", i);
            if (end === -1) {
                re += "\\{";
                i += 1;
            }
            else {
                const alts = glob.slice(i + 1, end).split(",").map(escapeRe);
                re += `(?:${alts.join("|")})`;
                i = end + 1;
            }
        }
        else {
            re += escapeRe(c);
            i += 1;
        }
    }
    return new RegExp(re + "$");
}
function escapeRe(s) {
    return s.replace(/[.+^${}()|[\]\\]/g, "\\$&");
}
export function matchesAny(path, globs) {
    return globs.some((g) => globToRegExp(g).test(path));
}
