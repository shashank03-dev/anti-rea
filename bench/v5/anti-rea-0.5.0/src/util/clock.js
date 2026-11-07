/** Injectable clock so reports and exception-expiry checks are reproducible in tests and CI. */
let fixed = null;
export function setClock(d) {
    fixed = d;
}
export function now() {
    return fixed ? new Date(fixed.getTime()) : new Date();
}
export function nowIso() {
    return now().toISOString();
}
