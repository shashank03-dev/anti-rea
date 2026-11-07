/** Injectable clock so reports and exception-expiry checks are reproducible in tests and CI. */
let fixed: Date | null = null;

export function setClock(d: Date | null): void {
  fixed = d;
}

export function now(): Date {
  return fixed ? new Date(fixed.getTime()) : new Date();
}

export function nowIso(): string {
  return now().toISOString();
}
