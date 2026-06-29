// stdio MCP transport uses stdout for JSON-RPC — ALL human-readable diagnostics
// must go to stderr.
const PREFIX = "[wx-mp-mcp]";

export const log = (...a: unknown[]): void => console.error(PREFIX, ...a);

/** Defensive: redact anything resembling an API key (this server never holds one). */
export function redact(s: string): string {
  return s.replace(/sk-[A-Za-z0-9_\-]{12,}/g, "sk-***REDACTED***");
}
