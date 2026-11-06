/** Headers whose values must never be returned to the page. */
export const SENSITIVE_HEADERS = [
  "cookie",
  "authorization",
  "proxy-authorization",
  "set-cookie",
  "cf-access-jwt-assertion",
] as const;

const SENSITIVE = new Set<string>(SENSITIVE_HEADERS);

export function splitHeaders(entries: Iterable<[string, string]>): {
  headers: Record<string, string>;
  omittedHeaders: string[];
} {
  const headers: Record<string, string> = {};
  const omittedHeaders: string[] = [];
  for (const [key, value] of entries) {
    const name = key.toLowerCase();
    if (SENSITIVE.has(name)) {
      if (!omittedHeaders.includes(name)) omittedHeaders.push(name);
      continue;
    }
    headers[name] = value;
  }
  return { headers, omittedHeaders };
}

export function headerValue(headers: Record<string, string>, name: string): string | null {
  const want = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === want) return value;
  }
  return null;
}

export function unquote(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}
