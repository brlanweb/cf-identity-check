/** IP text, family, and ICE candidate classification. Comparison uses a canonical form. */

export type AddressKind = "public" | "private" | "cgnat" | "unknown";

export type IceKind = AddressKind | "mdns" | "relay";

export type IceCandidate = {
  ip: string | null;
  kind: IceKind;
  typ: string | null;
};

export function canonicalIp(input: string | null | undefined): string | null {
  if (!input) return null;
  const raw = input.trim().toLowerCase().split("%")[0] ?? "";
  if (!raw) return null;
  if (raw.startsWith("::ffff:")) {
    const mapped = canonicalV4(raw.slice("::ffff:".length));
    if (mapped) return mapped;
  }
  if (raw.includes(".")) return canonicalV4(raw);
  if (raw.includes(":")) return canonicalV6(raw);
  return null;
}

export function sameIp(left: string | null | undefined, right: string | null | undefined): boolean {
  const a = canonicalIp(left);
  const b = canonicalIp(right);
  return Boolean(a && b && a === b);
}

export function ipFamily(ip: string | null | undefined): "v4" | "v6" | null {
  const canonical = canonicalIp(ip);
  if (!canonical) return null;
  return canonical.includes(":") ? "v6" : "v4";
}

export function classifyAddress(ip: string | null | undefined): AddressKind {
  const canonical = canonicalIp(ip);
  if (!canonical) return "unknown";
  if (!canonical.includes(":")) return classifyV4(canonical);
  return isV6NonPublic(canonical) ? "private" : "public";
}

export function parseIceCandidate(candidate: string): IceCandidate {
  const text = candidate.trim().replace(/^a=/, "");
  const parts = text.split(/\s+/);
  const typIndex = parts.indexOf("typ");
  const typ = typIndex >= 0 ? parts[typIndex + 1] ?? null : null;
  const raw = parts[4] ?? "";
  if (!raw || raw.endsWith(".local")) return { ip: raw || null, kind: "mdns", typ };
  if (typ === "relay") return { ip: raw, kind: "relay", typ };
  const kind = classifyAddress(raw);
  return { ip: canonicalIp(raw) ?? raw, kind, typ };
}

function canonicalV4(ip: string): string | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (!Number.isInteger(value) || value < 0 || value > 255) return null;
    nums.push(value);
  }
  return nums.join(".");
}

function canonicalV6(ip: string): string | null {
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const expand = (part: string): string[] => (part ? part.split(":") : []);
  const left = expand(halves[0] ?? "");
  const right = halves.length === 2 ? expand(halves[1] ?? "") : [];
  if (halves.length === 1 && left.length !== 8) return null;
  if (left.length + right.length > 8) return null;
  const groups = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right] : left;
  if (groups.length !== 8) return null;
  const nums: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    nums.push(parseInt(group, 16));
  }
  return nums.map((value) => value.toString(16)).join(":");
}

function classifyV4(ip: string): AddressKind {
  const [a, b] = ip.split(".").map((part) => Number(part));
  if (a === undefined || b === undefined) return "unknown";
  if (a === 100 && b >= 64 && b <= 127) return "cgnat";
  if (a === 0 || a === 10 || a === 127) return "private";
  if (a === 169 && b === 254) return "private";
  if (a === 172 && b >= 16 && b <= 31) return "private";
  if (a === 192 && (b === 168 || b === 0)) return "private";
  if (a === 192 && b === 0 && ip.startsWith("192.0.2.")) return "private";
  if (a === 198 && (b === 18 || b === 19)) return "private";
  if (a === 198 && b === 51 && ip.startsWith("198.51.100.")) return "private";
  if (a === 203 && b === 0 && ip.startsWith("203.0.113.")) return "private";
  if (a >= 224) return "private";
  return "public";
}

function isV6NonPublic(full: string): boolean {
  if (full === "0:0:0:0:0:0:0:0" || full === "0:0:0:0:0:0:0:1") return true;
  if (full.startsWith("2001:db8:")) return true;
  const head = parseInt(full.split(":")[0] ?? "0", 16);
  if (head >= 0xfe80 && head <= 0xfebf) return true;
  if (head >= 0xfc00 && head <= 0xfdff) return true;
  if (head >= 0xff00) return true;
  return false;
}
