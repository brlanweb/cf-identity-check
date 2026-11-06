/** Public spam-database hit for this exit IP. Never a fabricated abuse score. */
export type AbuseRecord = {
  source: "stopforumspam" | "none";
  appears: boolean | null;
  frequency: number | null;
  lastSeen: string | null;
  /** True when a lookup was attempted. False when there was no IP to query. */
  attempted: boolean;
};

/** Only public addresses are sent to the reputation lookup. Loopback and private ranges are not. */
export function isReputationLookupIp(ip: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(ip)) return false;
  if (ip.includes(":")) {
    const text = ip.toLowerCase();
    if (text === "::1" || text.startsWith("fe80:") || text.startsWith("fc") || text.startsWith("fd")) return false;
    return true;
  }
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const a = parts[0] ?? -1;
  const b = parts[1] ?? -1;
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 192 && b === 168) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

export function parseStopForumSpam(body: unknown): AbuseRecord | null {
  if (!body || typeof body !== "object") return null;
  const root = body as { success?: unknown; ip?: unknown };
  if (root.success !== 1 || !root.ip || typeof root.ip !== "object") return null;
  const ip = root.ip as { appears?: unknown; frequency?: unknown; lastseen?: unknown };
  if (ip.appears === undefined || ip.appears === null) return null;
  const appears = ip.appears === 1 || ip.appears === true;
  const frequency = typeof ip.frequency === "number" && Number.isFinite(ip.frequency) ? ip.frequency : 0;
  const lastSeen = typeof ip.lastseen === "string" && ip.lastseen.trim() ? ip.lastseen.trim() : null;
  return { source: "stopforumspam", appears, frequency, lastSeen, attempted: true };
}

export function historyCopy(record: AbuseRecord): { label: string; note: string } {
  if (record.source === "stopforumspam" && record.appears === true) {
    const times = record.frequency ?? 0;
    const seen = record.lastSeen ? `，最近 ${record.lastSeen}` : "";
    return {
      label: "有公开记录",
      note: `StopForumSpam 记录 ${times} 次${seen}。这不是 Claude 的滥用库。`,
    };
  }
  if (record.source === "stopforumspam" && record.appears === false) {
    return { label: "无公开记录", note: "StopForumSpam 未见此 IP。这不是完整历史。" };
  }
  if (record.attempted) {
    return { label: "无历史库", note: "公开库没有查到，不编造滥用记录。" };
  }
  return { label: "无历史库", note: "没有可用的历史库，不编造滥用记录。" };
}
