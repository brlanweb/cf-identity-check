import { canonicalIp, classifyAddress } from "../shared/ip.ts";
import type { EchoHit } from "../shared/model.ts";
import { parseIpinfo, parseIpip, unavailablePlace, type GeoPlace } from "../shared/sources.ts";

const ENDPOINTS: { name: string; family: "v4" | "v6"; url: string }[] = [
  { name: "ipify", family: "v4", url: "https://api.ipify.org?format=json" },
  { name: "ident.me", family: "v4", url: "https://v4.ident.me/json" },
  { name: "ipify", family: "v6", url: "https://api6.ipify.org?format=json" },
  { name: "ident.me", family: "v6", url: "https://v6.ident.me/json" },
];

export async function detectBrowser(): Promise<{ echoes: EchoHit[]; ipinfo: GeoPlace; ipip: GeoPlace }> {
  const [echoes, ipinfo, ipip] = await Promise.all([Promise.all(ENDPOINTS.map((item) => echo(item))), directIpinfo(), directIpip()]);
  return { echoes, ipinfo, ipip };
}

async function echo(item: { name: string; family: "v4" | "v6"; url: string }): Promise<EchoHit> {
  try {
    const response = await fetch(item.url, { cache: "no-store", signal: AbortSignal.timeout(2500) });
    if (!response.ok) return { name: item.name, family: item.family, ip: null, canonical: null, error: `HTTP ${response.status}` };
    const raw = readIp((await response.text()).trim());
    const canonical = accept(raw, item.family);
    if (!canonical) return { name: item.name, family: item.family, ip: null, canonical: null, error: raw ? "返回的不是该协议的公网地址" : "没有解析出 IP" };
    return { name: item.name, family: item.family, ip: raw, canonical, error: null };
  } catch (error) {
    const timed = error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError");
    return { name: item.name, family: item.family, ip: null, canonical: null, error: timed ? "超时" : "没有连上" };
  }
}

async function directIpinfo(): Promise<GeoPlace> {
  try {
    const response = await fetch("https://ipinfo.io/json", { cache: "no-store", signal: AbortSignal.timeout(2500) });
    if (!response.ok) return unavailablePlace("ipinfo-direct", `ipinfo.io 返回 HTTP ${response.status}`);
    return parseIpinfo(await response.json(), "ipinfo-direct") ?? unavailablePlace("ipinfo-direct", "ipinfo.io 没有返回地理位置。");
  } catch {
    return unavailablePlace("ipinfo-direct", "浏览器没有连上 ipinfo.io。");
  }
}

async function directIpip(): Promise<GeoPlace> {
  try {
    const response = await fetch("https://myip.ipip.net/json", { cache: "no-store", signal: AbortSignal.timeout(2500) });
    if (!response.ok) return unavailablePlace("ipip", `myip.ipip.net 返回 HTTP ${response.status}`);
    return parseIpip(await response.json()) ?? unavailablePlace("ipip", "myip.ipip.net 没有返回位置。");
  } catch {
    return unavailablePlace("ipip", "浏览器没有连上 myip.ipip.net。");
  }
}

function readIp(text: string): string | null {
  if (!text) return null;
  try {
    const json = JSON.parse(text) as { ip?: unknown };
    if (typeof json.ip === "string" && json.ip.trim()) return json.ip.trim();
  } catch {
    /* plain text echo */
  }
  const line = text.split(/\s+/)[0] ?? "";
  return line || null;
}

function accept(raw: string | null, family: "v4" | "v6"): string | null {
  const canonical = canonicalIp(raw);
  if (!canonical) return null;
  const is6 = canonical.includes(":");
  if (family === "v4" && is6) return null;
  if (family === "v6" && !is6) return null;
  if (classifyAddress(canonical) !== "public") return null;
  return canonical;
}
