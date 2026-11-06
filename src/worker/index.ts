import { Hono } from "hono";
import { isReputationLookupIp, parseStopForumSpam, type AbuseRecord } from "../shared/history.ts";
import { assembleIntel, reverseV4, type IpIntel } from "../shared/intel.ts";
import { splitHeaders } from "../shared/redact.ts";

const CF_KEYS = [
  "asn",
  "asOrganization",
  "colo",
  "country",
  "city",
  "continent",
  "region",
  "regionCode",
  "timezone",
  "postalCode",
  "metroCode",
  "latitude",
  "longitude",
  "isEUCountry",
  "httpProtocol",
  "tlsVersion",
  "tlsCipher",
  "clientTcpRtt",
  "clientQuicRtt",
  "clientAcceptEncoding",
  "requestPriority",
] as const;

type CfRecord = Record<string, unknown>;

function pickCf(cf: CfRecord): CfRecord {
  const picked: CfRecord = {};
  for (const key of CF_KEYS) {
    const value = cf[key];
    if (value !== undefined && value !== null) picked[key] = value;
  }
  const edgeL4 = cf.edgeL4;
  if (edgeL4 && typeof edgeL4 === "object") {
    const deliveryRate = (edgeL4 as CfRecord).deliveryRate;
    if (typeof deliveryRate === "number") picked.edgeL4 = { deliveryRate };
  }
  const bot = cf.botManagement;
  if (bot && typeof bot === "object") {
    const source = bot as CfRecord;
    picked.botManagement = {
      score: source.score ?? null,
      verifiedBot: source.verifiedBot ?? null,
      staticResource: source.staticResource ?? null,
      ja3Hash: source.ja3Hash ?? null,
      ja4: source.ja4 ?? null,
    };
  }
  return picked;
}

function historyRecord(attempted: boolean): AbuseRecord {
  return { source: "none", appears: null, frequency: null, lastSeen: null, attempted };
}

function asnNumber(value: unknown): string | null {
  if (typeof value === "number" && Number.isFinite(value)) return String(Math.trunc(value));
  if (typeof value === "string" && /^\d+$/.test(value.trim())) return value.trim();
  return null;
}

async function fetchJson(url: string, headers?: HeadersInit): Promise<unknown | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2200);
  try {
    const response = await fetch(url, {
      cache: "no-store",
      signal: controller.signal,
      redirect: "follow",
      headers: { Accept: "application/json", "User-Agent": "cf-identity-check/1.0", ...headers },
    });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function lookupIntel(ip: string | null, asn: string | null, edgeCountry: string | null): Promise<IpIntel> {
  const publicIp = ip && isReputationLookupIp(ip) ? ip : null;
  const ptrName = reverseV4(publicIp);
  const [rdapIp, ptrBody, prefixBody] = await Promise.all([
    publicIp ? fetchJson(`https://rdap.org/ip/${publicIp}`, { Accept: "application/rdap+json" }) : null,
    ptrName ? fetchJson(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(ptrName)}&type=PTR`, { Accept: "application/dns-json" }) : null,
    publicIp ? fetchJson(`https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(publicIp)}`) : null,
  ]);
  const prefix =
    prefixBody && typeof prefixBody === "object"
      ? (prefixBody as { data?: { resource?: unknown } }).data?.resource
      : null;
  const prefixText = typeof prefix === "string" ? prefix : null;
  const [rdapAsn, routingBody, rpkiBody] = await Promise.all([
    asn ? fetchJson(`https://rdap.org/autnum/${asn}`, { Accept: "application/rdap+json" }) : null,
    asn ? fetchJson(`https://stat.ripe.net/data/routing-status/data.json?resource=AS${asn}`) : null,
    asn && prefixText
      ? fetchJson(`https://stat.ripe.net/data/rpki-validation/data.json?resource=${asn}&prefix=${encodeURIComponent(prefixText)}`)
      : null,
  ]);
  return assembleIntel({
    ip,
    edgeCountry,
    ptrBody,
    rdapIp,
    rdapAsn,
    prefixBody,
    routingBody,
    rpkiBody,
  });
}

async function lookupAbuse(ip: string | null): Promise<AbuseRecord> {
  if (!ip || !isReputationLookupIp(ip)) return historyRecord(false);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1800);
  try {
    const response = await fetch(`https://api.stopforumspam.org/api?ip=${ip}&json`, {
      cache: "no-store",
      signal: controller.signal,
    });
    if (!response.ok) return historyRecord(true);
    return parseStopForumSpam(await response.json()) ?? historyRecord(true);
  } catch {
    return historyRecord(true);
  } finally {
    clearTimeout(timer);
  }
}

const app = new Hono();

app.get("/api/edge", async (c) => {
  const request = c.req.raw;
  const cf = pickCf((request as Request & { cf?: CfRecord }).cf ?? {});
  const { headers, omittedHeaders } = splitHeaders(request.headers);
  const connectingIp = request.headers.get("CF-Connecting-IP");
  const asn = asnNumber(cf.asn);
  const edgeCountry = typeof cf.country === "string" ? cf.country : request.headers.get("CF-IPCountry");
  const [history, intel] = await Promise.all([
    lookupAbuse(connectingIp),
    lookupIntel(connectingIp, asn, edgeCountry),
  ]);
  c.header("Cache-Control", "no-store");
  c.header(
    "Accept-CH",
    "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-WoW64",
  );
  c.header("X-Content-Type-Options", "nosniff");
  return c.json({
    connectingIp,
    ray: request.headers.get("CF-Ray"),
    ipCountry: request.headers.get("CF-IPCountry"),
    cf,
    headers,
    omittedHeaders,
    history,
    intel,
    collectedAt: new Date().toISOString(),
    privacy: "Cookie、Authorization 和 Cloudflare Access JWT 不会返回。Worker 不保存请求。公网出口 IP 会查询 StopForumSpam、RDAP、RIPEstat 和反向 DNS。",
  });
});

app.notFound((c) => c.json({ error: "not found" }, 404));

export default app;
