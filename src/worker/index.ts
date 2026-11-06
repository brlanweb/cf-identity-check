import { Hono } from "hono";
import { isReputationLookupIp, parseStopForumSpam, type AbuseRecord } from "../shared/history.ts";
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
  const history = await lookupAbuse(connectingIp);
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
    collectedAt: new Date().toISOString(),
    privacy: "Cookie、Authorization 和 Cloudflare Access JWT 不会返回。Worker 不保存请求。公网出口 IP 会向 StopForumSpam 查询一次。",
  });
});

app.notFound((c) => c.json({ error: "not found" }, 404));

export default app;
