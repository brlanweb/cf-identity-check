import { Hono } from "hono";
import { splitHeaders } from "../shared/redact.ts";
import { gather, type LookupEnv } from "./lookup.ts";

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

function asnNumber(value: unknown): string | null {
  if (typeof value === "number" && Number.isFinite(value)) return String(Math.trunc(value));
  if (typeof value === "string" && /^\d+$/.test(value.trim())) return value.trim();
  return null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

const app = new Hono<{ Bindings: LookupEnv }>();

app.get("/api/edge", async (c) => {
  const request = c.req.raw;
  const cf = pickCf((request as Request & { cf?: CfRecord }).cf ?? {});
  const { headers, omittedHeaders } = splitHeaders(request.headers);
  const connectingIp = request.headers.get("CF-Connecting-IP");
  const edgeCountry = text(cf.country) ?? request.headers.get("CF-IPCountry");
  const gathered = await gather({
    ip: connectingIp,
    cfAsn: asnNumber(cf.asn),
    cfOrg: text(cf.asOrganization),
    country: edgeCountry,
    region: text(cf.region),
    city: text(cf.city),
    latitude: cf.latitude,
    longitude: cf.longitude,
    timezone: text(cf.timezone),
    env: c.env ?? {},
  });
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
    history: gathered.history,
    intel: gathered.intel,
    network: gathered.network,
    collectedAt: new Date().toISOString(),
    privacy:
      "Cookie、Authorization 和 Cloudflare Access JWT 不会返回。Worker 不记录访问，也不写 KV、D1 或 Cookie。公网出口 IP 会查询 RDAP、RIPEstat、PeeringDB、ip-api.com、ipapi.co、ipwho.is、ipapi.is、ipinfo.io、Bilibili、proxycheck.io、Tor 出口列表和 StopForumSpam。这些公开结果会在边缘短时缓存。可选的 CF_RADAR_TOKEN、IPINFO_TOKEN、IPAPI_IS_KEY、PROXYCHECK_KEY、IP2LOCATION_KEY 只留在 Worker 环境里。",
  });
});

app.notFound((c) => c.json({ error: "not found" }, 404));

export default app;
