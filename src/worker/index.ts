import { Hono } from "hono";
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

const app = new Hono();

app.get("/api/edge", (c) => {
  const request = c.req.raw;
  const cf = pickCf((request as Request & { cf?: CfRecord }).cf ?? {});
  const { headers, omittedHeaders } = splitHeaders(request.headers);
  c.header("Cache-Control", "no-store");
  c.header(
    "Accept-CH",
    "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-WoW64",
  );
  c.header("X-Content-Type-Options", "nosniff");
  return c.json({
    connectingIp: request.headers.get("CF-Connecting-IP"),
    ray: request.headers.get("CF-Ray"),
    ipCountry: request.headers.get("CF-IPCountry"),
    cf,
    headers,
    omittedHeaders,
    collectedAt: new Date().toISOString(),
    privacy: "Cookie、Authorization 和 Cloudflare Access JWT 不会返回。这个 Worker 不保存请求。",
  });
});

app.notFound((c) => c.json({ error: "not found" }, 404));

export default app;
