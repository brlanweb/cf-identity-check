import { isReputationLookupIp, parseStopForumSpam, type AbuseRecord } from "../shared/history.ts";
import { assembleIntel, parsePtr, parseRpki, reverseV4, type IpIntel } from "../shared/intel.ts";
import { baseNetwork, type NetworkReport } from "../shared/report.ts";
import {
  cleanAsn,
  cloudflarePlace,
  parseBilibili,
  parseIp2Location,
  parseIpApi,
  parseIpapiCo,
  parseIpapiIs,
  parseIpinfo,
  parseIpwho,
  parsePeeringDbWebsite,
  parseProxycheck,
  parseRadar,
  parseRdapCidr,
  parseRipeIdentity,
  parseTorList,
  rdapAsnName,
  rdapRange,
  registrationCountry,
  unavailablePlace,
  type GeoPlace,
} from "../shared/sources.ts";

export type LookupEnv = {
  CF_RADAR_TOKEN?: string;
  IPINFO_TOKEN?: string;
  IPAPI_IS_KEY?: string;
  PROXYCHECK_KEY?: string;
  IP2LOCATION_KEY?: string;
};

const UA = "cf-identity-check/1.0 (+https://check.aisa.fun)";

type Loaded = { json: unknown | null; status: number | null };

export async function gather(input: {
  ip: string | null;
  cfAsn: string | null;
  cfOrg: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  latitude: unknown;
  longitude: unknown;
  timezone: string | null;
  env: LookupEnv;
}): Promise<{ history: AbuseRecord; intel: IpIntel; network: NetworkReport }> {
  const radarToken = secret(input.env.CF_RADAR_TOKEN);
  const ip2Key = secret(input.env.IP2LOCATION_KEY);
  const publicIp = input.ip && isReputationLookupIp(input.ip) ? input.ip : null;
  const cfPlace = publicIp
    ? cloudflarePlace({ ...input, ip: publicIp })
    : unavailablePlace(
        "cloudflare",
        input.ip
          ? "边缘地址不是公网。本地开发时 request.cf 里的国家或城市不能当成这个地址的位置。"
          : "边缘没有 CF-Connecting-IP。",
      );
  if (!publicIp) {
    const note = input.ip ? "边缘地址不是公网，没有向外部数据源查询。" : "边缘没有 CF-Connecting-IP。";
    const network = baseNetwork(note);
    network.places = network.places.map((place) => {
      if (place.id === "cloudflare") return cfPlace;
      if (place.id === "ip2location" && !ip2Key) return unavailablePlace("ip2location", "未设置 IP2LOCATION_KEY。", "未配置");
      return place;
    });
    network.radar = unconfiguredRadar(radarToken, note);
    if (!ip2Key) network.risk.ip2location = { state: "未配置", isProxy: null, note: "未设置 IP2LOCATION_KEY。" };
    return {
      history: { source: "none", appears: null, frequency: null, lastSeen: null, attempted: false },
      intel: assembleIntel({
        ip: input.ip,
        edgeCountry: input.country,
        ptrBody: null,
        rdapIp: null,
        rdapAsn: null,
        prefixBody: null,
        routingBody: null,
        rpkiBody: null,
      }),
      network,
    };
  }

  const ip = publicIp;
  const encoded = encodeURIComponent(ip);
  const knownAsn = cleanAsn(input.cfAsn);
  const ptrName = reverseV4(ip);
  const ipinfoToken = secret(input.env.IPINFO_TOKEN);
  const ipapiKey = secret(input.env.IPAPI_IS_KEY);
  const proxyKey = secret(input.env.PROXYCHECK_KEY);
  const ipinfoParams = ipinfoToken ? `?token=${encodeURIComponent(ipinfoToken)}` : "";
  const ipapiParams = new URLSearchParams({ q: ip });
  if (ipapiKey) ipapiParams.set("key", ipapiKey);
  const proxyParams = new URLSearchParams({ vpn: "1", asn: "1" });
  if (proxyKey) proxyParams.set("key", proxyKey);

  const [rdapIp, prefix, ptr, ipApi, ipapiCo, ipwho, ipapiIs, ipinfo, bili, proxy, tor, history, ip2, rdapAsn, peering, routing, radar] = await Promise.all([
    loadJson(`https://rdap.org/ip/${encoded}`, `rdap-ip:${ip}`, 43_200, { Accept: "application/rdap+json" }, 2500),
    loadJson(`https://stat.ripe.net/data/prefix-overview/data.json?resource=${encoded}`, `ripe-prefix:${ip}`, 43_200, undefined, 2500),
    ptrName ? loadJson(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(ptrName)}&type=PTR`, `ptr:${ip}`, 21_600, { Accept: "application/dns-json" }, 2200) : Promise.resolve(emptyLoaded()),
    loadJson(`http://ip-api.com/json/${encoded}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query`, `ip-api:${ip}`, 21_600, undefined, 2200),
    loadJson(`https://ipapi.co/${encoded}/json/`, `ipapi-co:${ip}`, 21_600, undefined, 2200),
    loadJson(`https://ipwho.is/${encoded}`, `ipwho:${ip}`, 21_600, undefined, 2200),
    loadJson(`https://api.ipapi.is/?${ipapiParams.toString()}`, `ipapi-is:${ip}`, 21_600, undefined, 2200),
    loadJson(`https://ipinfo.io/${encoded}/json${ipinfoParams}`, `ipinfo:${ip}`, 21_600, undefined, 2200),
    loadJson(`https://api.live.bilibili.com/client/v1/Ip/getInfoNew?ip=${encoded}`, `bilibili:${ip}`, 21_600, undefined, 2200),
    loadJson(`https://proxycheck.io/v2/${encoded}?${proxyParams.toString()}`, `proxycheck:${ip}`, 21_600, undefined, 2200),
    loadText("https://check.torproject.org/torbulkexitlist", "tor-exit-list", 1800, undefined, 2500, torAccept),
    lookupAbuse(ip),
    ip2Key ? loadJson(`https://api.ip2location.io/?key=${encodeURIComponent(ip2Key)}&ip=${encoded}&format=json`, `ip2location:${ip}`, 21_600, undefined, 2200) : Promise.resolve(emptyLoaded()),
    knownAsn ? loadJson(`https://rdap.org/autnum/${knownAsn}`, `rdap-asn:${knownAsn}`, 43_200, { Accept: "application/rdap+json" }, 2500) : Promise.resolve(emptyLoaded()),
    knownAsn ? loadJson(`https://www.peeringdb.com/api/net?asn=${knownAsn}`, `peeringdb:${knownAsn}`, 43_200, undefined, 2500) : Promise.resolve(emptyLoaded()),
    knownAsn ? loadJson(`https://stat.ripe.net/data/routing-status/data.json?resource=AS${knownAsn}`, `ripe-routing:${knownAsn}`, 43_200, undefined, 2500) : Promise.resolve(emptyLoaded()),
    knownAsn && radarToken ? lookupRadar(knownAsn, radarToken) : Promise.resolve(null),
  ]);

  const ripe = parseRipeIdentity(prefix.json);
  const who = ipwho.json ? parseIpwho(ipwho.json) : null;
  let resolvedAsn = knownAsn ?? ripe.asn ?? who?.asn ?? null;
  let rdapAsnBody = rdapAsn.json;
  let peeringBody = peering.json;
  let routingBody = routing.json;
  let radarReport = radar;

  if (!knownAsn && resolvedAsn) {
    const [asnBody, peeringLate, routingLate, radarLate] = await Promise.all([
      loadJson(`https://rdap.org/autnum/${resolvedAsn}`, `rdap-asn:${resolvedAsn}`, 43_200, { Accept: "application/rdap+json" }, 2500),
      loadJson(`https://www.peeringdb.com/api/net?asn=${resolvedAsn}`, `peeringdb:${resolvedAsn}`, 43_200, undefined, 2500),
      loadJson(`https://stat.ripe.net/data/routing-status/data.json?resource=AS${resolvedAsn}`, `ripe-routing:${resolvedAsn}`, 43_200, undefined, 2500),
      radarToken ? lookupRadar(resolvedAsn, radarToken) : Promise.resolve(null),
    ]);
    rdapAsnBody = asnBody.json;
    peeringBody = peeringLate.json;
    routingBody = routingLate.json;
    radarReport = radarLate;
  }

  const prefixText = ripe.prefix;
  const rpki = resolvedAsn && prefixText
    ? await loadJson(`https://stat.ripe.net/data/rpki-validation/data.json?resource=${resolvedAsn}&prefix=${encodeURIComponent(prefixText)}`, `rpki:${resolvedAsn}:${prefixText}`, 21_600, undefined, 2200)
    : emptyLoaded();

  const ipApiParsed = ipApi.json ? parseIpApi(ipApi.json) : null;
  const ipapiCoPlace = ipapiCo.json ? parseIpapiCo(ipapiCo.json) : null;
  const ipapiIsParsed = ipapiIs.json ? parseIpapiIs(ipapiIs.json) : null;
  const ipinfoPlace = ipinfo.json ? parseIpinfo(ipinfo.json, "ipinfo") : null;
  const biliPlace = bili.json ? parseBilibili(bili.json) : null;
  const ip2Parsed = ip2Key && ip2.json ? parseIp2Location(ip2.json) : null;
  const registered = registrationCountry(rdapIp.json, "RDAP") ?? registrationCountry(rdapAsnBody, "RDAP ASN");
  const rangeText = rdapRange(rdapIp.json);
  const cidr = parseRdapCidr(rdapIp.json);
  const names: { value: string; source: string }[] = [];
  pushUnique(names, rdapAsnName(rdapAsnBody), "RDAP");
  pushUnique(names, ripe.holder, "RIPEstat");
  pushUnique(names, input.cfOrg, "Cloudflare");
  pushUnique(names, who?.org ?? null, "ipwho.is");
  if (names.length === 0 && isRecord(ipinfo.json)) pushUnique(names, orgName(asText(ipinfo.json.org)), "ipinfo.io");
  const domains: { value: string; source: string }[] = [];
  pushUnique(domains, parsePeeringDbWebsite(peeringBody), "PeeringDB");
  pushUnique(domains, who?.domain ?? null, "ipwho.is");
  const rpkiParsed = parseRpki(rpki.json, prefixText);
  const network = baseNetwork("");
  network.queriedIp = ip;
  network.skipReason = null;
  network.places = [
    { ...cfPlace, ip },
    placeOrFail(ipinfoPlace, "ipinfo", "ipinfo.io", ipinfo.status),
    placeOrFail(ipApiParsed?.place ?? null, "ip-api", "ip-api.com", ipApi.status),
    placeOrFail(ipapiCoPlace, "ipapi-co", "ipapi.co", ipapiCo.status),
    placeOrFail(who?.place ?? null, "ipwho", "ipwho.is", ipwho.status),
    placeOrFail(ipapiIsParsed?.place ?? null, "ipapi-is", "ipapi.is", ipapiIs.status),
    ip2Key ? placeOrFail(ip2Parsed?.place ?? null, "ip2location", "IP2Location", ip2.status) : unavailablePlace("ip2location", "未设置 IP2LOCATION_KEY。", "未配置"),
    placeOrFail(biliPlace, "bilibili", "Bilibili", bili.status),
  ];
  network.risk = {
    tor: parseTorList(tor.ok ? tor.text : null, ip),
    ipApi: ipApiParsed && ipApiParsed.place.status === "已查询"
      ? { state: "已查询", hosting: ipApiParsed.hosting, proxy: ipApiParsed.proxy, mobile: ipApiParsed.mobile, note: ipApiParsed.place.note }
      : { state: "无法查询", hosting: null, proxy: null, mobile: null, note: ipApiParsed?.place.note ?? failNote("ip-api.com", ipApi.status) },
    proxycheck: proxy.json ? parseProxycheck(proxy.json, ip) : { state: "无法查询", proxy: null, type: null, provider: null, note: failNote("proxycheck.io", proxy.status) },
    ipapiIs: ipapiIsParsed && ipapiIsParsed.place.status === "已查询"
      ? { state: "已查询", isVpn: ipapiIsParsed.isVpn, isProxy: ipapiIsParsed.isProxy, isTor: ipapiIsParsed.isTor, isDatacenter: ipapiIsParsed.isDatacenter, isMobile: ipapiIsParsed.isMobile, note: ipapiIsParsed.place.note }
      : { state: "无法查询", isVpn: null, isProxy: null, isTor: null, isDatacenter: null, isMobile: null, note: ipapiIsParsed?.place.note ?? failNote("ipapi.is", ipapiIs.status) },
    ip2location: !ip2Key
      ? { state: "未配置", isProxy: null, note: "未设置 IP2LOCATION_KEY。" }
      : ip2Parsed && ip2Parsed.place.status === "已查询"
        ? { state: "已查询", isProxy: ip2Parsed.isProxy, note: ip2Parsed.place.note }
        : { state: "无法查询", isProxy: null, note: ip2Parsed?.place.note ?? failNote("IP2Location", ip2.status) },
  };
  network.identity = {
    asn: resolvedAsn,
    asnSource: knownAsn ? "Cloudflare" : ripe.asn ? "RIPEstat" : who?.asn ? "ipwho.is" : null,
    names,
    domains,
    range: rangeText ? { value: rangeText, source: "RDAP" } : cidr ? { value: cidr, source: "RDAP" } : null,
    prefix: prefixText ? { value: prefixText, source: "RIPEstat" } : null,
    registeredCountry: registered?.code ?? null,
    registeredCountrySource: registered?.source ?? null,
    ptr: ptrName ? parsePtr(ptr.json) : { state: "无法查询", value: null },
    rpki: { state: rpkiParsed.state, note: rpkiParsed.note },
  };
  network.radar = radarReport ?? (radarToken
    ? { state: "无法查询", human: null, bot: null, note: resolvedAsn ? "Cloudflare Radar 没有返回。" : "没有 ASN，不能查 Cloudflare Radar。" }
    : unconfiguredRadar(null, ""));
  return {
    history,
    intel: assembleIntel({
      ip,
      edgeCountry: input.country,
      ptrBody: ptr.json,
      rdapIp: rdapIp.json,
      rdapAsn: rdapAsnBody,
      prefixBody: prefix.json,
      routingBody,
      rpkiBody: rpki.json,
    }),
    network,
  };
}

function unconfiguredRadar(token: string | null, fallback: string): NetworkReport["radar"] {
  if (!token) return { state: "未配置", human: null, bot: null, note: "未设置 CF_RADAR_TOKEN。人机流量比不会用估算数字代替。" };
  return { state: "无法查询", human: null, bot: null, note: fallback || "Cloudflare Radar 没有查询。" };
}

function placeOrFail(place: GeoPlace | null, id: GeoPlace["id"], name: string, status: number | null): GeoPlace {
  if (place?.status === "已查询") return place;
  if (place) return place;
  return unavailablePlace(id, failNote(name, status));
}

async function lookupAbuse(ip: string): Promise<AbuseRecord> {
  const loaded = await loadJson(`https://api.stopforumspam.org/api?ip=${encodeURIComponent(ip)}&json`, `sfs:${ip}`, 3600, undefined, 1800);
  if (!loaded.json) return { source: "none", appears: null, frequency: null, lastSeen: null, attempted: true };
  return parseStopForumSpam(loaded.json) ?? { source: "none", appears: null, frequency: null, lastSeen: null, attempted: true };
}

async function lookupRadar(asn: string, token: string): Promise<NetworkReport["radar"]> {
  const loaded = await loadJson(
    `https://api.cloudflare.com/client/v4/radar/http/summary/bot_class?asn=${encodeURIComponent(asn)}&dateRange=7d&format=JSON`,
    `radar:${asn}`,
    21_600,
    { Authorization: `Bearer ${token}` },
    2200,
  );
  if (!loaded.json) return { state: "无法查询", human: null, bot: null, note: failNote("Cloudflare Radar", loaded.status) };
  const parsed = parseRadar(loaded.json);
  if (!parsed || parsed.human === null || parsed.bot === null) {
    return { state: "无法查询", human: null, bot: null, note: parsed?.note ?? "Cloudflare Radar 没有返回人机比例。" };
  }
  return { state: "已查询", human: parsed.human, bot: parsed.bot, note: parsed.note };
}

function emptyLoaded(): Loaded {
  return { json: null, status: null };
}

async function loadJson(url: string, cacheId: string, ttl: number, headers: HeadersInit | undefined, timeoutMs: number): Promise<Loaded> {
  const result = await loadText(url, cacheId, ttl, headers, timeoutMs, (text) => {
    try {
      JSON.parse(text);
      return true;
    } catch {
      return false;
    }
  });
  if (!result.ok) return { json: null, status: result.status };
  try {
    return { json: JSON.parse(result.text) as unknown, status: 200 };
  } catch {
    return { json: null, status: null };
  }
}

async function loadText(
  url: string,
  cacheId: string,
  ttl: number,
  headers: HeadersInit | undefined,
  timeoutMs: number,
  accept: (text: string) => boolean,
): Promise<{ ok: true; text: string } | { ok: false; status: number | null }> {
  const cacheKey = new Request(`https://cache.local/${encodeURIComponent(cacheId)}`);
  try {
    const hit = await edgeCache()?.match(cacheKey);
    if (hit) {
      const cached = await hit.text();
      if (accept(cached)) return { ok: true, text: cached };
    }
  } catch {
    /* Cache API is not available in every local runtime. */
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { Accept: "application/json", "User-Agent": UA, ...headers },
    });
    const text = await response.text();
    if (!response.ok || text.length > 1_000_000 || !accept(text)) return { ok: false, status: response.status };
    try {
      await edgeCache()?.put(cacheKey, new Response(text, { headers: { "Cache-Control": `public, max-age=${ttl}` } }));
    } catch {
      /* ignore cache write failures */
    }
    return { ok: true, text };
  } catch {
    return { ok: false, status: null };
  } finally {
    clearTimeout(timer);
  }
}

function edgeCache(): Cache | null {
  const store = (globalThis as { caches?: { default?: Cache } }).caches;
  return store?.default ?? null;
}

function torAccept(text: string): boolean {
  return text.length > 0 && text.length < 500_000 && /\d/.test(text) && !/<html/i.test(text);
}

function failNote(name: string, status: number | null): string {
  if (status === null) return `${name} 超时或没有连上。`;
  return `${name} 返回 HTTP ${status}。`;
}

function secret(value: string | undefined): string | null {
  const text = value?.trim();
  return text ? text : null;
}

function pushUnique(list: { value: string; source: string }[], value: string | null, source: string): void {
  if (!value) return;
  if (list.some((item) => item.value.toLowerCase() === value.toLowerCase())) return;
  list.push({ value, source });
}

function orgName(value: string | null): string | null {
  if (!value) return null;
  const text = value.replace(/^AS\d+\s+/i, "").trim();
  return text || null;
}

function asText(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
