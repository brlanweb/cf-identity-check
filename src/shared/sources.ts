/** Parsers for public IP, geo, ASN, and risk responses. A failed body becomes 无法查询, never a guessed place. */
import { canonicalIp, sameIp } from "./ip.ts";
import { parsePrefixOverview, parseRdapAsn, parseRdapIp } from "./intel.ts";
import { countryLabel } from "./score.ts";

export const SOURCE_IDS = [
  "cloudflare",
  "ipinfo",
  "ipinfo-direct",
  "ip-api",
  "ipapi-co",
  "ipwho",
  "ipapi-is",
  "ip2location",
  "ipip",
  "bilibili",
] as const;

export type SourceId = (typeof SOURCE_IDS)[number];

export const SERVER_SOURCE_IDS = ["cloudflare", "ipinfo", "ip-api", "ipapi-co", "ipwho", "ipapi-is", "ip2location", "bilibili"] as const;

export const SOURCE_LABEL: Record<SourceId, string> = {
  cloudflare: "Cloudflare",
  ipinfo: "ipinfo.io",
  "ipinfo-direct": "ipinfo.io（浏览器直连）",
  "ip-api": "ip-api.com",
  "ipapi-co": "ipapi.co",
  ipwho: "ipwho.is",
  "ipapi-is": "ipapi.is",
  ip2location: "IP2Location",
  ipip: "IPIP",
  bilibili: "Bilibili",
};

export type QueryState = "已查询" | "无法查询" | "未配置";

export type GeoPlace = {
  id: SourceId;
  status: QueryState;
  ip: string | null;
  countryCode: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
  note: string;
};

export type FacilityLabel = "机房IP" | "住宅IP" | "移动IP";

export type FacilityVote = { label: FacilityLabel; source: string };

const NAME_TO_CODE: Record<string, string> = {
  中国: "CN",
  中华人民共和国: "CN",
  china: "CN",
  "people's republic of china": "CN",
  香港: "HK",
  中国香港: "HK",
  "hong kong": "HK",
  澳门: "MO",
  澳門: "MO",
  中国澳门: "MO",
  macau: "MO",
  macao: "MO",
  台湾: "TW",
  台灣: "TW",
  中国台湾: "TW",
  taiwan: "TW",
  美国: "US",
  美國: "US",
  "united states": "US",
  "united states of america": "US",
  usa: "US",
  日本: "JP",
  japan: "JP",
  韩国: "KR",
  韓國: "KR",
  "south korea": "KR",
  "korea, republic of": "KR",
  "republic of korea": "KR",
  朝鲜: "KP",
  "north korea": "KP",
  新加坡: "SG",
  singapore: "SG",
  英国: "GB",
  英國: "GB",
  "united kingdom": "GB",
  "great britain": "GB",
  uk: "GB",
  德国: "DE",
  germany: "DE",
  法国: "FR",
  france: "FR",
  荷兰: "NL",
  "the netherlands": "NL",
  netherlands: "NL",
  加拿大: "CA",
  canada: "CA",
  澳大利亚: "AU",
  澳洲: "AU",
  australia: "AU",
  印度: "IN",
  india: "IN",
  俄罗斯: "RU",
  "russian federation": "RU",
  russia: "RU",
  巴西: "BR",
  brazil: "BR",
  意大利: "IT",
  italy: "IT",
  西班牙: "ES",
  spain: "ES",
  葡萄牙: "PT",
  portugal: "PT",
  瑞士: "CH",
  switzerland: "CH",
  瑞典: "SE",
  sweden: "SE",
  挪威: "NO",
  norway: "NO",
  丹麦: "DK",
  denmark: "DK",
  芬兰: "FI",
  finland: "FI",
  波兰: "PL",
  poland: "PL",
  土耳其: "TR",
  turkey: "TR",
  türkiye: "TR",
  乌克兰: "UA",
  ukraine: "UA",
  泰国: "TH",
  thailand: "TH",
  越南: "VN",
  vietnam: "VN",
  "viet nam": "VN",
  马来西亚: "MY",
  malaysia: "MY",
  印度尼西亚: "ID",
  印尼: "ID",
  indonesia: "ID",
  菲律宾: "PH",
  philippines: "PH",
  墨西哥: "MX",
  mexico: "MX",
  阿根廷: "AR",
  argentina: "AR",
  智利: "CL",
  chile: "CL",
  哥伦比亚: "CO",
  colombia: "CO",
  秘鲁: "PE",
  peru: "PE",
  南非: "ZA",
  "south africa": "ZA",
  埃及: "EG",
  egypt: "EG",
  尼日利亚: "NG",
  nigeria: "NG",
  肯尼亚: "KE",
  kenya: "KE",
  以色列: "IL",
  israel: "IL",
  阿联酋: "AE",
  "united arab emirates": "AE",
  沙特阿拉伯: "SA",
  "saudi arabia": "SA",
  伊朗: "IR",
  iran: "IR",
  爱尔兰: "IE",
  ireland: "IE",
  新西兰: "NZ",
  "new zealand": "NZ",
  比利时: "BE",
  belgium: "BE",
  奥地利: "AT",
  austria: "AT",
  捷克: "CZ",
  czechia: "CZ",
  "czech republic": "CZ",
  匈牙利: "HU",
  hungary: "HU",
  罗马尼亚: "RO",
  romania: "RO",
  希腊: "GR",
  greece: "GR",
  白俄罗斯: "BY",
  belarus: "BY",
  哈萨克斯坦: "KZ",
  kazakhstan: "KZ",
  巴基斯坦: "PK",
  pakistan: "PK",
  孟加拉: "BD",
  bangladesh: "BD",
  斯里兰卡: "LK",
  "sri lanka": "LK",
  柬埔寨: "KH",
  cambodia: "KH",
  老挝: "LA",
  laos: "LA",
  缅甸: "MM",
  myanmar: "MM",
  蒙古: "MN",
  mongolia: "MN",
  立陶宛: "LT",
  lithuania: "LT",
  拉脱维亚: "LV",
  latvia: "LV",
  爱沙尼亚: "EE",
  estonia: "EE",
  卢森堡: "LU",
  luxembourg: "LU",
  冰岛: "IS",
  iceland: "IS",
  卡塔尔: "QA",
  qatar: "QA",
  科威特: "KW",
  kuwait: "KW",
  巴林: "BH",
  bahrain: "BH",
  阿曼: "OM",
  oman: "OM",
  约旦: "JO",
  jordan: "JO",
  黎巴嫩: "LB",
  lebanon: "LB",
  伊拉克: "IQ",
  iraq: "IQ",
  叙利亚: "SY",
  syria: "SY",
  古巴: "CU",
  cuba: "CU",
  委内瑞拉: "VE",
  venezuela: "VE",
};

export function toCountryCode(value: string | null | undefined): string | null {
  if (!value) return null;
  const text = value.trim();
  if (/^[A-Za-z]{2}$/.test(text)) return text.toUpperCase();
  return NAME_TO_CODE[text.toLowerCase()] ?? NAME_TO_CODE[text] ?? null;
}

export function unavailablePlace(id: SourceId, note: string, status: QueryState = "无法查询"): GeoPlace {
  return {
    id,
    status,
    ip: null,
    countryCode: null,
    country: null,
    region: null,
    city: null,
    latitude: null,
    longitude: null,
    timezone: null,
    note: clip(note),
  };
}

export function finiteCoord(lat: unknown, lon: unknown): { latitude: number; longitude: number } | null {
  const latitude = asNumber(lat);
  const longitude = asNumber(lon);
  if (latitude === null || longitude === null) return null;
  if (latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) return null;
  if (latitude === 0 && longitude === 0) return null;
  return { latitude, longitude };
}

export function placeLine(place: GeoPlace): string {
  const parts = [place.country, place.region, place.city].filter((part): part is string => Boolean(part && part.trim()));
  return parts.length ? parts.join(" · ") : "—";
}

export function cloudflarePlace(input: {
  ip: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  latitude: unknown;
  longitude: unknown;
  timezone: string | null;
}): GeoPlace {
  const countryCode = toCountryCode(input.country);
  const coord = finiteCoord(input.latitude, input.longitude);
  if (!countryCode && !input.city && !input.region && !coord) {
    return unavailablePlace("cloudflare", "request.cf 没有国家、城市或坐标。本地开发时经常是空的，以部署到 Cloudflare 之后为准。");
  }
  return {
    id: "cloudflare",
    status: "已查询",
    ip: input.ip,
    countryCode,
    country: input.country,
    region: input.region,
    city: input.city,
    latitude: coord?.latitude ?? null,
    longitude: coord?.longitude ?? null,
    timezone: input.timezone,
    note: "来源 request.cf，对应这次请求的 CF-Connecting-IP。",
  };
}

export function parseIpApi(body: unknown): { place: GeoPlace; hosting: boolean | null; proxy: boolean | null; mobile: boolean | null } | null {
  if (!isRecord(body)) return null;
  if (body.status !== "success") {
    const message = typeof body.message === "string" ? body.message : "ip-api.com 没有返回成功结果";
    return { place: unavailablePlace("ip-api", message), hosting: null, proxy: null, mobile: null };
  }
  const coord = finiteCoord(body.lat, body.lon);
  const countryCode = toCountryCode(asText(body.countryCode));
  return {
    place: {
      id: "ip-api",
      status: "已查询",
      ip: asText(body.query),
      countryCode,
      country: asText(body.country),
      region: asText(body.regionName),
      city: asText(body.city),
      latitude: coord?.latitude ?? null,
      longitude: coord?.longitude ?? null,
      timezone: asText(body.timezone),
      note: "按边缘 IP 查询。proxy 字段把代理、VPN 和 Tor 合在一起。",
    },
    hosting: asBool(body.hosting),
    proxy: asBool(body.proxy),
    mobile: asBool(body.mobile),
  };
}

export function parseIpapiCo(body: unknown): GeoPlace | null {
  if (!isRecord(body)) return null;
  if (body.error === true || body.error) {
    const message = asText(body.message) ?? asText(body.reason) ?? "ipapi.co 拒绝了这次查询";
    return unavailablePlace("ipapi-co", message);
  }
  const countryCode = toCountryCode(asText(body.country_code) ?? asText(body.country));
  if (!countryCode && !asText(body.city)) return unavailablePlace("ipapi-co", "ipapi.co 没有返回地理位置。");
  const coord = finiteCoord(body.latitude, body.longitude);
  return {
    id: "ipapi-co",
    status: "已查询",
    ip: asText(body.ip),
    countryCode,
    country: asText(body.country_name) ?? asText(body.country),
    region: asText(body.region),
    city: asText(body.city),
    latitude: coord?.latitude ?? null,
    longitude: coord?.longitude ?? null,
    timezone: asText(body.timezone),
    note: "按边缘 IP 查询。",
  };
}

export function parseIpwho(body: unknown): { place: GeoPlace; domain: string | null; org: string | null; asn: string | null } | null {
  if (!isRecord(body)) return null;
  if (body.success === false) return { place: unavailablePlace("ipwho", asText(body.message) ?? "ipwho.is 没有返回成功结果"), domain: null, org: null, asn: null };
  const connection = isRecord(body.connection) ? body.connection : null;
  const timezone = isRecord(body.timezone) ? asText(body.timezone.id) : null;
  const coord = finiteCoord(body.latitude, body.longitude);
  const countryCode = toCountryCode(asText(body.country_code));
  if (!countryCode && !asText(body.city)) return null;
  return {
    place: {
      id: "ipwho",
      status: "已查询",
      ip: asText(body.ip),
      countryCode,
      country: asText(body.country),
      region: asText(body.region),
      city: asText(body.city),
      latitude: coord?.latitude ?? null,
      longitude: coord?.longitude ?? null,
      timezone,
      note: "按边缘 IP 查询。",
    },
    domain: hostName(connection ? asText(connection.domain) : null),
    org: connection ? asText(connection.org) : null,
    asn: connection && (typeof connection.asn === "number" || typeof connection.asn === "string") ? cleanAsn(String(connection.asn)) : null,
  };
}

export function parseIpapiIs(body: unknown): {
  place: GeoPlace;
  isVpn: boolean | null;
  isProxy: boolean | null;
  isTor: boolean | null;
  isDatacenter: boolean | null;
  isMobile: boolean | null;
} | null {
  if (!isRecord(body)) return null;
  if (body.error || body.message === "Invalid API key") {
    return {
      place: unavailablePlace("ipapi-is", asText(body.message) ?? "ipapi.is 没有返回成功结果"),
      isVpn: null,
      isProxy: null,
      isTor: null,
      isDatacenter: null,
      isMobile: null,
    };
  }
  const countryCode = toCountryCode(asText(body.country));
  const loc = isRecord(body.location) ? body.location : null;
  const country = asText(body.country) ?? (loc ? asText(loc.country) : null);
  const code = countryCode ?? (loc ? toCountryCode(asText(loc.country_code)) : null);
  const coord = finiteCoord(body.lat ?? loc?.latitude, body.lon ?? loc?.longitude);
  const flags = {
    isVpn: asBool(body.is_vpn),
    isProxy: asBool(body.is_proxy),
    isTor: asBool(body.is_tor),
    isDatacenter: asBool(body.is_datacenter),
    isMobile: asBool(body.is_mobile),
  };
  if (!code && !asText(body.city) && !loc) return null;
  const riskMissing = Object.values(flags).every((value) => value === null);
  return {
    place: {
      id: "ipapi-is",
      status: "已查询",
      ip: asText(body.ip),
      countryCode: code,
      country,
      region: asText(body.region) ?? (loc ? asText(loc.state) : null),
      city: asText(body.city) ?? (loc ? asText(loc.city) : null),
      latitude: coord?.latitude ?? null,
      longitude: coord?.longitude ?? null,
      timezone: asText(body.timezone) ?? (loc ? asText(loc.timezone) : null),
      note: riskMissing ? "按边缘 IP 查询。这次响应没有 is_vpn / is_datacenter 等风险字段。" : "按边缘 IP 查询。",
    },
    ...flags,
  };
}

type IpapiParsed = NonNullable<ReturnType<typeof parseIpapiIs>>;

/** Risk booleans are often absent without IPAPI_IS_KEY. Geo still stands; the empty risk row is 未配置. */
export function ipapiRiskFields(input: {
  parsed: IpapiParsed | null;
  hasKey: boolean;
  failureNote: string;
}): {
  state: QueryState;
  isVpn: boolean | null;
  isProxy: boolean | null;
  isTor: boolean | null;
  isDatacenter: boolean | null;
  isMobile: boolean | null;
  note: string;
} {
  const parsed = input.parsed;
  const queried = parsed?.place.status === "已查询";
  if (!parsed || !queried) {
    return {
      state: "无法查询",
      isVpn: null,
      isProxy: null,
      isTor: null,
      isDatacenter: null,
      isMobile: null,
      note: parsed?.place.note || input.failureNote,
    };
  }
  const flags = [parsed.isVpn, parsed.isProxy, parsed.isTor, parsed.isDatacenter, parsed.isMobile];
  const missingKey = !input.hasKey && flags.every((flag) => flag === null);
  return {
    state: missingKey ? "未配置" : "已查询",
    isVpn: parsed.isVpn,
    isProxy: parsed.isProxy,
    isTor: parsed.isTor,
    isDatacenter: parsed.isDatacenter,
    isMobile: parsed.isMobile,
    note: missingKey ? "未设置 IPAPI_IS_KEY。地理结果仍会显示，缺的风险字段不当成否。" : parsed.place.note,
  };
}

export function parseIpinfo(body: unknown, id: "ipinfo" | "ipinfo-direct"): GeoPlace | null {
  if (!isRecord(body)) return null;
  if (body.error || body.status === 429 || body.bogon === true) {
    const message = isRecord(body.error) ? asText(body.error.message) ?? asText(body.error.title) : asText(body.error);
    return unavailablePlace(id, message ?? "ipinfo.io 没有返回地理位置");
  }
  const countryCode = toCountryCode(asText(body.country));
  if (!countryCode && !asText(body.city)) return null;
  const loc = asText(body.loc);
  const [lat, lon] = loc ? loc.split(",") : [];
  const coord = finiteCoord(lat, lon);
  const anycast = body.anycast === true ? " ipinfo 标记为 anycast。" : "";
  return {
    id,
    status: "已查询",
    ip: asText(body.ip),
    countryCode,
    country: asText(body.country),
    region: asText(body.region),
    city: asText(body.city),
    latitude: coord?.latitude ?? null,
    longitude: coord?.longitude ?? null,
    timezone: asText(body.timezone),
    note: id === "ipinfo" ? `按边缘 IP 查询。${anycast}`.trim() : `浏览器直接请求 ipinfo.io 时它看到的地址。${anycast}`.trim(),
  };
}

export function parseIp2Location(body: unknown): { place: GeoPlace; isProxy: boolean | null } | null {
  if (!isRecord(body)) return null;
  const error = isRecord(body.error) ? body.error : null;
  if (error) return { place: unavailablePlace("ip2location", asText(error.error_message) ?? "IP2Location 拒绝了这次查询"), isProxy: null };
  const countryCode = toCountryCode(asText(body.country_code));
  if (!countryCode && !asText(body.city_name)) return { place: unavailablePlace("ip2location", "IP2Location 没有返回地理位置。"), isProxy: null };
  const coord = finiteCoord(body.latitude, body.longitude);
  const zone = asText(body.time_zone);
  return {
    place: {
      id: "ip2location",
      status: "已查询",
      ip: asText(body.ip),
      countryCode,
      country: asText(body.country_name),
      region: asText(body.region_name),
      city: asText(body.city_name),
      latitude: coord?.latitude ?? null,
      longitude: coord?.longitude ?? null,
      timezone: zone && zone.includes("/") ? zone : null,
      note: "按边缘 IP 查询，使用 IP2LOCATION_KEY。",
    },
    isProxy: asBool(body.is_proxy),
  };
}

export function parseIpip(body: unknown): GeoPlace | null {
  if (!isRecord(body)) return null;
  if (body.ret !== "ok" || !isRecord(body.data)) return unavailablePlace("ipip", "myip.ipip.net 没有返回位置。");
  const data = body.data;
  const location = Array.isArray(data.location) ? data.location.map((part) => (typeof part === "string" ? part.trim() : "")).filter(Boolean) : [];
  const [country, region, city] = location;
  const countryCode = toCountryCode(country);
  if (!country && !region && !city) return unavailablePlace("ipip", "myip.ipip.net 的位置是空的。");
  return {
    id: "ipip",
    status: "已查询",
    ip: asText(data.ip),
    countryCode,
    country: country ?? null,
    region: region ?? null,
    city: city ?? null,
    latitude: null,
    longitude: null,
    timezone: null,
    note: "浏览器直连 myip.ipip.net。这是中国侧看到的地址，不是按边缘 IP 反查。",
  };
}

export function parseBilibili(body: unknown): GeoPlace | null {
  if (!isRecord(body)) return null;
  if (body.code !== 0 || !isRecord(body.data)) return unavailablePlace("bilibili", asText(body.message) ?? "Bilibili 没有返回位置。");
  const data = body.data;
  const country = asText(data.country);
  const region = asText(data.province);
  const city = asText(data.city);
  const countryCode = toCountryCode(country);
  if (!country && !region && !city) return unavailablePlace("bilibili", "Bilibili 的位置字段是空的。");
  const coord = finiteCoord(data.latitude, data.longitude);
  const odd = country && !countryCode ? " 国家字段不像国家名，按原文显示。" : "";
  return {
    id: "bilibili",
    status: "已查询",
    ip: asText(data.addr),
    countryCode,
    country,
    region,
    city,
    latitude: coord?.latitude ?? null,
    longitude: coord?.longitude ?? null,
    timezone: null,
    note: `按边缘 IP 查询 api.live.bilibili.com。${odd}`.trim(),
  };
}

export function parseProxycheck(body: unknown, ip: string): {
  state: QueryState;
  proxy: boolean | null;
  type: string | null;
  provider: string | null;
  note: string;
} {
  if (!isRecord(body) || (body.status !== "ok" && body.status !== "warning")) {
    return { state: "无法查询", proxy: null, type: null, provider: null, note: "proxycheck.io 没有返回结果。" };
  }
  const row = findIpRow(body, ip);
  if (!row) return { state: "无法查询", proxy: null, type: null, provider: null, note: "proxycheck.io 的响应里没有这个 IP。" };
  const proxy = row.proxy === "yes" ? true : row.proxy === "no" ? false : null;
  return {
    state: "已查询",
    proxy,
    type: asText(row.type),
    provider: asText(row.provider),
    note: "proxycheck.io。type 为 VPN、TOR、SOCKS 时单独计入；Business 不拿来判断机房或住宅。",
  };
}

/** Hide the row only when the API itself says a key is required. Quota and transport failures stay visible. */
export function proxycheckReport(input: {
  body: unknown;
  ip: string;
  hasKey: boolean;
  failureNote: string;
}): ReturnType<typeof parseProxycheck> {
  if (!input.body) {
    return { state: "无法查询", proxy: null, type: null, provider: null, note: input.failureNote };
  }
  const parsed = parseProxycheck(input.body, input.ip);
  if (parsed.state === "已查询" || input.hasKey || !proxycheckNeedsKey(input.body)) return parsed;
  return {
    state: "未配置",
    proxy: null,
    type: null,
    provider: null,
    note: "未设置 PROXYCHECK_KEY。接口要求密钥，这次没有可用结果。",
  };
}

function proxycheckNeedsKey(body: unknown): boolean {
  if (!isRecord(body)) return false;
  const message = `${asText(body.message) ?? ""} ${asText(body.error) ?? ""}`.toLowerCase();
  if (!message.trim() || /quota|limit|exceed|too many|rate/.test(message)) return false;
  return /api key|apikey|key required|missing key|no api key/.test(message);
}

const VPN_TYPES = new Set(["vpn", "openvpn"]);
const TOR_TYPES = new Set(["tor"]);
const RESIDENTIAL_TYPES = new Set(["residential", "isp"]);
const MOBILE_TYPES = new Set(["wireless", "mobile"]);

export function proxycheckKind(type: string | null, proxy: boolean | null): { vpn: boolean; tor: boolean; proxy: boolean; residential: boolean; mobile: boolean } {
  const text = (type ?? "").trim().toLowerCase();
  return {
    vpn: VPN_TYPES.has(text),
    tor: TOR_TYPES.has(text),
    proxy: proxy === true && !VPN_TYPES.has(text) && !TOR_TYPES.has(text),
    residential: RESIDENTIAL_TYPES.has(text),
    mobile: MOBILE_TYPES.has(text),
  };
}

export function parseTorList(body: string | null, ip: string): { state: QueryState; listed: boolean | null; note: string } {
  if (!body || !/\d/.test(body) || /<html/i.test(body)) {
    return { state: "无法查询", listed: null, note: "Tor 出口列表没有返回，不能当成不在列表里。" };
  }
  const listed = torListHas(body, ip);
  return listed
    ? { state: "已查询", listed: true, note: "这个地址在 Tor Project 的 torbulkexitlist 里。" }
    : { state: "已查询", listed: false, note: "torbulkexitlist 里没有这个地址。列表有延迟。" };
}

export function torListHas(body: string, ip: string): boolean {
  const want = canonicalIp(ip);
  if (!want) return false;
  for (const line of body.split(/\s+/)) {
    const item = canonicalIp(line);
    if (item && item === want) return true;
  }
  return false;
}

export function parseRadar(body: unknown): { human: number | null; bot: number | null; note: string } | null {
  if (!isRecord(body)) return null;
  if (body.success === false) {
    const errors = Array.isArray(body.errors) ? body.errors : [];
    const first = errors.find((item) => isRecord(item));
    const message = first && isRecord(first) ? asText(first.message) ?? "" : "";
    if (/auth|token|permission|unauthorized/i.test(message)) return { human: null, bot: null, note: "Cloudflare Radar 拒绝了 CF_RADAR_TOKEN。" };
    return { human: null, bot: null, note: "Cloudflare Radar 没有返回人机比例。" };
  }
  const result = isRecord(body.result) ? body.result : null;
  const summary = result && isRecord(result.summary_0) ? result.summary_0 : null;
  if (!summary) return null;
  const human = asNumber(summary.human);
  const bot = asNumber(summary.bot);
  if (human === null || bot === null || human < 0 || bot < 0) return null;
  if (human <= 1 && bot <= 1 && human + bot > 0 && human + bot <= 1.05) {
    return { human: round2(human * 100), bot: round2(bot * 100), note: "Cloudflare Radar HTTP bot class，近 7 日，按 ASN 而不是单个 IP。" };
  }
  const sum = human + bot;
  const note = Math.abs(sum - 100) > 1.5 ? "Cloudflare Radar 返回的两项之和不是 100，按原样显示。" : "Cloudflare Radar HTTP bot class，近 7 日，按 ASN 而不是单个 IP。";
  return { human: round2(human), bot: round2(bot), note };
}

export function parsePeeringDbWebsite(body: unknown): string | null {
  if (!isRecord(body) || !Array.isArray(body.data)) return null;
  const first = body.data.find((item) => isRecord(item));
  if (!first || !isRecord(first)) return null;
  return hostName(asText(first.website));
}

export function parseRipeIdentity(body: unknown): { prefix: string | null; asn: string | null; holder: string | null } {
  const overview = parsePrefixOverview(body);
  let asn: string | null = null;
  if (isRecord(body) && isRecord(body.data) && Array.isArray(body.data.asns)) {
    const first = body.data.asns.find((item) => isRecord(item));
    if (first && isRecord(first)) asn = cleanAsn(typeof first.asn === "number" ? String(first.asn) : asText(first.asn));
  }
  return { prefix: overview.prefix, asn, holder: overview.holder };
}

export function parseRdapCidr(body: unknown): string | null {
  if (!isRecord(body) || !Array.isArray(body.cidr0_cidrs)) return null;
  const first = body.cidr0_cidrs.find((item) => isRecord(item));
  if (!first || !isRecord(first)) return null;
  const prefix = asText(first.v4prefix) ?? asText(first.v6prefix);
  const length = typeof first.length === "number" ? first.length : null;
  if (!prefix || length === null) return null;
  return `${prefix}/${length}`;
}

export function registrationCountry(body: unknown, sourcePrefix = "RDAP"): { code: string; source: string } | null {
  if (!isRecord(body)) return null;
  const network = toCountryCode(asText(body.country));
  if (network) return { code: network, source: `${sourcePrefix} network.country` };
  for (const entity of entities(body)) {
    if (!hasRole(entity, "registrant")) continue;
    const code = adrCountry(entity) ?? nestedRegistrantCountry(entity);
    if (code) return { code, source: `${sourcePrefix} 登记地址` };
  }
  return null;
}

export function rdapAsnName(body: unknown): string | null {
  return parseRdapAsn(body)?.name ?? null;
}

export function rdapRange(body: unknown): string | null {
  const range = parseRdapIp(body).range;
  return range;
}

export function ipOrigin(registered: string | null, places: { source: string; countryCode: string | null }[]): { label: "广播IP" | "原生IP" | "无法判断"; note: string } {
  if (!registered) return { label: "无法判断", note: "RDAP 没有登记国家，不能判断是广播还是原生。" };
  const votes = places.filter((place) => place.countryCode);
  if (votes.length === 0) return { label: "无法判断", note: `${countryLabel(registered)} 有登记国，但没有带国家代码的地理位置可以比较。` };
  const differ = votes.filter((place) => place.countryCode !== registered);
  if (differ.length === 0) {
    return { label: "原生IP", note: `登记国 ${countryLabel(registered)} 与 ${votes.map((place) => place.source).join("、")} 的国家一致。` };
  }
  const same = votes.filter((place) => place.countryCode === registered).map((place) => place.source);
  const diffText = differ.map((place) => `${place.source} ${countryLabel(place.countryCode)}`).join("、");
  const sameText = same.length ? `一致的有 ${same.join("、")}。` : "";
  return { label: "广播IP", note: `登记国 ${countryLabel(registered)}，与 ${diffText} 不一致。${sameText}` };
}

export function facilityVotes(input: {
  ipApiHosting: boolean | null;
  ipApiMobile: boolean | null;
  ipapiIsDatacenter: boolean | null;
  ipapiIsMobile: boolean | null;
  residential: boolean;
  mobile: boolean;
}): FacilityVote[] {
  const votes: FacilityVote[] = [];
  if (input.ipApiHosting === true) votes.push({ label: "机房IP", source: "ip-api.com hosting" });
  if (input.ipApiMobile === true) votes.push({ label: "移动IP", source: "ip-api.com mobile" });
  if (input.ipapiIsDatacenter === true) votes.push({ label: "机房IP", source: "ipapi.is is_datacenter" });
  if (input.ipapiIsMobile === true) votes.push({ label: "移动IP", source: "ipapi.is is_mobile" });
  if (input.residential) votes.push({ label: "住宅IP", source: "proxycheck.io" });
  if (input.mobile) votes.push({ label: "移动IP", source: "proxycheck.io" });
  return votes;
}

export function facilitySummary(votes: FacilityVote[], hostingFalse: boolean): { label: FacilityLabel | "不一致" | "无法查询"; note: string } {
  if (votes.length === 0) {
    const extra = hostingFalse ? "ip-api.com 的 hosting 为否，这不够标成住宅。" : "没有来源正面给出机房、住宅或移动。";
    return { label: "无法查询", note: extra };
  }
  const labels = [...new Set(votes.map((vote) => vote.label))];
  const detail = votes.map((vote) => `${vote.source}：${vote.label}`).join("；");
  if (labels.length === 1) return { label: labels[0] ?? "无法查询", note: detail };
  return { label: "不一致", note: detail };
}

export function observedIpNote(place: GeoPlace, edgeIp: string | null): GeoPlace {
  if (place.status !== "已查询" || !place.ip || !edgeIp || sameIp(place.ip, edgeIp)) return place;
  return { ...place, note: `${place.note} 该来源记录的 IP 与 CF-Connecting-IP 不同。`.trim() };
}

function nestedRegistrantCountry(entity: Record<string, unknown>): string | null {
  for (const child of entities(entity)) {
    if (!hasRole(child, "registrant")) continue;
    const code = adrCountry(child);
    if (code) return code;
  }
  return null;
}

function entities(body: Record<string, unknown> | unknown): Record<string, unknown>[] {
  if (!isRecord(body) || !Array.isArray(body.entities)) return [];
  return body.entities.filter((item): item is Record<string, unknown> => isRecord(item));
}

function hasRole(entity: Record<string, unknown>, role: string): boolean {
  return Array.isArray(entity.roles) && entity.roles.includes(role);
}

function adrCountry(entity: Record<string, unknown>): string | null {
  const vcard = entity.vcardArray;
  if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) return null;
  for (const row of vcard[1]) {
    if (!Array.isArray(row) || row[0] !== "adr") continue;
    const params = isRecord(row[1]) ? row[1] : null;
    const value = row[3];
    if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index -= 1) {
        const part = value[index];
        if (typeof part !== "string" || !part.trim()) continue;
        const code = toCountryCode(part.trim());
        if (code) return code;
      }
    }
    const label = params ? asText(params.label) : null;
    if (label) {
      const lines = label.split(/\n/).map((line) => line.trim()).filter(Boolean);
      const last = lines[lines.length - 1];
      const code = last ? toCountryCode(last) : null;
      if (code) return code;
    }
  }
  return null;
}

function findIpRow(body: Record<string, unknown>, ip: string): Record<string, unknown> | null {
  const direct = body[ip];
  if (isRecord(direct)) return direct;
  for (const [key, value] of Object.entries(body)) {
    if (!isRecord(value)) continue;
    if (sameIp(key, ip)) return value;
  }
  return null;
}

function hostName(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    const withScheme = /^[a-z]+:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    const host = new URL(withScheme).hostname.replace(/^www\./, "").toLowerCase();
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) return null;
    return host;
  } catch {
    return null;
  }
}

export function cleanAsn(value: string | null | undefined): string | null {
  if (!value) return null;
  const text = value.trim().replace(/^AS/i, "");
  return /^\d+$/.test(text) ? text : null;
}

function asText(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function asBool(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function asNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) return Number(value);
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function clip(value: string): string {
  const text = value.replace(/\s+/g, " ").trim();
  return text.length > 180 ? `${text.slice(0, 177)}…` : text;
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}
