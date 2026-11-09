/**
 * Heuristic trust score for the exit IP a Claude-style service would see.
 * Not an Anthropic product and not a connectivity test.
 * DNS is left unscored when neither the browser nor the edge exposes a resolver.
 * History never invents an abuse record.
 */
import { historyCopy, type AbuseRecord } from "./history.ts";
import { headerValue, unquote } from "./redact.ts";

export type Tone = "ok" | "warn" | "bad" | "neutral";

export type AttributeKind = "residential" | "datacenter" | "native" | "unknown";

export type EdgeSnapshot = {
  connectingIp: string | null;
  country: string | null;
  timezone: string | null;
  asOrganization: string | null;
  asn: string | null;
  colo: string | null;
  city: string | null;
  region: string | null;
};

export type ScoreInput = {
  edge: EdgeSnapshot | null;
  claimed: {
    userAgent: string;
    chPlatform: string | null;
    chMobile: boolean | null;
    acceptLanguage: string | null;
    languages: string[];
    timezone: string;
    platform: string;
  };
  observed: {
    webdriver: boolean;
    webglRenderer: string | null;
    screenWidth: number;
    screenHeight: number;
    outerWidth: number;
    outerHeight: number;
    webrtcGlobalIps: string[];
    webrtcCandidates: number;
    webrtcError: string | null;
    webrtcMdns: boolean;
    canvasHash: string | null;
    audioHash: string | null;
  };
  abuse?: AbuseRecord | null;
};

export type Mismatch = {
  label: string;
  claimed: string;
  observed: string;
  detail: string;
  severity: "info" | "warn" | "bad";
};

export type SignalId = "dns" | "udp" | "timezone" | "fingerprint" | "security";

export type SignalCard = {
  id: SignalId;
  label: string;
  score: number | null;
  tone: Tone;
  badge: string;
  note: string;
};

export type CheckState = "未发现" | "疑似" | "无记录" | "有公开记录" | "无法查询";

export type SceneAdvice = "推荐" | "一般" | "不推荐";

export type ScoreResult = {
  trust: {
    score: number;
    tone: Tone;
    band: "较高" | "中等" | "偏低" | "较低";
    headline: "良好" | "一般" | "高危";
    detail: string;
  };
  purity: { score: number; tone: Tone; band: "高" | "中" | "低" };
  risk: { score: number | null; tone: Tone; band: "低" | "中" | "高" | "未知" };
  regionSupport: { state: "正常" | "受限" | "无法判断"; note: string };
  securityChecks: {
    vpn: { state: CheckState; note: string };
    proxy: { state: CheckState; note: string };
    tor: { state: CheckState; note: string };
    crawler: { state: CheckState; note: string };
    abuse: { state: CheckState; note: string };
  };
  scenes: {
    ai: { score: number; advice: SceneAdvice };
    social: { score: number; advice: SceneAdvice };
    tiktok: { score: number; advice: SceneAdvice };
  };
  traffic: { human: number; machine: number; badge: "人类为主" | "机器偏多"; source: "估算" };
  deviceHints: {
    timezone: "一致" | "不一致" | "无法对照";
    language: "一致" | "不一致" | "无法对照";
    languageNote: string;
  };
  attribute: {
    kind: AttributeKind;
    label: "住宅" | "机房" | "原生" | "未知";
    /** Residential path that also looks native, or an unclassified non-datacenter ISP. */
    native: boolean;
    tag: "原生" | "VPN" | "Tor" | null;
    tone: Tone;
    note: string;
  };
  signals: SignalCard[];
  history: {
    label: string;
    note: string;
    source: AbuseRecord["source"];
    appears: boolean | null;
    frequency: number | null;
    lastSeen: string | null;
  };
  exit: {
    ip: string | null;
    countryLabel: string;
    city: string | null;
    asOrganization: string | null;
    asn: string | null;
    colo: string | null;
    country: string | null;
    region: string | null;
  };
  summary: string;
  notes: string[];
  mismatches: Mismatch[];
};

const TRUST_WEIGHT = { purity: 0.3, udp: 0.16, timezone: 0.18, fingerprint: 0.14, security: 0.22 };

const PROXY_HINTS = [
  "proxy",
  "luminati",
  "bright data",
  "brightdata",
  "oxylabs",
  "iproyal",
  "smartproxy",
  "geosurf",
  "netnut",
  "soax",
  "packetstream",
];

const VPN_HINTS = [
  "mullvad",
  "nordvpn",
  "nord vpn",
  "expressvpn",
  "express vpn",
  "protonvpn",
  "proton ag",
  "surfshark",
  "private internet",
  "ipvanish",
  "cyberghost",
  "windscribe",
  "hide.me",
  "astrill",
  "vpn",
];

const STRONG_HOSTING = [
  "amazon",
  "aws",
  "google cloud",
  "google llc",
  "microsoft azure",
  "microsoft corporation",
  "digitalocean",
  "linode",
  "akamai",
  "cloudflare",
  "ovh",
  "hetzner",
  "vultr",
  "choopa",
  "the constant company",
  "leaseweb",
  "m247",
  "datacamp",
  "psychz",
  "quadranet",
  "contabo",
  "oracle",
  "alibaba",
  "tencent",
  "huawei cloud",
  "scaleway",
  "g-core",
  "cdn77",
  "hostinger",
  "ionos",
  "online s.a.s",
  "frantech",
  "buyvm",
  "nforce",
  "serverius",
  "combahton",
  "colo crossing",
  "packethub",
  "hostwinds",
  "tzulo",
  "cogent",
  "hurricane electric",
  "zenlayer",
  "kaopu",
  "peg tech",
  "hostroyale",
  "datacamp limited",
  "24shells",
];

const WEAK_HOSTING = ["hosting", "datacenter", "data center", "colo", "cloud"];

const RESIDENTIAL = [
  "comcast",
  "verizon",
  "at&t",
  "charter",
  "spectrum",
  "cox comm",
  "china telecom",
  "china unicom",
  "china mobile",
  "chinanet",
  "deutsche telekom",
  "vodafone",
  "orange",
  "british telecom",
  "ntt ",
  "kddi",
  "softbank",
  "sk broadband",
  "sk telecom",
  "telstra",
  "optus",
  "rogers",
  "bell canada",
  "telus",
  "telecom italia",
  "telefonica",
  "swisscom",
  "telia",
  "telenor",
  "ziggo",
  "bouygues",
  "virgin media",
  "singtel",
  "starhub",
  "viettel",
  "vnpt",
  "fpt telecom",
  "google fiber",
  "broadband",
  "cable",
  "residential",
];

const TZ_COUNTRY: Record<string, string> = {
  "Asia/Shanghai": "CN",
  "Asia/Chongqing": "CN",
  "Asia/Harbin": "CN",
  "Asia/Urumqi": "CN",
  "Asia/Kashgar": "CN",
  "Asia/Hong_Kong": "HK",
  "Asia/Macau": "MO",
  "Asia/Taipei": "TW",
  "Asia/Tokyo": "JP",
  "Asia/Seoul": "KR",
  "Asia/Singapore": "SG",
  "Asia/Bangkok": "TH",
  "Asia/Jakarta": "ID",
  "Asia/Ho_Chi_Minh": "VN",
  "Asia/Manila": "PH",
  "Asia/Kuala_Lumpur": "MY",
  "Asia/Kolkata": "IN",
  "Asia/Calcutta": "IN",
  "Asia/Karachi": "PK",
  "Asia/Dhaka": "BD",
  "Asia/Dubai": "AE",
  "Asia/Riyadh": "SA",
  "Asia/Jerusalem": "IL",
  "Asia/Tehran": "IR",
  "Asia/Baghdad": "IQ",
  "Europe/London": "GB",
  "Europe/Dublin": "IE",
  "Europe/Lisbon": "PT",
  "Europe/Paris": "FR",
  "Europe/Berlin": "DE",
  "Europe/Rome": "IT",
  "Europe/Madrid": "ES",
  "Europe/Amsterdam": "NL",
  "Europe/Brussels": "BE",
  "Europe/Zurich": "CH",
  "Europe/Vienna": "AT",
  "Europe/Prague": "CZ",
  "Europe/Warsaw": "PL",
  "Europe/Stockholm": "SE",
  "Europe/Oslo": "NO",
  "Europe/Copenhagen": "DK",
  "Europe/Helsinki": "FI",
  "Europe/Athens": "GR",
  "Europe/Bucharest": "RO",
  "Europe/Budapest": "HU",
  "Europe/Istanbul": "TR",
  "Europe/Moscow": "RU",
  "Europe/Kyiv": "UA",
  "Europe/Kiev": "UA",
  "America/New_York": "US",
  "America/Detroit": "US",
  "America/Chicago": "US",
  "America/Denver": "US",
  "America/Phoenix": "US",
  "America/Los_Angeles": "US",
  "America/Anchorage": "US",
  "America/Juneau": "US",
  "America/Nome": "US",
  "America/Sitka": "US",
  "America/Adak": "US",
  "America/Boise": "US",
  "America/Indiana/Indianapolis": "US",
  "America/Kentucky/Louisville": "US",
  "America/North_Dakota/Center": "US",
  "Pacific/Honolulu": "US",
  "America/Toronto": "CA",
  "America/Vancouver": "CA",
  "America/Winnipeg": "CA",
  "America/Edmonton": "CA",
  "America/Halifax": "CA",
  "America/St_Johns": "CA",
  "America/Regina": "CA",
  "America/Mexico_City": "MX",
  "America/Sao_Paulo": "BR",
  "America/Buenos_Aires": "AR",
  "America/Bogota": "CO",
  "America/Lima": "PE",
  "America/Santiago": "CL",
  "Australia/Sydney": "AU",
  "Australia/Melbourne": "AU",
  "Australia/Perth": "AU",
  "Australia/Brisbane": "AU",
  "Australia/Adelaide": "AU",
  "Pacific/Auckland": "NZ",
  "Africa/Cairo": "EG",
  "Africa/Johannesburg": "ZA",
  "Africa/Lagos": "NG",
  "Africa/Nairobi": "KE",
};

/** Countries often absent from Claude's published coverage. Informational only — not part of purity. */
const REGION_NOTE = new Set(["CN", "RU", "BY", "IR", "KP", "SY", "CU"]);

const COUNTRY_LANG: Record<string, string> = {
  US: "en", GB: "en", AU: "en", CA: "en", NZ: "en", IE: "en",
  CN: "zh", TW: "zh", HK: "zh", MO: "zh",
  JP: "ja", KR: "ko", DE: "de", FR: "fr", ES: "es", PT: "pt", BR: "pt",
  RU: "ru", NL: "nl", IT: "it", PL: "pl", TR: "tr", VN: "vi", TH: "th", ID: "id",
};

const LANG_ZH: Record<string, string> = {
  en: "英语", zh: "中文", ja: "日语", ko: "韩语", de: "德语", fr: "法语", es: "西班牙语",
  pt: "葡萄牙语", ru: "俄语", nl: "荷兰语", it: "意大利语", pl: "波兰语", tr: "土耳其语",
  vi: "越南语", th: "泰语", id: "印尼语",
};

const COUNTRY_ZH: Record<string, string> = {
  CN: "中国",
  HK: "中国香港",
  MO: "中国澳门",
  TW: "中国台湾",
  US: "美国",
  JP: "日本",
  KR: "韩国",
  SG: "新加坡",
  GB: "英国",
  DE: "德国",
  FR: "法国",
  NL: "荷兰",
  CA: "加拿大",
  AU: "澳大利亚",
  IN: "印度",
  IR: "伊朗",
  TM: "土库曼斯坦",
  KP: "朝鲜",
  ER: "厄立特里亚",
  RU: "俄罗斯",
  BR: "巴西",
  SY: "叙利亚",
  CU: "古巴",
  BY: "白俄罗斯",
  VE: "委内瑞拉",
  T1: "Tor",
  XX: "未知",
};

const ATTR_LABEL: Record<AttributeKind, ScoreResult["attribute"]["label"]> = {
  residential: "住宅",
  datacenter: "机房",
  native: "原生",
  unknown: "未知",
};

const EMPTY_ABUSE: AbuseRecord = {
  source: "none",
  appears: null,
  frequency: null,
  lastSeen: null,
  attempted: false,
};

export function countryLabel(code: string | null): string {
  if (!code) return "未知";
  const upper = code.toUpperCase();
  const name = COUNTRY_ZH[upper];
  return name ? `${name}（${upper}）` : upper;
}

export function primaryLanguage(tag: string | null | undefined): string {
  if (!tag) return "";
  const first = tag.split(",")[0]?.trim().split(";")[0]?.trim().toLowerCase() ?? "";
  return first.split("-")[0] ?? "";
}

function normPlatform(value: string | null | undefined): string {
  const text = (value ?? "").toLowerCase();
  if (!text) return "";
  if (text.includes("iphone") || text.includes("ipad") || text.includes("ios")) return "ios";
  if (text.includes("android")) return "android";
  if (text.includes("cros") || text.includes("chrome os") || text.includes("chromeos")) return "chromeos";
  if (text.includes("win")) return "windows";
  if (text.includes("mac") || text.includes("os x") || text.includes("darwin")) return "mac";
  if (text.includes("linux") || text.includes("x11")) return "linux";
  return text;
}

function platformFromUserAgent(userAgent: string): string {
  const ua = userAgent.toLowerCase();
  if (ua.includes("iphone") || ua.includes("ipad") || ua.includes("ipod")) return "ios";
  if (ua.includes("android")) return "android";
  if (ua.includes("cros")) return "chromeos";
  if (ua.includes("windows")) return "windows";
  if (ua.includes("mac os") || ua.includes("macintosh")) return "mac";
  if (ua.includes("linux")) return "linux";
  return "";
}

export function parseClientHintMobile(value: string | null): boolean | null {
  if (!value) return null;
  const text = value.trim();
  if (text === "?1") return true;
  if (text === "?0") return false;
  return null;
}

function includesAny(haystack: string, needles: string[]): string | null {
  for (const needle of needles) {
    if (haystack.includes(needle)) return needle;
  }
  return null;
}

function classifyOrganization(organization: string | null): {
  kind: "residential" | "hosting" | "unknown";
  vpn: boolean;
  hit: string | null;
} {
  const text = (organization ?? "").toLowerCase();
  if (!text.trim()) return { kind: "unknown", vpn: false, hit: null };
  const vpn = includesAny(text, VPN_HINTS);
  if (vpn) return { kind: "hosting", vpn: true, hit: vpn };
  const strong = includesAny(text, STRONG_HOSTING);
  if (strong) return { kind: "hosting", vpn: false, hit: strong };
  const residential = includesAny(text, RESIDENTIAL);
  if (residential) return { kind: "residential", vpn: false, hit: residential };
  const weak = includesAny(text, WEAK_HOSTING);
  if (weak) return { kind: "hosting", vpn: false, hit: weak };
  return { kind: "unknown", vpn: false, hit: null };
}

function isTor(country: string, organization: string | null): boolean {
  if (country === "T1") return true;
  const text = (organization ?? "").toLowerCase();
  return /\btor\b/.test(text) || text.includes("tor exit") || text.includes("torservers");
}

function timezoneCountry(zone: string | null): string | null {
  if (!zone) return null;
  return TZ_COUNTRY[zone] ?? null;
}

type GeoResult = { score: number; note: string; conflict: boolean };

function compareGeo(browserZone: string, edgeZone: string | null, edgeCountry: string | null): GeoResult {
  const browserCountry = timezoneCountry(browserZone);
  const normalizedEdge = edgeCountry?.toUpperCase() ?? "";
  const edgeCountryKnown = Boolean(normalizedEdge && normalizedEdge !== "XX" && normalizedEdge !== "T1");

  if (!edgeZone && !edgeCountryKnown) {
    return { score: 60, note: "边缘没有时区或国家，跳过时区对照。", conflict: false };
  }
  if (browserCountry && edgeCountryKnown && browserCountry !== normalizedEdge) {
    return {
      score: 28,
      note: `浏览器时区像 ${countryLabel(browserCountry)}，边缘国家是 ${countryLabel(normalizedEdge)}。`,
      conflict: true,
    };
  }
  if (edgeZone && browserZone === edgeZone) {
    return { score: 94, note: "浏览器时区与边缘时区相同。", conflict: false };
  }
  const edgeTzCountry = timezoneCountry(edgeZone);
  if (browserCountry && edgeTzCountry && browserCountry === edgeTzCountry) {
    return { score: 86, note: "时区名称不同，但都落在同一国家/地区。", conflict: false };
  }
  if (browserCountry && edgeCountryKnown && browserCountry === normalizedEdge) {
    return { score: 88, note: "浏览器时区与边缘国家一致。", conflict: false };
  }
  if (edgeZone) {
    const browserRegion = browserZone.split("/")[0] ?? "";
    const edgeRegion = edgeZone.split("/")[0] ?? "";
    if (browserRegion && edgeRegion && browserRegion !== edgeRegion) {
      return { score: 36, note: `浏览器时区 ${browserZone} 与边缘时区 ${edgeZone} 不在同一个大区。`, conflict: true };
    }
    return { score: 68, note: `时区分别是 ${browserZone} 和 ${edgeZone}，没有足够资料判定是否跨国。`, conflict: false };
  }
  return { score: 70, note: "边缘没有时区字段，国家也不足以和浏览器时区对照。", conflict: false };
}

function uniquePlatforms(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

type ClientResult = { score: number; mismatches: Mismatch[]; note: string };

function compareClient(input: ScoreInput): ClientResult {
  const mismatches: Mismatch[] = [];
  let score = 100;
  const uaPlatform = platformFromUserAgent(input.claimed.userAgent);
  const chPlatform = normPlatform(input.claimed.chPlatform);
  const navPlatform = normPlatform(input.claimed.platform);
  const platforms = uniquePlatforms([uaPlatform, chPlatform, navPlatform]);
  if (platforms.length > 1) {
    score -= 40;
    mismatches.push({
      label: "系统平台",
      claimed: `UA ${uaPlatform || "—"} · Client Hints ${chPlatform || "—"} · platform ${navPlatform || "—"}`,
      observed: "三处声称应指向同一系统",
      detail: "User-Agent、Client Hints 和 navigator.platform 不一致。",
      severity: "warn",
    });
  }

  const uaMobile = /mobile|iphone|ipad|android/i.test(input.claimed.userAgent);
  if (input.claimed.chMobile !== null && input.claimed.chMobile !== uaMobile) {
    score -= 25;
    mismatches.push({
      label: "移动端标记",
      claimed: `Sec-CH-UA-Mobile ${input.claimed.chMobile ? "?1" : "?0"}`,
      observed: `User-Agent ${uaMobile ? "像移动端" : "不像移动端"}`,
      detail: "Client Hints 的移动端标记和 User-Agent 矛盾。",
      severity: "warn",
    });
  }

  const headerLang = primaryLanguage(input.claimed.acceptLanguage);
  const jsLang = primaryLanguage(input.claimed.languages[0]);
  if (headerLang && jsLang && headerLang !== jsLang) {
    score -= 20;
    mismatches.push({
      label: "语言",
      claimed: input.claimed.acceptLanguage ?? "—",
      observed: input.claimed.languages.join(", ") || "—",
      detail: "Accept-Language 的主语言和 navigator.languages 不一致。",
      severity: "warn",
    });
  }

  const renderer = (input.observed.webglRenderer ?? "").toLowerCase();
  const appleGpu = renderer.includes("apple") || renderer.includes("metal");
  const desktopClaim = platforms[0] === "windows" || platforms[0] === "linux";
  if (appleGpu && desktopClaim && platforms.length === 1) {
    score -= 25;
    mismatches.push({
      label: "显卡与系统",
      claimed: platforms[0] ?? "—",
      observed: input.observed.webglRenderer ?? "—",
      detail: "WebGL 渲染器像 Apple GPU，声称的系统却不是 macOS。",
      severity: "warn",
    });
  }

  if (input.observed.screenWidth <= 0 || input.observed.screenHeight <= 0) {
    score -= 30;
    mismatches.push({
      label: "屏幕",
      claimed: "正常屏幕尺寸",
      observed: `${input.observed.screenWidth}×${input.observed.screenHeight}`,
      detail: "屏幕宽或高为 0。",
      severity: "bad",
    });
  }

  score = Math.max(0, score);
  const note = mismatches.length === 0 ? "UA、Client Hints 和语言没有明显矛盾。" : mismatches.map((item) => item.detail).join("");
  return { score, mismatches, note };
}

type UdpResult = { score: number; note: string; leak: boolean; partial: boolean };

function compareUdp(ip: string | null, input: ScoreInput["observed"]): UdpResult {
  const globals = input.webrtcGlobalIps;
  if (input.webrtcError) return { score: 46, note: input.webrtcError, leak: false, partial: false };
  if (!ip) {
    if (globals.length > 0) {
      return { score: 52, note: `看到 UDP 公网 ${globals.join(", ")}，但没有边缘 IP 可对照。`, leak: false, partial: false };
    }
    return { score: 50, note: "没有边缘 IP，无法判断 UDP 是否泄漏。", leak: false, partial: false };
  }
  if (globals.length === 0) {
    if (input.webrtcCandidates > 0) {
      const mdns = input.webrtcMdns ? " 候选里有 mDNS。" : "";
      return { score: 76, note: `有 STUN 候选，但没有解析出公网 IP。未见公网泄漏。${mdns}`, leak: false, partial: false };
    }
    return { score: 50, note: "没有收到 WebRTC 候选，无法确认 UDP 出口。", leak: false, partial: false };
  }
  const extras = globals.filter((item) => item !== ip);
  if (globals.includes(ip) && extras.length === 0) {
    return { score: 96, note: "WebRTC 公网地址与 CF-Connecting-IP 相同。", leak: false, partial: false };
  }
  if (globals.includes(ip)) {
    return {
      score: 62,
      note: `出口 IP 在 WebRTC 候选里，同时还有其它公网地址 ${extras.join(", ")}。`,
      leak: false,
      partial: true,
    };
  }
  return { score: 26, note: `WebRTC 看到 ${globals.join(", ")}，边缘是 ${ip}。`, leak: true, partial: false };
}

function securityScore(input: ScoreInput, client: ClientResult, leak: boolean, geoConflict: boolean): { score: number; hits: string[] } {
  let score = 100;
  const hits: string[] = [];
  const ua = input.claimed.userAgent.toLowerCase();
  if (input.observed.webdriver) {
    score -= 70;
    hits.push("navigator.webdriver 为 true");
  }
  if (/headless|phantomjs|selenium|puppeteer|playwright/.test(ua)) {
    score -= 70;
    hits.push("User-Agent 含有无头或自动化字样");
  }
  const renderer = (input.observed.webglRenderer ?? "").toLowerCase();
  if (renderer.includes("swiftshader") || renderer.includes("llvmpipe")) {
    score -= 24;
    hits.push("WebGL 像软件渲染");
  }
  if (input.observed.outerWidth === 0 && input.observed.outerHeight === 0) {
    score -= 16;
    hits.push("窗口外部尺寸为 0");
  }
  if (input.claimed.languages.length === 0) {
    score -= 10;
    hits.push("navigator.languages 为空");
  }
  for (const mismatch of client.mismatches) {
    if (mismatch.label === "系统平台") {
      score -= 22;
      hits.push("UA 与 Client Hints 或平台不一致");
    } else if (mismatch.label === "语言") {
      score -= 8;
      hits.push("语言声称互相矛盾");
    } else if (mismatch.label === "移动端标记") {
      score -= 14;
      hits.push("移动端标记和 UA 矛盾");
    } else if (mismatch.label === "显卡与系统") {
      score -= 14;
      hits.push("显卡和声称的系统不一致");
    } else if (mismatch.label === "屏幕") {
      score -= 20;
      hits.push("屏幕尺寸异常");
    }
  }
  if (leak) {
    score -= 28;
    hits.push("WebRTC 公网地址和出口 IP 不一致");
  }
  if (geoConflict) {
    score -= 20;
    hits.push("时区与边缘位置不一致");
  }
  return { score: clamp(score), hits };
}

function clamp(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function goodBand(score: number, highAt: number, midAt: number, high: string, mid: string, low: string): { tone: Tone; badge: string } {
  if (score >= highAt) return { tone: "ok", badge: high };
  if (score >= midAt) return { tone: "warn", badge: mid };
  return { tone: "bad", badge: low };
}

function udpBadge(score: number): { tone: Tone; badge: string } {
  if (score >= 80) return { tone: "ok", badge: "一致" };
  if (score >= 70) return { tone: "ok", badge: "未泄漏" };
  if (score >= 60) return { tone: "warn", badge: "部分" };
  if (score >= 45) return { tone: "warn", badge: "不足" };
  return { tone: "bad", badge: "不一致" };
}

function trustBand(score: number): Omit<ScoreResult["trust"], "headline" | "detail"> {
  if (score >= 80) return { score, tone: "ok", band: "较高" };
  if (score >= 60) return { score, tone: "warn", band: "中等" };
  if (score >= 40) return { score, tone: "bad", band: "偏低" };
  return { score, tone: "bad", band: "较低" };
}

function purityBand(score: number): ScoreResult["purity"] {
  if (score >= 80) return { score, tone: "ok", band: "高" };
  if (score >= 45) return { score, tone: "warn", band: "中" };
  return { score, tone: "bad", band: "低" };
}

function riskBand(score: number): { tone: Tone; band: "低" | "中" | "高" } {
  if (score >= 60) return { tone: "bad", band: "高" };
  if (score >= 30) return { tone: "warn", band: "中" };
  return { tone: "ok", band: "低" };
}

function spamAdjust(abuse: AbuseRecord): { trust: number; risk: number } {
  if (abuse.source !== "stopforumspam" || abuse.appears !== true) return { trust: 0, risk: 0 };
  if ((abuse.frequency ?? 0) >= 3) return { trust: 12, risk: 32 };
  return { trust: 6, risk: 16 };
}

function attributeNote(input: {
  kind: AttributeKind;
  organization: string | null;
  tor: boolean;
  vpn: boolean;
  nativePath: boolean;
  leak: boolean;
  partial: boolean;
  geoConflict: boolean;
}): string {
  const org = input.organization?.trim() || "未提供";
  if (input.tor) return "边缘把这个出口标成 Tor，按匿名出口而不是住宅宽带计。";
  if (input.vpn) return `组织名像 VPN（${org}）。`;
  if (input.kind === "datacenter") return `组织名更像云厂商或机房（${org}）。`;
  if (input.kind === "residential" && input.nativePath) {
    return `组织名更像住宅宽带（${org}），时区和 UDP 与出口一致，所以同时标成原生。`;
  }
  if (input.kind === "residential") {
    const why = [
      input.leak ? "UDP 与出口不一致" : "",
      input.partial ? "UDP 还有其它公网地址" : "",
      input.geoConflict ? "时区与边缘不一致" : "",
    ].filter(Boolean).join("，");
    return `组织名更像住宅宽带（${org}）。${why}，所以不标原生。`;
  }
  if (input.kind === "native") {
    return `组织名「${org}」不在机房词表里，暂记为原生 ISP。没有 RIR 归属库，不能确认是不是广播地址。`;
  }
  return "没有 ASN 组织名，分不出住宅、机房或原生。";
}

function summarize(input: {
  hasEdge: boolean;
  tor: boolean;
  vpn: boolean;
  kind: AttributeKind;
  nativePath: boolean;
  leak: boolean;
  geoConflict: boolean;
  automated: boolean;
  fingerprint: number;
  security: number;
}): string {
  if (!input.hasEdge) return "没有边缘出口数据，信任分已压低。";
  if (input.tor) return "Tor 出口，纯净度和信任分很低。";
  if (input.automated) return "有自动化迹象，安全性把信任分压低。";
  if (input.vpn) return "组织名像 VPN，纯净度和信任分下降。";
  if (input.kind === "datacenter") return "组织名像机房或云厂商，纯净度偏低。";
  if (input.leak) return "UDP/WebRTC 公网地址和出口 IP 不一致。";
  if (input.geoConflict) return "浏览器时区和边缘位置不一致。";
  if (input.kind === "residential" && input.nativePath && input.fingerprint >= 85 && input.security >= 85) {
    return "像住宅原生出口，主要信号对齐。";
  }
  if (input.kind === "residential") return "像住宅宽带，但有信号没有完全对齐。";
  if (input.kind === "native") return "不像机房，暂记为原生 ISP。";
  return "没有 ASN 组织名，纯净度保守估计。";
}

function looksLikeProxy(organization: string | null): boolean {
  const text = (organization ?? "").toLowerCase();
  return PROXY_HINTS.some((hint) => text.includes(hint));
}

function looksAutomated(input: ScoreInput): boolean {
  const ua = input.claimed.userAgent.toLowerCase();
  return input.observed.webdriver || /headless|phantomjs|selenium|puppeteer|playwright|crawler|spider|\bbot\b/.test(ua);
}

function trustPhrase(score: number): { headline: ScoreResult["trust"]["headline"]; detail: string } {
  if (score >= 80) return { headline: "良好", detail: "主要信号整齐" };
  if (score >= 60) return { headline: "良好", detail: "该 IP 存在轻微风险" };
  return score >= 40 ? { headline: "一般", detail: "该 IP 风险偏高" } : { headline: "高危", detail: "该 IP 风险较高" };
}

function sceneFor(trustScore: number, cap: number): { score: number; advice: SceneAdvice } {
  const rounded = Math.round(trustScore / 20);
  const score = Math.max(1, Math.min(5, Math.min(cap, rounded || 1)));
  const advice: SceneAdvice = score >= 4 ? "推荐" : score <= 2 ? "不推荐" : "一般";
  return { score, advice };
}

function languageHint(country: string, languages: string[]): { state: "一致" | "不一致" | "无法对照"; note: string } {
  const expected = COUNTRY_LANG[country];
  const actual = primaryLanguage(languages[0]);
  if (!country || country === "XX" || country === "T1" || !expected) {
    return { state: "无法对照", note: "没有这个边缘国家的常用语言对照。" };
  }
  if (!actual) return { state: "无法对照", note: "浏览器没有给出语言。" };
  const expectedName = LANG_ZH[expected] ?? expected;
  if (actual === expected) {
    return { state: "一致", note: `浏览器主语言和${countryLabel(country)}常见的${expectedName}一致。` };
  }
  return { state: "不一致", note: `浏览器主语言是 ${actual}，${countryLabel(country)}更常见的是${expectedName}。` };
}

export function scoreVisit(input: ScoreInput): ScoreResult {
  const organization = input.edge?.asOrganization ?? null;
  const country = input.edge?.country?.toUpperCase() ?? "";
  const orgClass = classifyOrganization(organization);
  const tor = isTor(country, organization);
  const vpn = orgClass.vpn;
  const hasEdge = Boolean(input.edge && (input.edge.connectingIp || input.edge.country || input.edge.asOrganization));
  const hasOrgName = Boolean(organization?.trim());

  let kind: AttributeKind = "unknown";
  if (tor || vpn || orgClass.kind === "hosting") kind = "datacenter";
  else if (orgClass.kind === "residential") kind = "residential";
  else if (hasOrgName) kind = "native";

  const geo = compareGeo(input.claimed.timezone, input.edge?.timezone ?? null, input.edge?.country ?? null);
  const client = compareClient(input);
  const udp = compareUdp(input.edge?.connectingIp ?? null, input.observed);
  const security = securityScore(input, client, udp.leak, geo.conflict);

  let fingerprint = client.score;
  if (!input.observed.canvasHash) fingerprint -= 6;
  if (!input.observed.webglRenderer) fingerprint -= 6;
  if (!input.observed.audioHash) fingerprint -= 4;
  fingerprint = clamp(fingerprint);

  let purity = kind === "residential" ? 92 : kind === "native" ? 74 : kind === "datacenter" ? 24 : 48;
  if (vpn) purity = 12;
  if (tor) purity = 8;
  if (udp.leak) purity -= 14;
  if (geo.conflict) purity -= 10;
  purity = clamp(purity);

  const nativePath = kind === "residential" && hasEdge && !udp.leak && !udp.partial && !geo.conflict && !tor && !vpn;
  const abuse = input.abuse ?? EMPTY_ABUSE;
  const spam = spamAdjust(abuse);
  const automated = looksAutomated(input) || security.hits.some((hit) => hit.includes("webdriver") || hit.includes("无头") || hit.includes("自动化字样"));
  const proxy = looksLikeProxy(organization);

  const weighted =
    purity * TRUST_WEIGHT.purity +
    udp.score * TRUST_WEIGHT.udp +
    geo.score * TRUST_WEIGHT.timezone +
    fingerprint * TRUST_WEIGHT.fingerprint +
    security.score * TRUST_WEIGHT.security;

  let penalty = spam.trust;
  if (tor) penalty += 34;
  else if (vpn) penalty += 18;
  else if (kind === "datacenter") penalty += 8;
  if (kind === "unknown") penalty += 10;
  if (udp.leak) penalty += 10;
  if (geo.conflict) penalty += 8;
  if (client.mismatches.some((item) => item.label === "系统平台")) penalty += 12;

  let trust = weighted - penalty;
  if (security.score < 55) trust = Math.min(trust, security.score);
  if (!hasEdge) trust = Math.min(trust, 59);
  const trustScore = clamp(trust);

  let riskScore = 0;
  if (tor) riskScore += 62;
  else if (vpn) riskScore += 44;
  else if (kind === "datacenter") riskScore += 32;
  riskScore += 100 - security.score;
  if (udp.leak) riskScore += 8;
  if (geo.conflict) riskScore += 12;
  riskScore += spam.risk;
  riskScore = clamp(riskScore);

  const udpTone = udpBadge(udp.score);
  const tzTone = goodBand(geo.score, 80, 55, "一致", "大致", "偏差");
  const fpTone = goodBand(fingerprint, 85, 55, "整齐", "有差异", "异常");
  const secTone = goodBand(security.score, 80, 55, "干净", "留意", "风险");
  const hashNote = [
    input.observed.canvasHash ? "有 canvas" : "无 canvas",
    input.observed.webglRenderer ? "有 WebGL" : "无 WebGL",
    input.observed.audioHash ? "有 audio" : "无 audio",
  ].join("，");
  const securityNote = security.hits.length ? `${security.hits.join("；")}。` : "没有 webdriver、无头浏览器或明显伪装矛盾。";

  const signals: SignalCard[] = [
    {
      id: "dns",
      label: "DNS",
      score: null,
      tone: "neutral",
      badge: "不可得",
      note: "浏览器不暴露系统解析器或 DoH，边缘 request.cf 也没有解析器字段。不计入信任分。",
    },
    { id: "udp", label: "UDP", score: clamp(udp.score), ...udpTone, note: udp.note },
    { id: "timezone", label: "时区", score: clamp(geo.score), ...tzTone, note: geo.note },
    {
      id: "fingerprint",
      label: "指纹",
      score: fingerprint,
      ...fpTone,
      note: `${client.note}${hashNote}。`,
    },
    { id: "security", label: "安全性", score: security.score, ...secTone, note: securityNote },
  ];

  const mismatches = [...client.mismatches];
  if (geo.conflict) {
    mismatches.unshift({
      label: "时区",
      claimed: input.claimed.timezone || "—",
      observed: input.edge?.timezone || input.edge?.country || "—",
      detail: geo.note,
      severity: "warn",
    });
  }
  if (udp.leak && input.edge?.connectingIp) {
    mismatches.push({
      label: "公网地址",
      claimed: "WebRTC 候选",
      observed: `边缘 ${input.edge.connectingIp}`,
      detail: udp.note,
      severity: "warn",
    });
  }

  const historyText = historyCopy(abuse);
  const region = REGION_NOTE.has(country)
    ? `公开资料里，${countryLabel(country)}经常不在 Claude 的服务范围。这不计入纯净度或信任分。`
    : null;
  const note = attributeNote({
    kind,
    organization,
    tor,
    vpn,
    nativePath,
    leak: udp.leak,
    partial: udp.partial,
    geoConflict: geo.conflict,
  });
  const notes = [
    "信任分按纯净度 30%、UDP 16%、时区 18%、指纹 14%、安全性 22% 加权。DNS 缺测不计入。机房、VPN、泄漏和自动化会再扣分。",
    note,
    ...signals.map((item) => `${item.label}：${item.note}`),
    "colo 是 Cloudflare 接入机房，不代表用户在机房网络。",
  ];
  if (region) notes.push(region);

  const risk = hasEdge
    ? { score: riskScore, ...riskBand(riskScore) }
    : { score: null, tone: "neutral" as const, band: "未知" as const };
  const phrase = trustPhrase(trustScore);
  const aiCap = tor ? 1 : automated || vpn || kind === "datacenter" || REGION_NOTE.has(country) ? 2 : 5;
  const socialCap = tor || vpn || kind === "datacenter" ? 1 : automated || REGION_NOTE.has(country) ? 2 : 5;
  const language = languageHint(country, input.claimed.languages);
  const abuseState: CheckState =
    abuse.source === "stopforumspam" && abuse.appears === true
      ? "有公开记录"
      : abuse.source === "stopforumspam" && abuse.appears === false
        ? "无记录"
        : "无法查询";

  return {
    trust: { ...trustBand(trustScore), ...phrase },
    purity: purityBand(purity),
    risk,
    regionSupport: !hasEdge || !country || country === "XX"
      ? { state: "无法判断", note: "没有可靠的边缘国家，不能对照公开资料里的 Claude 服务范围。" }
      : REGION_NOTE.has(country)
        ? { state: "受限", note: `公开资料里，${countryLabel(country)}经常不在 Claude 的服务范围。这是静态启发式，不是官方名单。` }
        : { state: "正常", note: `${countryLabel(country)}不在这份常见受限清单里。清单会过时，也不是 Anthropic 的官方范围。` },
    securityChecks: {
      vpn: vpn
        ? { state: "疑似", note: "组织名里有 VPN 关键词。" }
        : { state: "未发现", note: "组织名不在内置 VPN 词表里。没有单独的 VPN 情报库。" },
      proxy: proxy
        ? { state: "疑似", note: "组织名里有代理服务关键词。" }
        : { state: "未发现", note: "组织名不在内置代理词表里。机房地址不会自动算作代理。" },
      tor: tor
        ? { state: "疑似", note: "边缘国家或组织名像 Tor 出口。" }
        : { state: "未发现", note: "没有看到 Tor 出口标记。" },
      crawler: automated
        ? { state: "疑似", note: "浏览器带有 webdriver、无头或爬虫字样。" }
        : { state: "未发现", note: "没有看到 webdriver、无头浏览器或爬虫字样。" },
      abuse:
        abuseState === "有公开记录"
          ? { state: abuseState, note: historyText.note }
          : abuseState === "无记录"
            ? { state: abuseState, note: "StopForumSpam 未见此 IP。这不是完整滥用库。" }
            : { state: abuseState, note: "没有查到公开滥用库，不编造记录。" },
    },
    scenes: {
      ai: sceneFor(trustScore, aiCap),
      social: sceneFor(trustScore, socialCap),
      tiktok: sceneFor(trustScore, socialCap),
    },
    traffic: automated
      ? { human: 15, machine: 85, badge: "机器偏多", source: "估算" }
      : (input.observed.webglRenderer ?? "").toLowerCase().includes("swiftshader") ||
          (input.observed.webglRenderer ?? "").toLowerCase().includes("llvmpipe")
        ? { human: 60, machine: 40, badge: "机器偏多", source: "估算" }
        : { human: 90, machine: 10, badge: "人类为主", source: "估算" },
    deviceHints: {
      timezone: !hasEdge || (!input.edge?.timezone && !input.edge?.country) ? "无法对照" : geo.conflict ? "不一致" : "一致",
      language: language.state,
      languageNote: language.note,
    },
    attribute: {
      kind,
      label: ATTR_LABEL[kind],
      native: kind === "native" || nativePath,
      tag: tor ? "Tor" : vpn ? "VPN" : nativePath ? "原生" : null,
      tone: kind === "residential" ? "ok" : kind === "datacenter" ? "bad" : "neutral",
      note,
    },
    signals,
    history: {
      label: historyText.label,
      note: historyText.note,
      source: abuse.source,
      appears: abuse.appears,
      frequency: abuse.frequency,
      lastSeen: abuse.lastSeen,
    },
    exit: {
      ip: input.edge?.connectingIp ?? null,
      countryLabel: countryLabel(input.edge?.country ?? null),
      city: input.edge?.city ?? null,
      asOrganization: organization,
      asn: input.edge?.asn ?? null,
      colo: input.edge?.colo ?? null,
      country: country || null,
      region: input.edge?.region ?? null,
    },
    summary: summarize({
      hasEdge,
      tor,
      vpn,
      kind,
      nativePath,
      leak: udp.leak,
      geoConflict: geo.conflict,
      automated,
      fingerprint,
      security: security.score,
    }),
    notes,
    mismatches,
  };
}

function asText(value: unknown): string | null {
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "string" && value.trim()) return value.trim();
  return null;
}

export function edgeSnapshotFromApi(payload: {
  connectingIp?: string | null;
  ipCountry?: string | null;
  cf?: Record<string, unknown>;
  headers?: Record<string, string>;
} | null): EdgeSnapshot | null {
  if (!payload) return null;
  const cf = payload.cf ?? {};
  const country = asText(cf.country) ?? asText(payload.ipCountry);
  return {
    connectingIp: asText(payload.connectingIp) ?? headerValue(payload.headers ?? {}, "cf-connecting-ip"),
    country,
    timezone: asText(cf.timezone),
    asOrganization: asText(cf.asOrganization),
    asn: asText(cf.asn),
    colo: asText(cf.colo),
    city: asText(cf.city),
    region: asText(cf.region),
  };
}

export function claimedFromSignals(input: {
  userAgent: string;
  platform: string;
  languages: string[];
  timezone: string;
  headers: Record<string, string>;
  chPlatform: string | null;
  chMobile: boolean | null;
}): ScoreInput["claimed"] {
  return {
    userAgent: input.userAgent,
    chPlatform: input.chPlatform ?? unquote(headerValue(input.headers, "sec-ch-ua-platform")),
    chMobile: input.chMobile ?? parseClientHintMobile(headerValue(input.headers, "sec-ch-ua-mobile")),
    acceptLanguage: headerValue(input.headers, "accept-language"),
    languages: input.languages,
    timezone: input.timezone,
    platform: input.platform,
  };
}

/** Browser timezone against the edge timezone and country. Missing data stays 无法对照. */
export function timezoneAlignment(
  browserZone: string,
  edgeZone: string | null,
  edgeCountry: string | null,
): "一致" | "不一致" | "无法对照" {
  if (!browserZone) return "无法对照";
  const country = edgeCountry?.toUpperCase() ?? "";
  const knownCountry = Boolean(country && country !== "XX" && country !== "T1");
  if (!edgeZone && !knownCountry) return "无法对照";
  return compareGeo(browserZone, edgeZone, edgeCountry).conflict ? "不一致" : "一致";
}

export function display(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}
