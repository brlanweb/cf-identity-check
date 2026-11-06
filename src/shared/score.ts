import { headerValue, unquote } from "./redact.ts";
import { evaluateServices, type ServiceGroup } from "./services.ts";

export type Outlook = "higher" | "mixed" | "lower";

export type EdgeSnapshot = {
  connectingIp: string | null;
  country: string | null;
  timezone: string | null;
  asOrganization: string | null;
  colo: string | null;
  city: string | null;
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
    hardwareConcurrency: number | null;
    maxTouchPoints: number;
    screenWidth: number;
    screenHeight: number;
    outerWidth: number;
    outerHeight: number;
    webrtcGlobalIps: string[];
  };
};

export type Reason = { tone: "ok" | "warn" | "bad"; text: string };

export type Mismatch = {
  label: string;
  claimed: string;
  observed: string;
  detail: string;
  severity: "info" | "warn" | "bad";
};

export type Axis = { id: string; label: string; score: number; note: string };

export type Glance = {
  id: "country" | "network" | "geo" | "client" | "automation";
  label: string;
  value: string;
  badge: string;
  tone: "ok" | "warn" | "bad" | "neutral";
};

export type RiskScore = {
  id: "spoof" | "fraud";
  label: "伪装度" | "欺诈分";
  score: number;
  tone: "ok" | "warn" | "bad";
  status: "低" | "中" | "高";
};

export type ScoreResult = {
  outlook: Outlook;
  headline: string;
  summary: string;
  reasons: Reason[];
  axes: Axis[];
  mismatches: Mismatch[];
  glances: Glance[];
  risks: RiskScore[];
  services: ServiceGroup[];
};

const RANK: Outlook[] = ["lower", "mixed", "higher"];

const HEADLINE: Record<Outlook, string> = {
  higher: "偏高",
  mixed: "中等",
  lower: "偏低",
};

const SUMMARY: Record<Outlook, string> = {
  higher: "四项信号比较整齐，清单里多数 AI 和流媒体的直接打开阻力相对较小。",
  mixed: "信号不完全同向。各项服务对地区和机房地址的态度不同，看下面的矩阵。",
  lower: "按地区、网络类型或客户端异常，清单里不少服务处于较高阻力。",
};

/**
 * Places where a broad set of foreign consumer services is widely reported as
 * unreachable. Per-service nuance lives in services.ts. Static hint only.
 */
const RESTRICTED: Record<string, string> = {
  CN: "边缘 IP 落在中国大陆。公开资料里，YouTube、Netflix、Google 以及 Claude、ChatGPT 等多数境外服务在这里通常不能直接使用。",
  IR: "边缘 IP 落在伊朗。YouTube 与多项 Google 服务经常无法直接访问，部分 AI 服务也不在开放地区。",
  TM: "边缘 IP 落在土库曼斯坦。YouTube 等境外网站在这里经常无法直接访问。",
  KP: "边缘 IP 落在朝鲜。对外网站访问通常受到严格限制。",
  ER: "边缘 IP 落在厄立特里亚。YouTube 等境外网站在这里经常无法直接访问。",
};

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
  "mullvad",
  "nordvpn",
  "expressvpn",
  "protonvpn",
  "proton ag",
  "surfshark",
  "private internet",
  "tzulo",
  "cogent",
  "hurricane electric",
  "zenlayer",
  "kaopu",
  "peg tech",
  "hostroyale",
  "datacamp limited",
  "24shells",
  "vpn",
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

export const COUNTRY_ZH: Record<string, string> = {
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

export function normPlatform(value: string | null | undefined): string {
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

export function platformFromUserAgent(userAgent: string): string {
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

export function classifyOrganization(organization: string | null): {
  kind: "residential" | "hosting" | "unknown";
  hit: string | null;
} {
  const text = (organization ?? "").toLowerCase();
  if (!text.trim()) return { kind: "unknown", hit: null };
  const strong = includesAny(text, STRONG_HOSTING);
  const residential = includesAny(text, RESIDENTIAL);
  const weak = includesAny(text, WEAK_HOSTING);
  if (strong) return { kind: "hosting", hit: strong };
  if (residential) return { kind: "residential", hit: residential };
  if (weak) return { kind: "hosting", hit: weak };
  return { kind: "unknown", hit: null };
}

function timezoneCountry(zone: string | null): string | null {
  if (!zone) return null;
  return TZ_COUNTRY[zone] ?? null;
}

function downgrade(level: Outlook): Outlook {
  const index = RANK.indexOf(level);
  return RANK[Math.max(0, index - 1)] ?? "lower";
}

type GeoResult = { score: number; note: string; conflict: boolean };

function compareGeo(browserZone: string, edgeZone: string | null): GeoResult {
  if (!edgeZone) {
    return { score: 60, note: "边缘没有时区，跳过地理对照。", conflict: false };
  }
  if (browserZone === edgeZone) {
    return { score: 94, note: "浏览器时区与边缘时区相同。", conflict: false };
  }
  const browserCountry = timezoneCountry(browserZone);
  const edgeCountry = timezoneCountry(edgeZone);
  if (browserCountry && edgeCountry && browserCountry === edgeCountry) {
    return { score: 84, note: "时区名称不同，但都落在同一国家/地区。", conflict: false };
  }
  if (browserCountry && edgeCountry && browserCountry !== edgeCountry) {
    return {
      score: 28,
      note: `浏览器时区像 ${countryLabel(browserCountry)}，边缘时区像 ${countryLabel(edgeCountry)}。`,
      conflict: true,
    };
  }
  const browserRegion = browserZone.split("/")[0] ?? "";
  const edgeRegion = edgeZone.split("/")[0] ?? "";
  if (browserRegion && edgeRegion && browserRegion !== edgeRegion) {
    return { score: 40, note: `浏览器时区 ${browserZone} 与边缘时区 ${edgeZone} 不在同一个大区。`, conflict: true };
  }
  return { score: 68, note: `时区分别是 ${browserZone} 和 ${edgeZone}，没有足够资料判定是否跨国。`, conflict: false };
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
  const note = mismatches.length === 0 ? "UA、Client Hints、语言和屏幕没有明显互相矛盾。" : mismatches.map((item) => item.detail).join("");
  return { score, mismatches, note };
}

type AutomationResult = { score: number; hits: string[] };

function automationRisk(input: ScoreInput): AutomationResult {
  let score = 0;
  const hits: string[] = [];
  const ua = input.claimed.userAgent.toLowerCase();
  if (input.observed.webdriver) {
    score += 70;
    hits.push("navigator.webdriver 为 true");
  }
  if (/headless|phantomjs|selenium|puppeteer|playwright/.test(ua)) {
    score += 70;
    hits.push("User-Agent 含有自动化或无头浏览器字样");
  }
  const renderer = (input.observed.webglRenderer ?? "").toLowerCase();
  if (renderer.includes("swiftshader") || renderer.includes("llvmpipe")) {
    score += 30;
    hits.push("WebGL 渲染器像软件模拟（SwiftShader / llvmpipe）");
  }
  if (input.observed.outerWidth === 0 && input.observed.outerHeight === 0) {
    score += 20;
    hits.push("窗口外部尺寸为 0");
  }
  if (input.claimed.languages.length === 0) {
    score += 15;
    hits.push("navigator.languages 为空");
  }
  return { score: Math.min(100, score), hits };
}

function networkAxis(kind: "residential" | "hosting" | "unknown", organization: string | null): Axis {
  if (kind === "residential") {
    return { id: "network", label: "住宅网络倾向", score: 86, note: `组织名更像住宅宽带（${organization || "未提供"}）。` };
  }
  if (kind === "hosting") {
    return { id: "network", label: "住宅网络倾向", score: 24, note: `组织名更像云厂商、托管或 VPN 出口（${organization || "未提供"}）。` };
  }
  return { id: "network", label: "住宅网络倾向", score: 52, note: organization ? `组织名「${organization}」不在内置的住宅/机房词表里。` : "没有 ASN 组织名。" };
}

export function scoreVisit(input: ScoreInput): ScoreResult {
  const reasons: Reason[] = [];
  const network = classifyOrganization(input.edge?.asOrganization ?? null);
  const geo = compareGeo(input.claimed.timezone, input.edge?.timezone ?? null);
  const client = compareClient(input);
  const automation = automationRisk(input);
  const country = input.edge?.country?.toUpperCase() ?? "";
  const hasEdge = Boolean(input.edge && (input.edge.connectingIp || input.edge.country || input.edge.asOrganization));

  let outlook: Outlook = "mixed";
  if (!hasEdge) {
    outlook = "mixed";
    reasons.push({ tone: "warn", text: "没有读到 Cloudflare 边缘地理信息。本地开发时 request.cf 经常是空的，部署到 Workers 后才会填上。" });
  } else if (country === "T1") {
    outlook = "lower";
    reasons.push({ tone: "bad", text: "Cloudflare 把这个地址标成 Tor（T1）。这类出口经常被平台直接拒绝。" });
  } else if (RESTRICTED[country]) {
    outlook = "lower";
    reasons.push({ tone: "bad", text: RESTRICTED[country] });
  } else if (network.kind === "hosting") {
    outlook = "mixed";
    reasons.push({
      tone: "warn",
      text: `ASN 组织名更像云厂商、托管或 VPN（${input.edge?.asOrganization}）。数据中心地址上，Netflix、Disney+、Claude、ChatGPT 经常拒绝，YouTube 一类则宽松一些。`,
    });
  } else if (network.kind === "residential") {
    outlook = "higher";
    reasons.push({
      tone: "ok",
      text: `ASN 组织名更像住宅宽带（${input.edge?.asOrganization}），边缘国家/地区是 ${countryLabel(country)}。`,
    });
  } else if (!country || country === "XX") {
    outlook = "mixed";
    reasons.push({ tone: "warn", text: "有连接地址，但没有可靠的国家/地区代码。" });
  } else {
    outlook = "higher";
    reasons.push({
      tone: "ok",
      text: `边缘国家/地区是 ${countryLabel(country)}，不在这份常见限制清单里，组织名也看不出机房或 VPN。`,
    });
  }

  if (hasEdge && network.kind === "hosting" && RESTRICTED[country]) {
    reasons.push({ tone: "warn", text: "这个地址同时落在常见限制地区，组织名也像机房或 VPN。" });
  }

  reasons.push({ tone: geo.conflict ? "warn" : "ok", text: geo.note });
  if (geo.conflict) outlook = downgrade(outlook);

  if (client.mismatches.length === 0) {
    reasons.push({ tone: "ok", text: client.note });
  } else {
    for (const mismatch of client.mismatches) {
      reasons.push({ tone: mismatch.severity === "bad" ? "bad" : "warn", text: mismatch.detail });
    }
    if (client.score < 55) outlook = downgrade(outlook);
  }

  if (automation.hits.length === 0) {
    reasons.push({ tone: "ok", text: "没有看到 webdriver、无头浏览器字样或软件渲染器。" });
  } else {
    reasons.push({ tone: "bad", text: `自动化迹象：${automation.hits.join("；")}。` });
    if (automation.score >= 45) outlook = downgrade(outlook);
  }

  const connectingIp = input.edge?.connectingIp ?? null;
  const webrtcIps = input.observed.webrtcGlobalIps;
  if (connectingIp && webrtcIps.length > 0 && !webrtcIps.includes(connectingIp)) {
    reasons.push({
      tone: "warn",
      text: "WebRTC 候选里的公网地址和 CF-Connecting-IP 不同。多宿主或代理时会出现这种情况。",
    });
    client.mismatches.push({
      label: "公网地址",
      claimed: "WebRTC 候选",
      observed: `边缘 ${connectingIp}`,
      detail: `WebRTC 看到 ${webrtcIps.join(", ")}，边缘看到 ${connectingIp}。`,
      severity: "warn",
    });
  }

  const axes: Axis[] = [
    networkAxis(network.kind, input.edge?.asOrganization ?? null),
    { id: "geo", label: "地理一致", score: geo.score, note: geo.note },
    { id: "client", label: "客户端一致", score: client.score, note: client.note },
    {
      id: "automation",
      label: "自动化风险",
      score: automation.score,
      note: automation.hits.length ? automation.hits.join("；") : "没有明显的自动化标记。",
    },
  ];

  const glances = buildGlances({
    hasEdge,
    country,
    network: network.kind,
    geoConflict: geo.conflict,
    edgeTimezone: input.edge?.timezone ?? null,
    clientScore: client.score,
    clientMismatchCount: client.mismatches.length,
    automationScore: automation.score,
  });

  const services = evaluateServices({
    hasEdge,
    country,
    countryName: countryLabel(country || null),
    network: network.kind,
    tor: country === "T1",
    geoConflict: geo.conflict,
    clientScore: client.score,
    automationScore: automation.score,
  });

  const risks = buildRisks({
    country,
    network: network.kind,
    geoConflict: geo.conflict,
    automationScore: automation.score,
    mismatches: client.mismatches,
  });

  return {
    outlook,
    headline: HEADLINE[outlook],
    summary: SUMMARY[outlook],
    reasons,
    axes,
    mismatches: client.mismatches,
    glances,
    risks,
    services,
  };
}

function riskBand(score: number): Pick<RiskScore, "tone" | "status"> {
  if (score >= 60) return { tone: "bad", status: "高" };
  if (score >= 30) return { tone: "warn", status: "中" };
  return { tone: "ok", status: "低" };
}

function buildRisks(input: {
  country: string;
  network: "residential" | "hosting" | "unknown";
  geoConflict: boolean;
  automationScore: number;
  mismatches: Mismatch[];
}): RiskScore[] {
  const labels = new Set(input.mismatches.map((item) => item.label));
  const hosting = input.network === "hosting";
  const tor = input.country === "T1";
  let spoof = 0;
  if (input.geoConflict) spoof += 36;
  if (labels.has("系统平台")) spoof += 24;
  if (labels.has("语言")) spoof += 14;
  if (labels.has("移动端标记")) spoof += 12;
  if (labels.has("显卡与系统")) spoof += 12;
  if (labels.has("屏幕")) spoof += 10;
  if (labels.has("公网地址")) spoof += 20;
  if (hosting) spoof += 34;
  if (tor) spoof += 46;
  if (input.automationScore >= 45) spoof += 16;
  else if (input.automationScore > 0) spoof += 8;

  let fraud = 0;
  if (tor) fraud += 64;
  if (input.automationScore >= 70) fraud += 62;
  else if (input.automationScore >= 30) fraud += 34;
  else if (input.automationScore > 0) fraud += 16;
  if (hosting) fraud += 18;
  if (input.geoConflict) fraud += 14;
  let client = 0;
  if (labels.has("系统平台")) client += 16;
  if (labels.has("语言")) client += 8;
  if (labels.has("移动端标记")) client += 8;
  if (labels.has("显卡与系统")) client += 8;
  if (labels.has("屏幕")) client += 12;
  fraud += Math.min(30, client);
  if (labels.has("公网地址")) fraud += 10;

  const spoofScore = Math.max(0, Math.min(100, spoof));
  const fraudScore = Math.max(0, Math.min(100, fraud));
  return [
    { id: "spoof", label: "伪装度", score: spoofScore, ...riskBand(spoofScore) },
    { id: "fraud", label: "欺诈分", score: fraudScore, ...riskBand(fraudScore) },
  ];
}

function buildGlances(input: {
  hasEdge: boolean;
  country: string;
  network: "residential" | "hosting" | "unknown";
  geoConflict: boolean;
  edgeTimezone: string | null;
  clientScore: number;
  clientMismatchCount: number;
  automationScore: number;
}): Glance[] {
  const countryGlance: Glance = !input.hasEdge
    ? { id: "country", label: "边缘地区", value: "未知", badge: "无边缘", tone: "neutral" }
    : input.country === "T1"
      ? { id: "country", label: "边缘地区", value: "Tor", badge: "高风险", tone: "bad" }
      : RESTRICTED[input.country]
        ? { id: "country", label: "边缘地区", value: countryLabel(input.country), badge: "受限", tone: "bad" }
        : !input.country || input.country === "XX"
          ? { id: "country", label: "边缘地区", value: "未知", badge: "无代码", tone: "neutral" }
          : { id: "country", label: "边缘地区", value: countryLabel(input.country), badge: "可见", tone: "ok" };

  const networkGlance: Glance =
    input.network === "residential"
      ? { id: "network", label: "网络类型", value: "住宅宽带", badge: "住宅", tone: "ok" }
      : input.network === "hosting"
        ? { id: "network", label: "网络类型", value: "机房或 VPN", badge: "机房", tone: "warn" }
        : { id: "network", label: "网络类型", value: "未能归类", badge: "未知", tone: "neutral" };

  const geoGlance: Glance = !input.edgeTimezone
    ? { id: "geo", label: "时区对照", value: "缺少边缘时区", badge: "跳过", tone: "neutral" }
    : input.geoConflict
      ? { id: "geo", label: "时区对照", value: "不一致", badge: "偏差", tone: "warn" }
      : { id: "geo", label: "时区对照", value: "一致", badge: "对齐", tone: "ok" };

  const clientGlance: Glance =
    input.clientMismatchCount === 0
      ? { id: "client", label: "客户端", value: "未见矛盾", badge: "整齐", tone: "ok" }
      : input.clientScore < 55
        ? { id: "client", label: "客户端", value: "多处矛盾", badge: "异常", tone: "bad" }
        : { id: "client", label: "客户端", value: "有差异", badge: "留意", tone: "warn" };

  const automationGlance: Glance =
    input.automationScore >= 45
      ? { id: "automation", label: "自动化", value: "有迹象", badge: "风险", tone: "bad" }
      : input.automationScore > 0
        ? { id: "automation", label: "自动化", value: "弱迹象", badge: "留意", tone: "warn" }
        : { id: "automation", label: "自动化", value: "未见迹象", badge: "干净", tone: "ok" };

  return [countryGlance, networkGlance, geoGlance, clientGlance, automationGlance];
}

export function edgeSnapshotFromApi(payload: {
  connectingIp?: string | null;
  ipCountry?: string | null;
  cf?: Record<string, unknown>;
  headers?: Record<string, string>;
} | null): EdgeSnapshot | null {
  if (!payload) return null;
  const cf = payload.cf ?? {};
  const text = (value: unknown): string | null => (typeof value === "string" && value.trim() ? value : null);
  const country = text(cf.country) ?? text(payload.ipCountry);
  return {
    connectingIp: payload.connectingIp ?? headerValue(payload.headers ?? {}, "cf-connecting-ip"),
    country,
    timezone: text(cf.timezone),
    asOrganization: text(cf.asOrganization),
    colo: text(cf.colo),
    city: text(cf.city),
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

export function display(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}
