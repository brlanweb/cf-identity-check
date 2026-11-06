import "./styles.css";
import { collectBrowser, type BrowserReport } from "./collect.ts";
import { sha256, shortHash } from "./hash.ts";
import { renderPage, type Field, type Reachability, type SessionMemo } from "./render.ts";
import type { AbuseRecord } from "../shared/history.ts";
import { isReputationLookupIp } from "../shared/history.ts";
import type { IpIntel } from "../shared/intel.ts";
import { headerValue } from "../shared/redact.ts";
import {
  claimedFromSignals,
  countryLabel,
  display,
  edgeSnapshotFromApi,
  scoreVisit,
} from "../shared/score.ts";

type EdgePayload = {
  connectingIp: string | null;
  ray: string | null;
  ipCountry: string | null;
  cf: Record<string, unknown>;
  headers: Record<string, string>;
  omittedHeaders: string[];
  history?: AbuseRecord;
  intel?: IpIntel;
  collectedAt: string;
  privacy: string;
};

const SESSION_KEY = "cf-identity-check-session";

type SessionRow = { ip: string | null; trust: number };

function isSessionRow(value: unknown): value is SessionRow {
  if (!value || typeof value !== "object") return false;
  const row = value as { ip?: unknown; trust?: unknown };
  return (row.ip === null || typeof row.ip === "string") && typeof row.trust === "number";
}

function recordSession(ip: string | null, trust: number): SessionMemo {
  const current: SessionRow = { ip, trust };
  try {
    const parsed: unknown = JSON.parse(sessionStorage.getItem(SESSION_KEY) || "[]");
    const rows = Array.isArray(parsed) ? parsed.filter(isSessionRow) : [];
    rows.push(current);
    const kept = rows.slice(-12);
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(kept));
    const ips = new Set(kept.map((row) => row.ip).filter((item): item is string => Boolean(item)));
    return { runs: kept.length, ipChanges: Math.max(0, ips.size - 1) };
  } catch {
    return { runs: 1, ipChanges: 0 };
  }
}

function abuseFrom(payload: EdgePayload | null): AbuseRecord {
  const history = payload?.history;
  if (!history || (history.source !== "none" && history.source !== "stopforumspam")) {
    return { source: "none", appears: null, frequency: null, lastSeen: null, attempted: false };
  }
  return {
    source: history.source,
    appears: typeof history.appears === "boolean" ? history.appears : null,
    frequency: typeof history.frequency === "number" ? history.frequency : null,
    lastSeen: typeof history.lastSeen === "string" ? history.lastSeen : null,
    attempted: Boolean(history.attempted),
  };
}

type EdgeResult = { payload: EdgePayload | null; error: string | null };

function text(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

async function probe(name: string, url: string): Promise<Reachability> {
  const started = performance.now();
  try {
    await fetch(url, { mode: "no-cors", cache: "no-store", signal: AbortSignal.timeout(5000) });
    return { name, url, ok: true, ms: Math.round(performance.now() - started) };
  } catch {
    return { name, url, ok: false, ms: Math.round(performance.now() - started) };
  }
}

async function udpHolder(ip: string): Promise<string | null> {
  try {
    const response = await fetch(`https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(2500),
    });
    if (!response.ok) return null;
    const body = (await response.json()) as { data?: { asns?: { holder?: string }[] } };
    const holder = body.data?.asns?.[0]?.holder;
    return holder?.trim() ? holder : null;
  } catch {
    return null;
  }
}

async function loadEdge(): Promise<EdgeResult> {
  try {
    const response = await fetch("/api/edge", { cache: "no-store" });
    if (!response.ok) {
      return { payload: null, error: `边缘接口返回 ${response.status}。` };
    }
    const payload = (await response.json()) as EdgePayload;
    return { payload, error: null };
  } catch {
    return { payload: null, error: "没有连上 /api/edge。" };
  }
}

function observedFields(edge: EdgePayload | null, browser: BrowserReport): Field[] {
  const cf = edge?.cf ?? {};
  const connection = browser.connection
    ? [`${browser.connection.effectiveType ?? "—"}`, browser.connection.downlink !== null ? `${browser.connection.downlink} Mb/s` : null, browser.connection.rtt !== null ? `rtt ${browser.connection.rtt} ms` : null, browser.connection.saveData ? "saveData" : null]
        .filter(Boolean)
        .join(" · ")
    : "浏览器没有提供 Network Information";
  const permissionText = Object.entries(browser.permissions)
    .map(([name, state]) => `${name}: ${state}`)
    .join(" · ");
  const storageText = Object.entries(browser.storage)
    .map(([name, ok]) => `${name}: ${ok ? "可用" : "不可用"}`)
    .join(" · ");
  const webrtc = browser.webrtc.error
    ? browser.webrtc.error
    : browser.webrtc.globalIps.length
      ? `公网 ${browser.webrtc.globalIps.join(", ")}`
      : browser.webrtc.ips.length
        ? `仅本地/保留地址 ${browser.webrtc.ips.join(", ")}`
        : browser.webrtc.candidates.length
          ? `${browser.webrtc.candidates.length} 条候选，没有可解析的 IP（常见于 mDNS）`
          : "没有收到候选";

  return [
    { section: "边缘", label: "连接 IP", value: display(edge?.connectingIp), source: "CF-Connecting-IP" },
    { section: "边缘", label: "国家/地区", value: countryLabel(text(cf.country) === "—" ? edge?.ipCountry ?? null : text(cf.country)), source: "request.cf.country" },
    { section: "边缘", label: "城市 / 地区", value: [text(cf.city), text(cf.region)].filter((item) => item !== "—").join(" · ") || "—", source: "request.cf" },
    { section: "边缘", label: "数据中心", value: text(cf.colo), source: "request.cf.colo" },
    { section: "边缘", label: "ASN", value: cf.asn === undefined ? "—" : `${text(cf.asn)} · ${text(cf.asOrganization)}`, source: "request.cf.asn / asOrganization" },
    { section: "边缘", label: "时区", value: text(cf.timezone), source: "由 IP 地理推断" },
    { section: "边缘", label: "协议 / TLS", value: [text(cf.httpProtocol), text(cf.tlsVersion), text(cf.tlsCipher)].join(" · "), source: "request.cf" },
    { section: "边缘", label: "往返时间", value: cf.clientTcpRtt !== undefined ? `${text(cf.clientTcpRtt)} ms TCP` : cf.clientQuicRtt !== undefined ? `${text(cf.clientQuicRtt)} ms QUIC` : "—", source: "clientTcpRtt / clientQuicRtt" },
    { section: "边缘", label: "坐标", value: cf.latitude !== undefined ? `${text(cf.latitude)}, ${text(cf.longitude)}` : "—", source: "request.cf" },
    { section: "边缘", label: "Ray", value: display(edge?.ray), source: "CF-Ray" },
    { section: "浏览器测量", label: "WebGL", value: browser.webgl ? `${browser.webgl.unmaskedRenderer || browser.webgl.renderer} · ${browser.webgl.unmaskedVendor || browser.webgl.vendor}` : "不可用", source: "WEBGL_debug_renderer_info" },
    { section: "浏览器测量", label: "Canvas 哈希", value: shortHash(browser.canvasHash), source: "SHA-256，完整值在原始 JSON" },
    { section: "浏览器测量", label: "音频哈希", value: shortHash(browser.audioHash), source: "SHA-256，完整值在原始 JSON" },
    { section: "浏览器测量", label: "WebRTC", value: webrtc, source: "stun.cloudflare.com / stun.l.google.com" },
    { section: "浏览器测量", label: "屏幕", value: `${browser.screen.width}×${browser.screen.height} · ${browser.screen.colorDepth} bit · dpr ${browser.window.devicePixelRatio}`, source: "screen / devicePixelRatio" },
    { section: "浏览器测量", label: "窗口", value: `inner ${browser.window.innerWidth}×${browser.window.innerHeight} · outer ${browser.window.outerWidth}×${browser.window.outerHeight}`, source: "window" },
    { section: "浏览器测量", label: "硬件", value: `${browser.hardwareConcurrency ?? "—"} 线程 · 内存 ${browser.deviceMemory ?? "—"} GB · 触点 ${browser.maxTouchPoints}`, source: "hardwareConcurrency / deviceMemory" },
    { section: "浏览器测量", label: "webdriver", value: browser.webdriver ? "true" : "false", source: "navigator.webdriver" },
    { section: "浏览器测量", label: "连接", value: connection, source: "navigator.connection" },
    { section: "浏览器测量", label: "权限", value: permissionText || "—", source: "Permissions API" },
    { section: "浏览器测量", label: "存储能力", value: storageText, source: "探测后立即删除临时键" },
  ];
}

function claimedFields(edge: EdgePayload | null, browser: BrowserReport): Field[] {
  const headers = edge?.headers ?? {};
  const hints = browser.userAgentData;
  return [
    { section: "请求头", label: "User-Agent", value: display(headerValue(headers, "user-agent") ?? browser.userAgent), source: headerValue(headers, "user-agent") ? "请求头" : "navigator.userAgent（请求头里没有）" },
    { section: "请求头", label: "Client Hints", value: [headerValue(headers, "sec-ch-ua"), headerValue(headers, "sec-ch-ua-mobile"), headerValue(headers, "sec-ch-ua-platform")].filter(Boolean).join(" · ") || "请求里没有 Sec-CH-UA", source: "Sec-CH-UA*" },
    { section: "请求头", label: "Accept-Language", value: display(headerValue(headers, "accept-language")), source: "Accept-Language" },
    { section: "请求头", label: "已省略的头", value: edge?.omittedHeaders.length ? edge.omittedHeaders.join(", ") : "这次没有出现 Cookie / Authorization", source: "只记录名字，不回传内容" },
    { section: "脚本可读", label: "时区", value: `${browser.timezone} · ${browser.timezoneOffset}`, source: "Intl.DateTimeFormat" },
    { section: "脚本可读", label: "语言", value: browser.languages.join(", ") || "—", source: `navigator.languages · locale ${browser.locale || "—"}` },
    { section: "脚本可读", label: "platform / vendor", value: `${browser.platform || "—"} · ${browser.vendor || "—"}`, source: "navigator.platform / vendor" },
    { section: "脚本可读", label: "userAgentData", value: hints ? [`platform ${hints.platform ?? "—"}`, `mobile ${hints.mobile}`, hints.brands, hints.architecture ? `arch ${hints.architecture}/${hints.bitness ?? "—"}` : null, hints.platformVersion ? `版本 ${hints.platformVersion}` : null, hints.model ? `型号 ${hints.model}` : null].filter(Boolean).join(" · ") : "浏览器没有 userAgentData", source: "navigator.userAgentData" },
    { section: "脚本可读", label: "完整版本列表", value: display(hints?.fullVersionList), source: "getHighEntropyValues" },
    { section: "脚本可读", label: "其他", value: [`DNT ${browser.doNotTrack ?? "—"}`, `GPC ${browser.globalPrivacyControl ?? "—"}`, `pdf ${browser.pdfViewerEnabled ?? "—"}`, `cookieEnabled ${browser.cookieEnabled}`].join(" · "), source: "navigator" },
  ];
}

let runId = 0;

async function run(): Promise<void> {
  const id = ++runId;
  const status = document.querySelector("#status");
  if (status) {
    status.textContent = "正在读取边缘与浏览器信号…";
    status.className = "is-loading";
  }
  const [edgeResult, browser, probes] = await Promise.all([
    loadEdge(),
    collectBrowser(),
    Promise.all([probe("claude.ai", "https://claude.ai/"), probe("anthropic.com", "https://www.anthropic.com/")]),
  ]);
  if (id !== runId) return;
  const headers = edgeResult.payload?.headers ?? {};
  const score = scoreVisit({
    edge: edgeSnapshotFromApi(edgeResult.payload),
    claimed: claimedFromSignals({
      userAgent: browser.userAgent,
      platform: browser.platform,
      languages: browser.languages,
      timezone: browser.timezone,
      headers,
      chPlatform: browser.userAgentData?.platform ?? null,
      chMobile: browser.userAgentData?.mobile ?? null,
    }),
    observed: {
      webdriver: browser.webdriver,
      webglRenderer: browser.webgl?.unmaskedRenderer ?? browser.webgl?.renderer ?? null,
      screenWidth: browser.screen.width,
      screenHeight: browser.screen.height,
      outerWidth: browser.window.outerWidth,
      outerHeight: browser.window.outerHeight,
      webrtcGlobalIps: browser.webrtc.globalIps,
      webrtcCandidates: browser.webrtc.candidates.length,
      webrtcError: browser.webrtc.error,
      webrtcMdns: browser.webrtc.mdns,
      canvasHash: browser.canvasHash,
      audioHash: browser.audioHash,
    },
    abuse: abuseFrom(edgeResult.payload),
  });
  const udpIp = browser.webrtc.globalIps.find((item) => item !== score.exit.ip && isReputationLookupIp(item)) ?? null;
  const holder = udpIp ? await udpHolder(udpIp) : null;
  const renderer = browser.webgl?.unmaskedRenderer ?? browser.webgl?.renderer ?? null;
  const webglHash = renderer ? await sha256(renderer) : null;
  if (id !== runId) return;
  const session = recordSession(score.exit.ip, score.trust.score);
  renderPage({
    status: edgeResult.error ? "边缘接口不可用，分数主要来自浏览器。" : "",
    score,
    session,
    intel: edgeResult.payload?.intel ?? null,
    probes,
    udpHolder: holder,
    device: {
      timezone: browser.timezone,
      timezoneOffset: browser.timezoneOffset,
      languages: browser.languages,
      userAgent: browser.userAgent,
      cookieEnabled: browser.cookieEnabled,
      webglRenderer: renderer,
      canvasHash: browser.canvasHash,
      webglHash,
    },
    observed: observedFields(edgeResult.payload, browser),
    claimed: claimedFields(edgeResult.payload, browser),
    raw: {
      edge: edgeResult.payload,
      edgeError: edgeResult.error,
      browser,
      score,
      session,
    },
  });
}

document.querySelector("#rerun")?.addEventListener("click", () => {
  void run();
});

void run();
