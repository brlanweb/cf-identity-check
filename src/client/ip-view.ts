import type { BrowserReport } from "./collect.ts";
import type { IceKind } from "../shared/ip.ts";
import type { IpModel, PlaceView, RiskRow } from "../shared/model.ts";
import { SOURCE_LABEL, placeLine } from "../shared/sources.ts";
import { countryLabel } from "../shared/score.ts";

const KIND_LABEL: Record<IceKind, string> = {
  public: "公网",
  private: "私网",
  cgnat: "CGNAT",
  mdns: "mDNS",
  relay: "中继",
  unknown: "未知",
};

type LeafletMap = { remove: () => void; invalidateSize: () => void; setView: (center: [number, number], zoom: number) => LeafletMap };
type LeafletApi = {
  map: (el: HTMLElement, opts: object) => LeafletMap;
  tileLayer: (url: string, opts: object) => { addTo: (map: LeafletMap) => void };
  circleMarker: (latlng: [number, number], opts: object) => { addTo: (map: LeafletMap) => void };
};

let activeMap: LeafletMap | null = null;
let refreshMap: (() => void) | null = null;

export function clearExitMap(): void {
  try {
    activeMap?.remove();
  } catch {
    /* The container may already be gone. */
  }
  activeMap = null;
  refreshMap = null;
}

export function refreshExitMap(): void {
  refreshMap?.();
}

export function showIpLoading(): void {
  clearExitMap();
  const panel = document.querySelector("#ip-panel");
  if (!panel) return;
  panel.setAttribute("aria-busy", "true");
  panel.innerHTML = `<div class="stack skeleton" aria-hidden="true">
    <div class="skel skel-hero"></div>
    <div class="skel-grid two"><div class="skel"></div><div class="skel"></div></div>
    <div class="skel-grid two"><div class="skel"></div><div class="skel"></div></div>
  </div>`;
}

export function renderIpPage(model: IpModel, browser: BrowserReport): void {
  clearExitMap();
  const panel = document.querySelector("#ip-panel");
  if (!panel) return;
  panel.removeAttribute("aria-busy");
  const score = model.purity.score;
  const held = model.purity.lines.some((line) => line.points === null);
  panel.innerHTML = `<div class="stack">
    <section class="hero">
      <div class="hero-main">
        <h2>My IP</h2>
        <div class="myip-line">
          <p class="myip-addr mono">${escapeHtml(model.headlineIp ?? model.headlineSource)}</p>
          <span class="badge tone-${model.stackLabel === "无法检测" ? "neutral" : "ok"}">${escapeHtml(model.stackLabel)}</span>
        </div>
        <p class="note">${escapeHtml(model.headlineSource)}。${escapeHtml(model.stackNote)}</p>
        <ul class="echo-list">
          <li><span>边缘 CF-Connecting-IP</span><b class="mono">${escapeHtml(model.edgeIp ?? "没有")}</b></li>
          ${model.echoes.map((echo) => `<li><span>${echo.family === "v4" ? "IPv4" : "IPv6"} · ${escapeHtml(echo.name)}</span><b class="mono ${echo.ip ? "" : "is-unknown"}">${escapeHtml(echo.ip ?? echo.error ?? "没有")}</b></li>`).join("")}
        </ul>
        ${model.routingBanner ? `<p class="banner">${escapeHtml(model.routingBanner)}</p>` : ""}
        ${model.lookupNote ? `<p class="note">${escapeHtml(model.lookupNote)}</p>` : ""}
        ${model.colo ? `<p class="note">Cloudflare 机房 ${escapeHtml(model.colo)} 是接入点，不是用户所在的机房。</p>` : ""}
      </div>
      <div class="hero-side tone-${model.purity.tone}">
        <h2>纯净度系数</h2>
        <p class="purity-score"><strong>${score === null ? "—" : `${score}%`}</strong><span>${escapeHtml(model.purity.label)}</span></p>
        <div class="purity-track" aria-hidden="true">${score === null ? "" : `<i style="left:${score}%"></i>`}</div>
        <div class="purity-ticks" aria-hidden="true">${[0, 15, 25, 40, 50, 70, 100].map((tick) => `<span style="left:${tick}%">${tick}</span>`).join("")}</div>
        <p class="note">越低越纯净。${held ? "有项目未计入，低分只代表已查到的信号。" : "下面列出每一项加分。"}</p>
      </div>
    </section>

    <section class="fact-grid">
      ${fact("IP", model.headlineIp ?? echoIps(model) ?? "无法查询", model.headlineSource)}
      ${fact("ASN", model.asnTitle, model.asnSource ? `编号来自 ${model.asnSource}` : "没有 ASN", model.asnNames.map((item) => `${item.value} · ${item.source}`).join(" / "))}
      ${fact("AS域名", model.domains[0]?.value ?? "无法查询", model.domains.map((item) => `${item.value} · ${item.source}`).join(" / ") || "PeeringDB 和 ipwho.is 都没有给出域名")}
      ${fact("IP范围", model.range?.value ?? "无法查询", model.range ? model.range.source : "RDAP 没有返回起止地址", model.prefix ? `BGP ${model.prefix.value} · ${model.prefix.source}` : "")}
      ${fact("人机流量比", radarValue(model), model.radar.note)}
      ${fact("反向 DNS", model.ptr.state === "有记录" ? model.ptr.value ?? "有记录" : model.ptr.state, "IPv4 通过 Cloudflare DNS 查询 PTR。")}
    </section>

    <section class="pair">
      <article class="block">
        <div class="card-head"><h2>IP 来源</h2><span class="badge tone-${model.origin.label === "原生IP" ? "ok" : model.origin.label === "广播IP" ? "warn" : "neutral"}">${escapeHtml(model.origin.label)}</span></div>
        <p class="prose">${escapeHtml(model.origin.note)}</p>
        ${model.registeredCountry ? `<p class="note">登记国 ${escapeHtml(countryLabel(model.registeredCountry))}，${escapeHtml(model.registeredCountrySource ?? "RDAP")}。</p>` : ""}
      </article>
      <article class="block">
        <div class="card-head"><h2>IP 属性</h2><span class="badge tone-${model.facility.label === "住宅IP" ? "ok" : model.facility.label === "机房IP" ? "bad" : model.facility.label === "不一致" ? "warn" : "neutral"}">${escapeHtml(model.facility.label)}</span></div>
        <p class="prose">${escapeHtml(model.facility.note)}</p>
      </article>
    </section>

    <section class="group" id="purity">
      ${groupLabel("纯净度明细", "Score")}
      <article class="block">
        <ul class="purity-lines">
          ${model.purity.lines.map((line) => `<li><span>${escapeHtml(line.label)}</span><b class="${line.points === null ? "is-unknown" : line.points > 0 ? "is-hot" : ""}">${line.points === null ? "未计入" : line.points > 0 ? `+${line.points}` : "0"}</b><small>${escapeHtml(line.detail)}</small></li>`).join("")}
        </ul>
        <details class="fold"><summary>计算公式</summary><p class="prose">${escapeHtml(model.purity.formula)}</p></details>
      </article>
    </section>

    <nav class="jumps" aria-label="检测项目">
      <a href="#geo">IP 定位</a>
      <a href="#risk">风险</a>
      <a href="#fingerprint">指纹</a>
      <a href="#map">出口地图</a>
      <a href="#vpn">VPN 泄露</a>
      <a href="#webrtc">WebRTC</a>
      <a href="#dns">DNS</a>
    </nav>

    <section class="group" id="geo">
      ${groupLabel("IP 定位信息", "Location")}
      <div class="loc-grid">
        ${model.places.map((place) => locationCard(place)).join("")}
      </div>
    </section>

    <section class="group" id="risk">
      ${groupLabel("IP 风险检测", "Risk")}
      <article class="block">
        <ul class="check-list">${model.risks.map((row) => riskItem(row)).join("")}</ul>
      </article>
    </section>

    <section class="group" id="fingerprint">
      ${groupLabel("指纹信息分析", "Fingerprint")}
      <article class="block">
        <div class="kv-grid cols-2">${fingerprint(model, browser)}</div>
      </article>
    </section>

    <section class="group" id="map">
      ${groupLabel("IP 出口地图", "Map")}
      <article class="block">
        ${model.map ? `<div id="exit-map" class="map-frame" role="img" aria-label="出口位置，来自 ${escapeHtml(model.map.source)}"></div><p class="note">${escapeHtml(model.map.note)} ${model.map.latitude.toFixed(4)}, ${model.map.longitude.toFixed(4)}</p>` : `<p class="prose">没有可用坐标，不放置地图针。</p>`}
      </article>
    </section>

    <section class="group" id="vpn">
      ${groupLabel("VPN 泄露检测", "VPN")}
      <article class="block">
        <div class="card-head"><h2>出口标记</h2><span class="badge tone-${model.vpn.tone}">${escapeHtml(model.vpn.mark)}</span></div>
        <p class="prose">${escapeHtml(model.vpn.note)}</p>
        <p class="note">${escapeHtml(model.routingBanner ?? "同族的边缘地址和浏览器回显没有不一致。")}</p>
        <p class="note">${escapeHtml(model.webrtc.detail)}</p>
      </article>
    </section>

    <section class="group" id="webrtc">
      ${groupLabel("WebRTC 检测", "WebRTC")}
      <article class="block">
        <div class="card-head"><h2>候选地址</h2><span class="badge tone-${model.webrtc.leak === "yes" ? "bad" : model.webrtc.leak === "no" ? "ok" : "neutral"}">${model.webrtc.leak === "yes" ? "公网不一致" : model.webrtc.leak === "no" ? "未发现公网不一致" : "无法判断"}</span></div>
        <p class="prose">${escapeHtml(model.webrtc.error ?? model.webrtc.detail)}</p>
        ${model.webrtc.rows.length ? `<ul class="check-list">${model.webrtc.rows.map((row) => `<li><span class="mono">${escapeHtml(row.ip)}</span><span class="badge tone-${row.kind === "public" ? "warn" : "neutral"}">${KIND_LABEL[row.kind]}</span></li>`).join("")}</ul>` : `<p class="note">没有解析出候选地址。</p>`}
        <p class="note">STUN：stun.cloudflare.com:3478、stun.l.google.com:19302、stun.chat.bilibili.com:3478、stun.miwifi.com:3478。中继地址不拿来和出口比较。</p>
      </article>
    </section>

    <section class="group" id="dns">
      ${groupLabel("DNS 泄露检测", "DNS")}
      <article class="block">
        <div class="card-head"><h2>解析器</h2><span class="badge tone-neutral">无法判断</span></div>
        <p class="prose">${escapeHtml(model.dnsNote)}</p>
      </article>
    </section>
  </div>`;
  if (model.map) {
    const frame = document.querySelector<HTMLElement>("#exit-map");
    if (frame) mountMap(frame, model.map.latitude, model.map.longitude);
  }
}

function echoIps(model: IpModel): string | null {
  const ips = model.echoes.map((echo) => echo.ip).filter((ip): ip is string => Boolean(ip));
  const unique = [...new Set(ips)];
  return unique.length ? unique.join(" / ") : null;
}

function fact(label: string, value: string, source: string, extra = ""): string {
  return `<article class="fact"><h3>${escapeHtml(label)}</h3><p>${escapeHtml(value)}</p>${source ? `<p class="src">${escapeHtml(source)}</p>` : ""}${extra ? `<p class="src">${escapeHtml(extra)}</p>` : ""}</article>`;
}

function locationCard(place: PlaceView): string {
  const tone = place.status === "已查询" ? "ok" : place.status === "未配置" ? "neutral" : "neutral";
  const agree = place.agreement === "一致" ? "与登记国一致" : place.agreement === "不同" ? "与登记国不同" : "";
  return `<article class="loc-card">
    <header><h3>${escapeHtml(SOURCE_LABEL[place.id])}</h3><span class="badge tone-${tone}">${escapeHtml(place.status)}</span></header>
    <p class="loc-place">${place.countryCode ? `<span class="flag" aria-hidden="true">${flag(place.countryCode)}</span>` : ""}${escapeHtml(place.status === "已查询" ? placeLine(place) : "—")}</p>
    ${place.ip ? `<p class="src mono">${escapeHtml(place.ip)}</p>` : ""}
    ${place.timezone ? `<p class="src">${escapeHtml(place.timezone)}</p>` : ""}
    ${agree ? `<p class="src">${agree}</p>` : ""}
    <p class="src">${escapeHtml(place.note)}</p>
  </article>`;
}

function riskItem(row: RiskRow): string {
  return `<li><span>${escapeHtml(row.label)}<small>${escapeHtml(row.source)} · ${escapeHtml(row.note)}</small></span><span class="badge tone-${row.tone}">${escapeHtml(row.value)}</span></li>`;
}

function fingerprint(model: IpModel, browser: BrowserReport): string {
  const renderer = browser.webgl?.unmaskedRenderer || browser.webgl?.renderer || "不可用";
  const items: { label: string; value: string; note?: string; badge?: string }[] = [
    { label: "时区", value: model.timezone.state, note: `浏览器 ${model.timezone.browser || "—"} ${browser.timezoneOffset}；边缘 ${model.timezone.edge || "—"}`, badge: model.timezone.state === "一致" ? "ok" : model.timezone.state === "不一致" ? "bad" : "neutral" },
    { label: "语言", value: browser.languages.join(", ") || "—", note: "navigator.languages，不拿来改纯净度" },
    { label: "系统 / 浏览器", value: osAndBrowser(browser.userAgent), note: browser.userAgentData?.platform ? `Client Hints ${browser.userAgentData.platform}` : browser.platform || "" },
    { label: "屏幕", value: `${browser.screen.width}×${browser.screen.height} · dpr ${browser.window.devicePixelRatio}` },
    { label: "硬件", value: `${browser.hardwareConcurrency ?? "—"} 线程 · ${browser.deviceMemory ?? "—"} GB · 触点 ${browser.maxTouchPoints}` },
    { label: "Cookie", value: browser.cookieEnabled ? "已启用" : "未启用", badge: browser.cookieEnabled ? "ok" : "neutral" },
    { label: "webdriver", value: browser.webdriver ? "true" : "false", badge: browser.webdriver ? "bad" : "ok" },
    { label: "WebGL", value: renderer },
    { label: "Canvas", value: short(browser.canvasHash), note: "浏览器内 SHA-256" },
    { label: "音频", value: short(browser.audioHash), note: "浏览器内 SHA-256" },
  ];
  return items
    .map((item) => {
      const value = item.badge ? `<span class="badge tone-${item.badge}">${escapeHtml(item.value)}</span>` : escapeHtml(item.value);
      return `<div class="kv"><dt>${escapeHtml(item.label)}</dt><dd>${value}${item.note ? `<small>${escapeHtml(item.note)}</small>` : ""}</dd></div>`;
    })
    .join("");
}

function radarValue(model: IpModel): string {
  if (model.radar.state === "已查询" && model.radar.human !== null && model.radar.bot !== null) {
    return `human ${model.radar.human}% · bot ${model.radar.bot}%`;
  }
  return model.radar.state;
}

function groupLabel(title: string, en: string): string {
  return `<header class="group-head"><h2>${escapeHtml(title)}<span>${escapeHtml(en)}</span></h2></header>`;
}

function osAndBrowser(userAgent: string): string {
  const ua = userAgent.toLowerCase();
  const os = ua.includes("windows") ? "Windows" : ua.includes("mac os") || ua.includes("macintosh") ? "macOS" : ua.includes("android") ? "Android" : ua.includes("iphone") || ua.includes("ipad") ? "iOS" : ua.includes("linux") ? "Linux" : "未知系统";
  const browser = ua.includes("edg/") ? "Edge" : ua.includes("firefox") ? "Firefox" : ua.includes("chrome") || ua.includes("chromium") ? "Chrome" : ua.includes("safari") ? "Safari" : "未知浏览器";
  return `${os} · ${browser}`;
}

function short(value: string | null): string {
  if (!value) return "—";
  return value.slice(0, 16);
}

function flag(code: string): string {
  if (!/^[A-Za-z]{2}$/.test(code)) return "";
  const points = [...code.toUpperCase()].map((char) => 0x1f1e6 + char.charCodeAt(0) - 65);
  return String.fromCodePoint(...points);
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

function mountMap(el: HTMLElement, latitude: number, longitude: number): void {
  const leaflet = (window as unknown as { L?: LeafletApi }).L;
  if (!leaflet) {
    el.textContent = "地图库没有加载。坐标写在下面。";
    return;
  }
  const view = leaflet.map(el, { zoomControl: true, scrollWheelZoom: false }).setView([latitude, longitude], 9);
  leaflet.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap",
    maxZoom: 19,
  }).addTo(view);
  leaflet.circleMarker([latitude, longitude], {
    radius: 8,
    color: "#e7edf6",
    weight: 2,
    fillColor: "#e2b56a",
    fillOpacity: 0.95,
  }).addTo(view);
  activeMap = view;
  refreshMap = () => view.invalidateSize();
  requestAnimationFrame(() => view.invalidateSize());
}
