import type { BrowserReport } from "./collect.ts";
import type { IceKind } from "../shared/ip.ts";
import { presentedPlaces, presentedRisks, showRadar, type IpModel, type PlaceView, type RiskRow } from "../shared/model.ts";
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

const TICKS = [0, 15, 25, 40, 50, 70, 100];

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
  panel.innerHTML = `<div class="sheet skeleton" aria-hidden="true">
    <div class="skel skel-mast"></div>
    <div class="skel skel-row"></div>
    <div class="skel skel-row"></div>
  </div>`;
}

export function renderIpPage(model: IpModel, browser: BrowserReport): void {
  clearExitMap();
  const panel = document.querySelector("#ip-panel");
  if (!panel) return;
  panel.removeAttribute("aria-busy");
  const places = presentedPlaces(model.places);
  const risks = presentedRisks(model.risks);
  panel.innerHTML = `<div class="sheet">
    ${mast(model)}
    ${compare(model)}
    ${identity(model)}
    ${verdicts(model)}
    ${purityBlock(model)}
    ${toc()}
    ${geo(places)}
    ${risk(risks)}
    ${fingerSection(model, browser)}
    ${mapSection(model)}
    ${vpnSection(model)}
    ${webrtcSection(model)}
    ${dnsSection(model)}
  </div>`;
  if (model.map) {
    const frame = document.querySelector<HTMLElement>("#exit-map");
    if (frame) mountMap(frame, model.map.latitude, model.map.longitude);
  }
}

function mast(model: IpModel): string {
  const score = model.purity.score;
  const held = model.purity.lines.some((line) => line.points === null);
  const address = model.headlineIp ?? model.headlineSource;
  const addressClass = model.headlineIp ? `ip-display mono${model.headlineIp.length > 18 ? " is-long" : ""}` : "ip-display is-plain";
  const stackTone = model.stackLabel === "无法检测" ? "neutral" : "ok";
  const colo = model.colo ? `<p class="quiet">Cloudflare 机房 ${escapeHtml(model.colo)} 是接入点，不是用户所在的机房。</p>` : "";
  return `<section class="mast tone-${model.purity.tone}">
    <div class="mast-main">
      <p class="eyebrow">当前出口</p>
      <p class="${addressClass}">${escapeHtml(address)}</p>
      <div class="mast-meta">
        <span class="badge tone-${stackTone}">${escapeHtml(model.stackLabel)}</span>
        <p>${escapeHtml(model.headlineSource)}。${escapeHtml(model.stackNote)}</p>
      </div>
      ${colo}
    </div>
    <aside class="purity" aria-label="纯净度系数">
      <p class="eyebrow">纯净度</p>
      ${score === null ? `<p class="purity-empty">${escapeHtml(model.purity.label)}</p>` : `<p class="purity-num">${score}<small>%</small></p><p class="purity-label">${escapeHtml(model.purity.label)}</p><div class="scale-line" aria-hidden="true"><span class="scale-track"></span><i class="scale-mark" style="left:${score}%"></i></div><div class="scale-ticks" aria-hidden="true">${TICKS.map((tick) => `<span class="${tick === 15 || tick === 40 ? "tick-minor" : ""}" style="left:${tick}%">${tick}</span>`).join("")}</div>`}
      <p class="quiet">${held ? "越低越纯净。有项目未计入，分数只代表已经查到的信号。" : "越低越纯净。每一项加分都列在下面。"}</p>
    </aside>
  </section>`;
}

function compare(model: IpModel): string {
  const edge = compareCell("边缘", model.edgeIp ?? "没有", "CF-Connecting-IP", !model.edgeIp);
  const echoes = model.echoes
    .map((echo) => {
      const label = `${echo.family === "v4" ? "IPv4" : "IPv6"} · ${echo.name}`;
      const value = echo.ip ?? echo.error ?? "没有";
      return compareCell(label, value, "这条没有连上", !echo.ip);
    })
    .join("");
  const banner = model.routingBanner ? `<p class="callout">${escapeHtml(model.routingBanner)}</p>` : "";
  const note = model.lookupNote ? `<p class="quiet aside-note">${escapeHtml(model.lookupNote)}</p>` : "";
  return `<section class="band" aria-label="地址对照">
    <header class="section-head"><h2>地址对照</h2><p>边缘的 CF-Connecting-IP，以及浏览器各自连上的 IPv4、IPv6。</p></header>
    <div class="frame"><div class="compare">${edge}${echoes}</div></div>
    ${banner}${note}
  </section>`;
}

function compareCell(label: string, value: string, failNote: string, failed: boolean): string {
  return `<div class="compare-item">
    <p class="compare-label">${escapeHtml(label)}</p>
    <p class="compare-value mono${failed ? " is-unknown" : ""}">${escapeHtml(value)}</p>
    ${failed ? `<p class="quiet">${escapeHtml(failNote)}</p>` : ""}
  </div>`;
}

function identity(model: IpModel): string {
  const domain = model.domains[0]?.value ?? "无法查询";
  const domainNote = model.domains.length
    ? nameList(model.domains)
    : `<small>PeeringDB 和 ipwho.is 都没有给出域名</small>`;
  const range = model.range?.value ?? "无法查询";
  const rangeBits = [model.range ? model.range.source : "", model.prefix ? `BGP ${model.prefix.value} · ${model.prefix.source}` : ""].filter(Boolean);
  const rangeNote = `<small>${escapeHtml(rangeBits.join(" · ") || "RDAP 没有返回起止地址")}</small>`;
  const ptr = model.ptr.state === "有记录" ? model.ptr.value ?? "有记录" : model.ptr.state;
  const asnNote = model.asnNames.length
    ? nameList(model.asnNames)
    : `<small>${escapeHtml(model.asnSource ? `编号来自 ${model.asnSource}` : "没有 ASN")}</small>`;
  const rows = [
    record("ASN", model.asnTitle, asnNote),
    record("AS 域名", domain, domainNote),
    record("IP 范围", range, rangeNote),
    record("反向 DNS", ptr, "<small>IPv4 通过 Cloudflare DNS 查询 PTR。</small>"),
  ];
  if (showRadar(model.radar)) rows.push(record("人机流量比", radarValue(model), `<small>${escapeHtml(model.radar.note)}</small>`));
  return `<section class="band" aria-label="网络登记">
    <header class="section-head"><h2>网络登记</h2><p>ASN、域名和范围。名称按来源分开写。</p></header>
    <div class="frame"><dl class="sheet-list">${rows.join("")}</dl></div>
  </section>`;
}

function nameList(items: { value: string; source: string }[]): string {
  return `<ul class="meta-list">${items.map((item) => `<li><span>${escapeHtml(item.value)}</span><small>${escapeHtml(item.source)}</small></li>`).join("")}</ul>`;
}

function record(label: string, value: string, noteHtml: string): string {
  const quiet = value === "无法查询" || value === "无记录" || value === "没有 ASN";
  return `<div>
    <dt>${escapeHtml(label)}</dt>
    <dd>
      <strong class="${quiet ? "is-unknown" : ""}">${escapeHtml(value)}</strong>
      ${noteHtml}
    </dd>
  </div>`;
}

function verdicts(model: IpModel): string {
  const originTone = model.origin.label === "原生IP" ? "ok" : model.origin.label === "广播IP" ? "warn" : "neutral";
  const facilityTone = model.facility.label === "住宅IP" ? "ok" : model.facility.label === "机房IP" ? "bad" : model.facility.label === "移动IP" || model.facility.label === "不一致" ? "warn" : "neutral";
  const registered = model.registeredCountry
    ? `<p class="quiet">登记国 ${escapeHtml(countryLabel(model.registeredCountry))}，${escapeHtml(model.registeredCountrySource ?? "RDAP")}。</p>`
    : "";
  return `<section class="verdicts" aria-label="来源与属性">
    <article class="verdict">
      <h2>来源</h2>
      <p class="verdict-word tone-${originTone}">${escapeHtml(model.origin.label)}</p>
      <p>${escapeHtml(model.origin.note)}</p>
      ${registered}
    </article>
    <article class="verdict">
      <h2>属性</h2>
      <p class="verdict-word tone-${facilityTone}">${escapeHtml(model.facility.label)}</p>
      <p>${escapeHtml(model.facility.note)}</p>
    </article>
  </section>`;
}

function purityBlock(model: IpModel): string {
  const lines = model.purity.lines
    .map((line) => {
      const points = line.points === null ? "未计入" : line.points > 0 ? `+${line.points}` : "0";
      const klass = line.points === null ? "is-unknown" : line.points > 0 ? "is-hot" : "";
      return `<li><div class="ledger-top"><span>${escapeHtml(line.label)}</span><b class="${klass}">${points}</b></div><small>${escapeHtml(ledgerDetail(line.label, line.detail, model))}</small></li>`;
    })
    .join("");
  return `<section class="band" id="purity">
    <header class="section-head"><h2>纯净度明细</h2><p>从 0 往上加。查不到的项写「未计入」，不当成安全。</p></header>
    <div class="frame">
      <ol class="ledger">${lines}</ol>
      <details class="fold in-card"><summary>计算公式</summary><p class="quiet">${escapeHtml(model.purity.formula)}</p></details>
    </div>
  </section>`;
}

function ledgerDetail(label: string, detail: string, model: IpModel): string {
  if (label === "同族出口不一致" && model.routingBanner) return "同族浏览器回显和边缘地址不一致。地址写在上面的对照里。";
  if (label === "广播 IP" && model.origin.label === "广播IP") return "登记国和地理位置不一致。说明写在上面的「来源」里。";
  return detail;
}

function toc(): string {
  const links = [
    ["#geo", "定位"],
    ["#risk", "风险"],
    ["#fingerprint", "指纹"],
    ["#map", "地图"],
    ["#vpn", "VPN"],
    ["#webrtc", "WebRTC"],
    ["#dns", "DNS"],
  ];
  return `<nav class="toc" aria-label="检测项目">${links.map(([href, label]) => `<a href="${href}">${label}</a>`).join("")}</nav>`;
}

function geo(places: PlaceView[]): string {
  const body = places.length
    ? `<div class="frame"><div class="directory">${places.map((place) => locationRow(place)).join("")}</div></div>`
    : `<p class="quiet">没有可显示的定位来源。</p>`;
  return `<section class="band" id="geo">
    <header class="section-head"><h2>定位</h2><p>每家单独列出，不把国家和坐标合成一个答案。</p></header>
    ${body}
  </section>`;
}

function locationRow(place: PlaceView): string {
  const line = place.status === "已查询" ? placeLine(place) : "—";
  const flagMark = place.countryCode ? `<span class="flag" aria-hidden="true">${flag(place.countryCode)}</span>` : "";
  const bits = [place.ip, place.timezone, place.agreement === "一致" ? "与登记国一致" : place.agreement === "不同" ? "与登记国不同" : ""].filter((bit): bit is string => Boolean(bit));
  const badge = place.status === "已查询" ? "" : `<span class="badge tone-neutral">${escapeHtml(place.status)}</span>`;
  return `<article class="dir-row${place.status === "已查询" ? "" : " is-quiet-row"}">
    <div class="dir-k"><h3>${escapeHtml(SOURCE_LABEL[place.id])}</h3>${badge}</div>
    <div class="dir-v">
      <p class="dir-place">${flagMark}${escapeHtml(line)}</p>
      ${bits.length ? `<p class="quiet">${escapeHtml(bits.join(" · "))}</p>` : ""}
      <p class="quiet">${escapeHtml(place.note)}</p>
    </div>
  </article>`;
}

function risk(rows: RiskRow[]): string {
  const body = rows.length
    ? `<div class="frame"><div class="directory">${rows.map((row) => riskRow(row)).join("")}</div></div>`
    : `<p class="quiet">没有可显示的风险来源。</p>`;
  return `<section class="band" id="risk">
    <header class="section-head"><h2>风险</h2><p>只写来源自己给出的字段。没有返回，就不当成否。</p></header>
    ${body}
  </section>`;
}

function riskRow(row: RiskRow): string {
  return `<article class="dir-row risk-row">
    <div class="dir-k"><h3>${escapeHtml(row.label)}</h3><p class="quiet">${escapeHtml(row.source)}</p></div>
    <p class="dir-note">${escapeHtml(row.note)}</p>
    <span class="badge tone-${row.tone}">${escapeHtml(row.value)}</span>
  </article>`;
}

function fingerSection(model: IpModel, browser: BrowserReport): string {
  return `<section class="band" id="fingerprint">
    <header class="section-head"><h2>指纹</h2><p>这次浏览器报上来的环境。除了时区，不拿来改纯净度。</p></header>
    <div class="frame pad"><div class="kv-grid cols-2">${fingerprint(model, browser)}</div></div>
  </section>`;
}

function fingerprint(model: IpModel, browser: BrowserReport): string {
  const renderer = browser.webgl?.unmaskedRenderer || browser.webgl?.renderer || "不可用";
  const items: { label: string; value: string; note?: string; badge?: string }[] = [
    {
      label: "时区",
      value: model.timezone.state,
      note: `浏览器 ${model.timezone.browser || "—"} ${browser.timezoneOffset}；边缘 ${model.timezone.edge || "—"}`,
      badge: model.timezone.state === "一致" ? "ok" : model.timezone.state === "不一致" ? "bad" : "neutral",
    },
    { label: "语言", value: browser.languages.join(", ") || "—", note: "navigator.languages" },
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
      const wide = !item.badge && item.value.length > 36 ? " is-wide" : "";
      return `<div class="kv${wide}"><dt>${escapeHtml(item.label)}</dt><dd>${value}${item.note ? `<small>${escapeHtml(item.note)}</small>` : ""}</dd></div>`;
    })
    .join("");
}

function mapSection(model: IpModel): string {
  if (!model.map) {
    return `<section class="band" id="map">
      <header class="section-head"><h2>地图</h2><p>针落在有坐标的一家上，优先 Cloudflare。不取几家的平均。</p></header>
      <p class="quiet">没有可用坐标，不放置地图针。</p>
    </section>`;
  }
  const pin = model.places.find((place) => place.status === "已查询" && SOURCE_LABEL[place.id] === model.map?.source);
  const title = pin ? placeLine(pin) : model.map.source;
  const flagMark = pin?.countryCode ? `<span class="flag" aria-hidden="true">${flag(pin.countryCode)}</span>` : "";
  return `<section class="band" id="map">
    <header class="section-head"><h2>地图</h2><p>针落在有坐标的一家上，优先 Cloudflare。不取几家的平均。</p></header>
    <div class="map-stage">
      <div id="exit-map" class="map-frame" role="img" aria-label="出口位置，来自 ${escapeHtml(model.map.source)}"></div>
      <div class="map-chip">
        <p class="map-chip-place">${flagMark}${escapeHtml(title)}</p>
        <p>${escapeHtml(model.map.source)} · ${model.map.latitude.toFixed(4)}, ${model.map.longitude.toFixed(4)}</p>
      </div>
    </div>
    <p class="quiet map-note">${escapeHtml(model.map.note)}</p>
  </section>`;
}

function vpnSection(model: IpModel): string {
  return `<section class="band" id="vpn">
    <header class="section-head"><h2>VPN 与分流</h2><p>只采用来源自己标出的 VPN、代理和 Tor。</p></header>
    <div class="frame pad-block">
      <p class="verdict-word tone-${model.vpn.tone}">${escapeHtml(model.vpn.mark)}</p>
      <p>${escapeHtml(model.vpn.note)}</p>
    </div>
  </section>`;
}

function webrtcSection(model: IpModel): string {
  const label = model.webrtc.leak === "yes" ? "公网不一致" : model.webrtc.leak === "no" ? "未发现公网不一致" : "无法判断";
  const tone = model.webrtc.leak === "yes" ? "bad" : model.webrtc.leak === "no" ? "ok" : "neutral";
  const rows = model.webrtc.rows.length
    ? `<ul class="candidates">${model.webrtc.rows.map((row) => `<li><span class="mono">${escapeHtml(row.ip)}</span><span class="badge tone-${row.kind === "public" ? "warn" : "neutral"}">${KIND_LABEL[row.kind]}</span></li>`).join("")}</ul>`
    : `<p class="quiet">没有解析出候选地址。</p>`;
  return `<section class="band" id="webrtc">
    <header class="section-head"><h2>WebRTC</h2><p>只有公网候选才和已知出口比较。只看到 mDNS 时是无法判断，不当成没有泄露。</p></header>
    <div class="frame pad-block">
      <div class="row-head"><h3>候选地址</h3><span class="badge tone-${tone}">${label}</span></div>
      <p>${escapeHtml(model.webrtc.error ?? model.webrtc.detail)}</p>
      ${rows}
      <p class="quiet">STUN：stun.cloudflare.com:3478、stun.l.google.com:19302、stun.chat.bilibili.com:3478、stun.miwifi.com:3478。中继地址不拿来和出口比较。</p>
    </div>
  </section>`;
}

function dnsSection(model: IpModel): string {
  return `<section class="band" id="dns">
    <div class="limit">
      <div class="row-head"><h2>DNS 泄露</h2><span class="badge tone-neutral">无法判断</span></div>
      <p>${escapeHtml(model.dnsNote)}</p>
    </div>
  </section>`;
}

function radarValue(model: IpModel): string {
  if (model.radar.state === "已查询" && model.radar.human !== null && model.radar.bot !== null) {
    return `人 ${model.radar.human}% · 机器 ${model.radar.bot}%`;
  }
  return model.radar.state;
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
  const view = leaflet.map(el, { zoomControl: true, scrollWheelZoom: false, attributionControl: true }).setView([latitude, longitude], 11);
  leaflet.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap",
    maxZoom: 19,
  }).addTo(view);
  leaflet.circleMarker([latitude, longitude], {
    radius: 7,
    color: "#f4efe6",
    weight: 2,
    fillColor: "#e0c39a",
    fillOpacity: 1,
  }).addTo(view);
  activeMap = view;
  refreshMap = () => view.invalidateSize();
  requestAnimationFrame(() => view.invalidateSize());
}
