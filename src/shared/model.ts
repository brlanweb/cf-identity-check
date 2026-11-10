import type { AbuseRecord } from "./history.ts";
import { classifyAddress, canonicalIp, ipFamily, type IceCandidate, type IceKind } from "./ip.ts";
import { purityScore, type PurityResult, type Tri } from "./purity.ts";
import { baseNetwork, type NetworkReport } from "./report.ts";
import { timezoneAlignment } from "./score.ts";
import {
  SOURCE_LABEL,
  facilitySummary,
  facilityVotes,
  ipOrigin,
  observedIpNote,
  proxycheckKind,
  type GeoPlace,
  type SourceId,
} from "./sources.ts";

export type EchoHit = {
  name: string;
  family: "v4" | "v6";
  ip: string | null;
  canonical: string | null;
  error: string | null;
};

export type PlaceView = GeoPlace & { agreement: "一致" | "不同" | "无法比较" };

export type RiskRow = {
  label: string;
  value: string;
  source: string;
  note: string;
  tone: "ok" | "warn" | "bad" | "neutral";
};

export type IpModel = {
  headlineIp: string | null;
  headlineSource: string;
  stackLabel: "IPv4 Only" | "IPv6 Only" | "双栈" | "无法检测";
  stackNote: string;
  edgeIp: string | null;
  edgePublic: boolean;
  colo: string | null;
  echoes: EchoHit[];
  routingBanner: string | null;
  lookupNote: string | null;
  asnTitle: string;
  asnSource: string | null;
  asnNames: { value: string; source: string }[];
  domains: { value: string; source: string }[];
  range: { value: string; source: string } | null;
  prefix: { value: string; source: string } | null;
  ptr: NetworkReport["identity"]["ptr"];
  registeredCountry: string | null;
  registeredCountrySource: string | null;
  radar: NetworkReport["radar"];
  places: PlaceView[];
  origin: { label: "广播IP" | "原生IP" | "无法判断"; note: string };
  facility: { label: "机房IP" | "住宅IP" | "移动IP" | "不一致" | "无法查询"; note: string };
  purity: PurityResult;
  risks: RiskRow[];
  vpn: { mark: string; note: string; tone: RiskRow["tone"] };
  map: { latitude: number; longitude: number; source: string; note: string } | null;
  webrtc: { rows: { ip: string; kind: IceKind }[]; leak: Tri; detail: string; error: string | null };
  timezone: { state: "一致" | "不一致" | "无法对照"; browser: string; edge: string | null };
  dnsNote: string;
};

export const DNS_NOTE =
  "没有结论可以下。要知道 DNS 走了哪台解析器，得有自己的权威域名，让对方来查一个只用一次的名字。本站没有这样的域名，浏览器也不提供系统解析器。这项留在页面上，是因为做不到，不是因为少了一把密钥。";

/** Drop a card or row whose only message is that its secret is missing. Real misses stay. */
export function presentedPlaces(places: PlaceView[]): PlaceView[] {
  return places.filter((place) => place.status !== "未配置");
}

export function presentedRisks(rows: RiskRow[]): RiskRow[] {
  return rows.filter((row) => row.value !== "未配置");
}

export function showRadar(radar: { state: string }): boolean {
  return radar.state !== "未配置";
}

const PLACE_ORDER: SourceId[] = ["cloudflare", "ipinfo", "ipinfo-direct", "ip-api", "ipapi-co", "ipwho", "ipapi-is", "ip2location", "ipip", "bilibili"];

const PIN_ORDER: SourceId[] = ["cloudflare", "ipinfo", "ipinfo-direct", "ip-api", "ipapi-co", "ipwho", "ipapi-is", "bilibili", "ipip", "ip2location"];

export function buildIpModel(input: {
  network: NetworkReport | null;
  echoes: EchoHit[];
  direct: { ipinfo: GeoPlace; ipip: GeoPlace };
  edge: { ip: string | null; timezone: string | null; country: string | null; colo: string | null };
  browserTimezone: string;
  webrtcCandidates: IceCandidate[];
  webrtcError: string | null;
  abuse: AbuseRecord;
}): IpModel {
  const network = usableNetwork(input.network);
  const v4 = uniqueFamily(input.echoes, "v4");
  const v6 = uniqueFamily(input.echoes, "v6");
  const edgeCanon = canonicalIp(input.edge.ip);
  const edgePublic = Boolean(edgeCanon && classifyAddress(edgeCanon) === "public");
  const split = splitOf(input.edge.ip, v4, v6, input.echoes);
  const places = decoratePlaces(network, input.direct, input.edge.ip);
  const origin = ipOrigin(
    network.identity.registeredCountry,
    places.filter((place) => place.status === "已查询").map((place) => ({ source: SOURCE_LABEL[place.id], countryCode: place.countryCode })),
  );
  const kind = proxycheckKind(network.risk.proxycheck.type, network.risk.proxycheck.proxy);
  const votes = facilityVotes({
    ipApiHosting: network.risk.ipApi.hosting,
    ipApiMobile: network.risk.ipApi.mobile,
    ipapiIsDatacenter: network.risk.ipapiIs.isDatacenter,
    ipapiIsMobile: network.risk.ipapiIs.isMobile,
    residential: kind.residential,
    mobile: kind.mobile,
  });
  const facility = facilitySummary(votes, network.risk.ipApi.hosting === false);
  const exits = exitSet(input.edge.ip, input.echoes);
  const webrtc = summarizeWebrtc(input.webrtcCandidates, exits);
  const alignment = timezoneAlignment(input.browserTimezone, input.edge.timezone, input.edge.country);
  const torYes = network.risk.tor.listed === true || kind.tor || network.risk.ipapiIs.isTor === true;
  const vpnYes = kind.vpn || network.risk.ipapiIs.isVpn === true;
  const proxyYes = kind.proxy || network.risk.ipapiIs.isProxy === true;
  const datacenterYes = network.risk.ipApi.hosting === true || network.risk.ipapiIs.isDatacenter === true;
  const mobileYes = network.risk.ipApi.mobile === true || network.risk.ipapiIs.isMobile === true || kind.mobile;
  const purity = purityScore({
    tor: torYes ? "yes" : network.risk.tor.listed === false ? "no" : "unknown",
    torDetail: torDetail(network, kind.tor),
    vpn: vpnYes ? "yes" : vpnKnownNo(network, vpnYes) ? "no" : "unknown",
    vpnDetail: flagDetail([
      ["proxycheck.io", kind.vpn ? "VPN" : network.risk.proxycheck.state === "已查询" ? network.risk.proxycheck.type ?? "非 VPN" : null],
      ["ipapi.is is_vpn", boolText(network.risk.ipapiIs.isVpn)],
    ]),
    proxy: proxyYes ? "yes" : proxyKnownNo(network, proxyYes) ? "no" : "unknown",
    proxyDetail: flagDetail([
      ["proxycheck.io", network.risk.proxycheck.state === "已查询" ? `${network.risk.proxycheck.proxy ? "proxy" : "非 proxy"}${network.risk.proxycheck.type ? ` / ${network.risk.proxycheck.type}` : ""}` : null],
      ["ipapi.is is_proxy", boolText(network.risk.ipapiIs.isProxy)],
    ]),
    ipApiProxy: network.risk.ipApi.proxy === true ? "yes" : network.risk.ipApi.proxy === false ? "no" : "unknown",
    ipApiProxyDetail: network.risk.ipApi.proxy === null ? network.risk.ipApi.note : "ip-api.com 的 proxy 把代理、VPN 和 Tor 合在一起。",
    datacenter: datacenterYes ? "yes" : datacenterKnownNo(network, datacenterYes) ? "no" : "unknown",
    datacenterDetail: flagDetail([
      ["ip-api.com hosting", boolText(network.risk.ipApi.hosting)],
      ["ipapi.is is_datacenter", boolText(network.risk.ipapiIs.isDatacenter)],
    ]),
    mobile: mobileYes ? "yes" : mobileKnownNo(network, mobileYes) ? "no" : "unknown",
    mobileDetail: flagDetail([
      ["ip-api.com mobile", boolText(network.risk.ipApi.mobile)],
      ["ipapi.is is_mobile", boolText(network.risk.ipapiIs.isMobile)],
      ["proxycheck.io", kind.mobile ? "Wireless" : null],
    ]),
    broadcast: origin.label === "广播IP" ? "broadcast" : origin.label === "原生IP" ? "native" : "unknown",
    broadcastDetail: origin.note,
    abuse: input.abuse.source === "stopforumspam" && input.abuse.appears === true ? "hit" : input.abuse.source === "stopforumspam" && input.abuse.appears === false ? "clean" : "unknown",
    abuseDetail: input.abuse.source === "stopforumspam" ? `StopForumSpam appears=${String(input.abuse.appears)}，次数 ${input.abuse.frequency ?? 0}。` : "没有查到 StopForumSpam。",
    abuseHeavy: (input.abuse.frequency ?? 0) >= 3,
    webrtcLeak: webrtc.leak,
    webrtcDetail: webrtc.detail,
    timezone: alignment === "不一致" ? "yes" : alignment === "一致" ? "no" : "unknown",
    timezoneDetail: alignment === "无法对照" ? "没有足够的时区或国家可以对照。" : `浏览器 ${input.browserTimezone || "—"}，边缘 ${input.edge.timezone || input.edge.country || "—"}。`,
    split: split.tri,
    splitDetail: split.detail,
  });
  const head = headline(input.edge.ip, input.echoes);
  const stack = stackOf(v4, v6, input.edge.ip);
  return {
    headlineIp: head.ip,
    headlineSource: head.source,
    stackLabel: stack.label,
    stackNote: stack.note,
    edgeIp: input.edge.ip,
    edgePublic,
    colo: input.edge.colo,
    echoes: input.echoes,
    routingBanner: routingBanner(v4, v6, input.echoes, split),
    lookupNote: network.skipReason,
    asnTitle: network.identity.asn ? (network.identity.names[0] ? `AS${network.identity.asn} - ${network.identity.names[0].value}` : `AS${network.identity.asn}`) : "无法查询",
    asnSource: network.identity.asnSource,
    asnNames: network.identity.names,
    domains: network.identity.domains,
    range: network.identity.range,
    prefix: network.identity.prefix,
    ptr: network.identity.ptr,
    registeredCountry: network.identity.registeredCountry,
    registeredCountrySource: network.identity.registeredCountrySource,
    radar: network.radar,
    places,
    origin,
    facility,
    purity,
    risks: riskRows(network, input.abuse),
    vpn: vpnSummary(torYes, vpnYes, proxyYes, network),
    map: mapPin(places),
    webrtc: { ...webrtc, error: input.webrtcError },
    timezone: { state: alignment, browser: input.browserTimezone, edge: input.edge.timezone },
    dnsNote: DNS_NOTE,
  };
}

export function usableNetwork(network: NetworkReport | null): NetworkReport {
  if (!network || !Array.isArray(network.places) || !network.risk || !network.identity || !network.radar) {
    return baseNetwork("边缘响应缺少数据源。");
  }
  return network;
}

function decoratePlaces(network: NetworkReport, direct: { ipinfo: GeoPlace; ipip: GeoPlace }, edgeIp: string | null): PlaceView[] {
  const byId = new Map(network.places.map((place) => [place.id, place]));
  const merged: GeoPlace[] = [];
  for (const id of PLACE_ORDER) {
    if (id === "ipinfo" || id === "ipinfo-direct") {
      if (id === "ipinfo") merged.push(...mergeIpinfo(byId.get("ipinfo"), direct.ipinfo));
      continue;
    }
    if (id === "ipip") {
      merged.push(direct.ipip);
      continue;
    }
    const place = byId.get(id);
    if (place) merged.push(place);
  }
  const registered = network.identity.registeredCountry;
  return merged.map((place) => {
    const noted = observedIpNote(place, edgeIp);
    return { ...noted, agreement: agreementOf(registered, noted.countryCode) };
  });
}

function mergeIpinfo(server: GeoPlace | undefined, direct: GeoPlace): GeoPlace[] {
  const serverOk = server?.status === "已查询";
  const directOk = direct.status === "已查询";
  if (serverOk && directOk && server?.ip && direct.ip && canonicalIp(server.ip) === canonicalIp(direct.ip)) {
    return [{ ...server, note: `${server.note} 浏览器直连看到同一地址。`.trim() }];
  }
  if (serverOk && directOk && server) return [server, direct];
  if (serverOk && server) return [server];
  if (directOk) return [direct];
  if (server) return [{ ...server, note: `${server.note} 浏览器直连也没有返回。`.trim() }];
  return [direct];
}

function agreementOf(registered: string | null, code: string | null): PlaceView["agreement"] {
  if (!registered || !code) return "无法比较";
  return registered === code ? "一致" : "不同";
}

function uniqueFamily(echoes: EchoHit[], family: EchoHit["family"]): string[] {
  const found: string[] = [];
  for (const echo of echoes) {
    if (echo.family === family && echo.canonical && !found.includes(echo.canonical)) found.push(echo.canonical);
  }
  return found;
}

function displayIps(canonicals: string[], echoes: EchoHit[]): string {
  return canonicals.map((item) => echoes.find((echo) => echo.canonical === item)?.ip ?? item).join("、");
}

function splitOf(edgeIp: string | null, v4: string[], v6: string[], echoes: EchoHit[]): { tri: Tri; detail: string } {
  const edgeCanon = canonicalIp(edgeIp);
  if (!edgeCanon || classifyAddress(edgeCanon) !== "public") {
    return { tri: "unknown", detail: "边缘没有公网地址，不和浏览器回显比分流。" };
  }
  const family = ipFamily(edgeCanon);
  const peers = family === "v6" ? v6 : v4;
  if (peers.length === 0) return { tri: "unknown", detail: "浏览器没有同族回显，不能判断分流。" };
  if (peers.every((ip) => ip === edgeCanon)) return { tri: "no", detail: "同族浏览器回显和 CF-Connecting-IP 一致。" };
  return {
    tri: "yes",
    detail: `CF-Connecting-IP 是 ${edgeIp}，浏览器 ${family === "v6" ? "IPv6" : "IPv4"} 回显是 ${displayIps(peers, echoes)}。`,
  };
}

function routingBanner(v4: string[], v6: string[], echoes: EchoHit[], split: { tri: Tri; detail: string }): string | null {
  const parts: string[] = [];
  if (v4.length > 1) parts.push(`IPv4 回显不一致：${displayIps(v4, echoes)}`);
  if (v6.length > 1) parts.push(`IPv6 回显不一致：${displayIps(v6, echoes)}`);
  if (split.tri === "yes") parts.push(split.detail);
  return parts.length ? parts.join("。") : null;
}

function stackOf(v4: string[], v6: string[], edgeIp: string | null): { label: IpModel["stackLabel"]; note: string } {
  if (v4.length && v6.length) {
    const via = ipFamily(edgeIp);
    const viaText = via === "v6" ? "IPv6" : via === "v4" ? "IPv4" : null;
    return { label: "双栈", note: viaText ? `浏览器能通 IPv4 和 IPv6。这次连到本站用的是 ${viaText}。` : "浏览器能通 IPv4 和 IPv6。" };
  }
  if (v4.length) return { label: "IPv4 Only", note: "只检测到 IPv4 回显，IPv6 回显没有连上。" };
  if (v6.length) return { label: "IPv6 Only", note: "只检测到 IPv6 回显，IPv4 回显没有连上。" };
  const edgeCanon = canonicalIp(edgeIp);
  if (edgeCanon && classifyAddress(edgeCanon) === "public") {
    return {
      label: edgeCanon.includes(":") ? "IPv6 Only" : "IPv4 Only",
      note: "浏览器没有独立回显，徽章只按边缘地址。",
    };
  }
  return { label: "无法检测", note: "边缘和浏览器都没有给出公网地址。" };
}

function headline(edgeIp: string | null, echoes: EchoHit[]): { ip: string | null; source: string } {
  const edgeCanon = canonicalIp(edgeIp);
  if (edgeCanon && classifyAddress(edgeCanon) === "public") return { ip: edgeIp, source: "CF-Connecting-IP" };
  const unique = [...new Set(echoes.map((echo) => echo.canonical).filter((item): item is string => Boolean(item)))];
  if (unique.length === 1) {
    const raw = echoes.find((echo) => echo.canonical === unique[0])?.ip ?? unique[0] ?? null;
    return { ip: raw, source: "浏览器回显" };
  }
  if (unique.length > 1) return { ip: null, source: "多个回显不一致" };
  return { ip: null, source: "没有检测到公网 IP" };
}

function exitSet(edgeIp: string | null, echoes: EchoHit[]): string[] {
  const set = new Set<string>();
  const edgeCanon = canonicalIp(edgeIp);
  if (edgeCanon && classifyAddress(edgeCanon) === "public") set.add(edgeCanon);
  for (const echo of echoes) if (echo.canonical) set.add(echo.canonical);
  return [...set];
}

function summarizeWebrtc(candidates: IceCandidate[], exits: string[]): IpModel["webrtc"] {
  const rows: { ip: string; kind: IceKind }[] = [];
  for (const candidate of candidates) {
    const ip = candidate.ip ?? "";
    if (!ip) continue;
    if (rows.some((row) => row.kind === candidate.kind && row.ip === ip)) continue;
    rows.push({ ip, kind: candidate.kind });
  }
  const publics = [...new Set(candidates.filter((item) => item.kind === "public" && item.ip).map((item) => canonicalIp(item.ip) ?? "").filter(Boolean))];
  if (candidates.length === 0) return { rows, leak: "unknown", detail: "没有收到 ICE 候选。", error: null };
  if (publics.length === 0) {
    const kinds = [...new Set(candidates.map((item) => item.kind))].join("、");
    return { rows, leak: "unknown", detail: `没有公网候选（${kinds}）。mDNS 或私网不能证明没有泄露。`, error: null };
  }
  if (exits.length === 0) return { rows, leak: "unknown", detail: `看到公网 ${publics.join("、")}，但没有出口地址可对照。`, error: null };
  const extras = publics.filter((ip) => !exits.includes(ip));
  if (extras.length === 0) return { rows, leak: "no", detail: "WebRTC 公网候选都在已知出口里。", error: null };
  return { rows, leak: "yes", detail: `WebRTC 公网 ${extras.join("、")} 不在边缘或浏览器回显里。`, error: null };
}

function mapPin(places: PlaceView[]): IpModel["map"] {
  const located = places.filter((place) => place.status === "已查询" && place.latitude !== null && place.longitude !== null);
  located.sort((a, b) => PIN_ORDER.indexOf(a.id) - PIN_ORDER.indexOf(b.id));
  const pin = located[0];
  if (!pin || pin.latitude === null || pin.longitude === null) return null;
  const latitude = pin.latitude;
  const longitude = pin.longitude;
  const far = located.filter((place) => {
    if (place === pin || place.latitude === null || place.longitude === null) return false;
    return km(latitude, longitude, place.latitude, place.longitude) > 200;
  });
  const note = far.length
    ? `针来自 ${SOURCE_LABEL[pin.id]}。${far.map((place) => SOURCE_LABEL[place.id]).join("、")} 的坐标相差超过 200 公里，没有取平均。`
    : `针来自 ${SOURCE_LABEL[pin.id]}，不是几家坐标的平均值。`;
  return { latitude: pin.latitude, longitude: pin.longitude, source: SOURCE_LABEL[pin.id], note };
}

function km(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLon = (lon2 - lon1) * rad;
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) ** 2;
  return 6371 * 2 * Math.asin(Math.min(1, Math.sqrt(h)));
}

function torDetail(network: NetworkReport, proxycheckTor: boolean): string {
  const parts = [network.risk.tor.note];
  if (proxycheckTor) parts.push("proxycheck.io 的 type 是 TOR。");
  if (network.risk.ipapiIs.isTor === true) parts.push("ipapi.is is_tor 为是。");
  return parts.join("");
}

function vpnKnownNo(network: NetworkReport, vpnYes: boolean): boolean {
  if (vpnYes) return false;
  return (network.risk.proxycheck.state === "已查询" && network.risk.proxycheck.proxy === false) || network.risk.ipapiIs.isVpn === false;
}

function proxyKnownNo(network: NetworkReport, proxyYes: boolean): boolean {
  if (proxyYes) return false;
  return (network.risk.proxycheck.state === "已查询" && network.risk.proxycheck.proxy === false) || network.risk.ipapiIs.isProxy === false;
}

function datacenterKnownNo(network: NetworkReport, yes: boolean): boolean {
  if (yes) return false;
  return network.risk.ipApi.hosting === false || network.risk.ipapiIs.isDatacenter === false;
}

function mobileKnownNo(network: NetworkReport, yes: boolean): boolean {
  if (yes) return false;
  return network.risk.ipApi.mobile === false || network.risk.ipapiIs.isMobile === false;
}

function boolText(value: boolean | null): string | null {
  if (value === null) return null;
  return value ? "是" : "否";
}

function flagDetail(pairs: [string, string | null][]): string {
  const parts = pairs.filter((pair): pair is [string, string] => Boolean(pair[1])).map(([label, value]) => `${label} ${value}`);
  return parts.length ? parts.join("；") : "没有返回。";
}

function vpnSummary(torYes: boolean, vpnYes: boolean, proxyYes: boolean, network: NetworkReport): IpModel["vpn"] {
  if (torYes) return { mark: "疑似", note: "有来源把这个地址标成 Tor 出口。", tone: "bad" };
  if (vpnYes) return { mark: "疑似", note: "有来源把这个地址标成 VPN。", tone: "bad" };
  if (proxyYes) return { mark: "疑似", note: "有来源把这个地址标成代理。", tone: "warn" };
  if (network.risk.tor.listed === false || network.risk.proxycheck.state === "已查询" || network.risk.ipapiIs.isVpn === false) {
    return { mark: "未发现", note: "已返回的来源没有把这个地址标成 VPN、代理或 Tor。没返回的来源不算数。", tone: "ok" };
  }
  return { mark: "无法查询", note: "VPN、代理和 Tor 列表都没有查到。", tone: "neutral" };
}

function riskRows(network: NetworkReport, abuse: AbuseRecord): RiskRow[] {
  const kind = proxycheckKind(network.risk.proxycheck.type, network.risk.proxycheck.proxy);
  const rows: RiskRow[] = [
    boolRow("Tor 出口列表", network.risk.tor.listed, network.risk.tor.state, "Tor Project torbulkexitlist", network.risk.tor.note),
    boolRow("ip-api.com hosting", network.risk.ipApi.hosting, network.risk.ipApi.state, "ip-api.com", "true 表示机房、托管或数据中心。"),
    boolRow("ip-api.com proxy", network.risk.ipApi.proxy, network.risk.ipApi.state, "ip-api.com", "这个字段把代理、VPN 和 Tor 合在一起。"),
    boolRow("ip-api.com mobile", network.risk.ipApi.mobile, network.risk.ipApi.state, "ip-api.com", "true 表示移动运营商。"),
  ];
  if (network.risk.proxycheck.state === "未配置") {
    rows.push({ label: "proxycheck.io", value: "未配置", source: "proxycheck.io", note: network.risk.proxycheck.note, tone: "neutral" });
  } else if (network.risk.proxycheck.state !== "已查询") {
    rows.push({ label: "proxycheck.io", value: "无法查询", source: "proxycheck.io", note: network.risk.proxycheck.note, tone: "neutral" });
  } else {
    const value = `${network.risk.proxycheck.proxy ? "proxy" : "非 proxy"}${network.risk.proxycheck.type ? ` · ${network.risk.proxycheck.type}` : ""}`;
    rows.push({
      label: "proxycheck.io",
      value,
      source: "proxycheck.io",
      note: network.risk.proxycheck.provider ? `${network.risk.proxycheck.note} ${network.risk.proxycheck.provider}` : network.risk.proxycheck.note,
      tone: kind.vpn || kind.tor || kind.proxy ? "bad" : "ok",
    });
  }
  rows.push(ipapiIsRow(network));
  rows.push(boolRow("IP2Location 代理", network.risk.ip2location.isProxy, network.risk.ip2location.state, "IP2Location", network.risk.ip2location.note));
  rows.push(abuseRow(abuse));
  rows.push({
    label: "欺诈黑名单",
    value: "无法查询",
    source: "无",
    note: "没有接支付或欺诈评分。StopForumSpam 只代表公开的垃圾发帖记录。",
    tone: "neutral",
  });
  const rpkiTone = network.identity.rpki.state === "valid" ? "ok" : network.identity.rpki.state === "invalid" ? "bad" : "neutral";
  rows.push({
    label: "RPKI",
    value: network.identity.rpki.state === "valid" ? "有效" : network.identity.rpki.state === "invalid" ? "无效" : network.identity.rpki.state === "unknown" ? "不确定" : "无法查询",
    source: "RIPEstat",
    note: network.identity.rpki.note,
    tone: rpkiTone,
  });
  return rows;
}

function ipapiIsRow(network: NetworkReport): RiskRow {
  const risk = network.risk.ipapiIs;
  if (risk.state === "未配置") return { label: "ipapi.is 风险字段", value: "未配置", source: "ipapi.is", note: risk.note, tone: "neutral" };
  if (risk.state !== "已查询") return { label: "ipapi.is 风险字段", value: "无法查询", source: "ipapi.is", note: risk.note, tone: "neutral" };
  const parts = [
    risk.isVpn === null ? null : `VPN ${risk.isVpn ? "是" : "否"}`,
    risk.isProxy === null ? null : `代理 ${risk.isProxy ? "是" : "否"}`,
    risk.isTor === null ? null : `Tor ${risk.isTor ? "是" : "否"}`,
    risk.isDatacenter === null ? null : `机房 ${risk.isDatacenter ? "是" : "否"}`,
    risk.isMobile === null ? null : `移动 ${risk.isMobile ? "是" : "否"}`,
  ].filter((part): part is string => Boolean(part));
  if (parts.length === 0) return { label: "ipapi.is 风险字段", value: "无法查询", source: "ipapi.is", note: risk.note || "响应里没有 is_vpn / is_datacenter 等字段。可设置 IPAPI_IS_KEY。", tone: "neutral" };
  const bad = risk.isVpn === true || risk.isProxy === true || risk.isTor === true || risk.isDatacenter === true;
  return { label: "ipapi.is 风险字段", value: parts.join(" · "), source: "ipapi.is", note: risk.note, tone: bad ? "bad" : "ok" };
}

function boolRow(label: string, value: boolean | null, state: NetworkReport["risk"]["tor"]["state"], source: string, note: string): RiskRow {
  if (state === "未配置") return { label, value: "未配置", source, note, tone: "neutral" };
  if (state !== "已查询" || value === null) return { label, value: "无法查询", source, note, tone: "neutral" };
  return { label, value: value ? "是" : "否", source, note, tone: value ? "bad" : "ok" };
}

function abuseRow(abuse: AbuseRecord): RiskRow {
  if (abuse.source === "stopforumspam" && abuse.appears === true) {
    return { label: "StopForumSpam", value: "有公开记录", source: "StopForumSpam", note: `记录 ${abuse.frequency ?? 0} 次。这不是欺诈评分。`, tone: "bad" };
  }
  if (abuse.source === "stopforumspam" && abuse.appears === false) {
    return { label: "StopForumSpam", value: "无记录", source: "StopForumSpam", note: "未见此 IP。这不是完整滥用库。", tone: "ok" };
  }
  return { label: "StopForumSpam", value: "无法查询", source: "StopForumSpam", note: abuse.attempted ? "查询失败，不编造记录。" : "没有拿公网 IP 去查。", tone: "neutral" };
}
