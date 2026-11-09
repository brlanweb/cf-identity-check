/**
 * 纯净度系数 is a risk score: 0 is clean, 100 is not.
 * Only signals a source actually returned add points. Missing data is listed and not treated as safe.
 * Bands match the ticks 0, 15, 25, 40, 50, 70, 100.
 */
import type { Tone } from "./score.ts";

export type Tri = "yes" | "no" | "unknown";

export type PurityInput = {
  tor: Tri;
  torDetail: string;
  vpn: Tri;
  vpnDetail: string;
  proxy: Tri;
  proxyDetail: string;
  ipApiProxy: Tri;
  ipApiProxyDetail: string;
  datacenter: Tri;
  datacenterDetail: string;
  mobile: Tri;
  mobileDetail: string;
  broadcast: "broadcast" | "native" | "unknown";
  broadcastDetail: string;
  abuse: "hit" | "clean" | "unknown";
  abuseDetail: string;
  abuseHeavy: boolean;
  webrtcLeak: Tri;
  webrtcDetail: string;
  timezone: Tri;
  timezoneDetail: string;
  split: Tri;
  splitDetail: string;
};

export type PurityLine = {
  label: string;
  /** Null means the signal was not counted. Zero means it was checked and added nothing. */
  points: number | null;
  detail: string;
};

export type PurityLabel = "极度纯净" | "纯净" | "一般" | "轻微风险" | "高风险" | "极度风险" | "无法计算";

export type PurityResult = {
  score: number | null;
  label: PurityLabel;
  tone: Tone;
  lines: PurityLine[];
  formula: string;
};

export const PURITY_POINTS = {
  tor: 55,
  vpn: 40,
  proxy: 28,
  ipApiProxy: 12,
  datacenter: 18,
  mobile: 6,
  broadcast: 10,
  abuse: 12,
  abuseHeavy: 20,
  webrtc: 12,
  timezone: 8,
  split: 14,
} as const;

export const PURITY_FORMULA =
  "从 0 起加：Tor 出口 +55，VPN +40，其它代理 +28，ip-api 的合并 proxy 标记 +12（前四项只取最高一档），机房 +18，移动且不是机房 +6，登记国和地理位置国家不同 +10，StopForumSpam 命中 +12（次数不少于 3 则 +20），WebRTC 公网地址不在已知出口里 +12，时区不一致 +8，同族回显和 CF-Connecting-IP 不一致 +14。上限 100。查不到的项不加分，也不当成安全。";

export function purityLabel(score: number): Exclude<PurityLabel, "无法计算"> {
  if (score < 15) return "极度纯净";
  if (score < 25) return "纯净";
  if (score < 40) return "一般";
  if (score < 50) return "轻微风险";
  if (score < 70) return "高风险";
  return "极度风险";
}

export function purityTone(label: PurityLabel): Tone {
  if (label === "极度纯净" || label === "纯净") return "ok";
  if (label === "一般" || label === "轻微风险") return "warn";
  if (label === "高风险" || label === "极度风险") return "bad";
  return "neutral";
}

export function purityScore(input: PurityInput): PurityResult {
  const lines: PurityLine[] = [];
  let score = 0;
  let scored = false;

  const hit = (points: number, label: string, detail: string): void => {
    score += points;
    scored = true;
    lines.push({ label, points, detail });
  };
  const clear = (label: string, detail: string, counts: boolean): void => {
    if (counts) scored = true;
    lines.push({ label, points: 0, detail });
  };
  const aside = (label: string, detail: string): void => {
    lines.push({ label, points: null, detail });
  };

  if (input.tor === "yes") hit(PURITY_POINTS.tor, "Tor 出口", input.torDetail);
  else if (input.tor === "no") clear("Tor 出口", input.torDetail, false);
  else aside("Tor 出口", input.torDetail);

  if (input.tor === "yes") {
    aside("VPN", "已按 Tor 出口计分，不重复加。");
    aside("代理", "已按 Tor 出口计分，不重复加。");
    aside("ip-api proxy", "已按 Tor 出口计分，不重复加。");
  } else if (input.vpn === "yes") {
    hit(PURITY_POINTS.vpn, "VPN", input.vpnDetail);
    aside("代理", "已按 VPN 计分，不重复加。");
    aside("ip-api proxy", "已按 VPN 计分，不重复加。");
  } else if (input.proxy === "yes") {
    hit(PURITY_POINTS.proxy, "代理", input.proxyDetail);
    if (input.vpn === "no") clear("VPN", input.vpnDetail, true);
    else aside("VPN", input.vpnDetail);
    aside("ip-api proxy", "已按代理计分，不重复加。");
  } else if (input.ipApiProxy === "yes") {
    hit(PURITY_POINTS.ipApiProxy, "ip-api proxy", input.ipApiProxyDetail);
    if (input.vpn === "no") clear("VPN", input.vpnDetail, true);
    else aside("VPN", input.vpnDetail);
    if (input.proxy === "no") clear("代理", input.proxyDetail, true);
    else aside("代理", input.proxyDetail);
  } else {
    if (input.vpn === "no") clear("VPN", input.vpnDetail, true);
    else aside("VPN", input.vpnDetail);
    if (input.proxy === "no") clear("代理", input.proxyDetail, true);
    else aside("代理", input.proxyDetail);
    if (input.ipApiProxy === "no") clear("ip-api proxy", input.ipApiProxyDetail, true);
    else aside("ip-api proxy", input.ipApiProxyDetail);
  }

  if (input.datacenter === "yes") hit(PURITY_POINTS.datacenter, "机房", input.datacenterDetail);
  else if (input.datacenter === "no") clear("机房", input.datacenterDetail, true);
  else aside("机房", input.datacenterDetail);

  if (input.mobile === "yes" && input.datacenter === "yes") aside("移动网络", "已按机房计分，不重复加。");
  else if (input.mobile === "yes") hit(PURITY_POINTS.mobile, "移动网络", input.mobileDetail);
  else if (input.mobile === "no") clear("移动网络", input.mobileDetail, false);
  else aside("移动网络", input.mobileDetail);

  if (input.broadcast === "broadcast") hit(PURITY_POINTS.broadcast, "广播 IP", input.broadcastDetail);
  else if (input.broadcast === "native") clear("广播 IP", input.broadcastDetail, false);
  else aside("广播 IP", input.broadcastDetail);

  if (input.abuse === "hit") hit(input.abuseHeavy ? PURITY_POINTS.abuseHeavy : PURITY_POINTS.abuse, "公开滥用记录", input.abuseDetail);
  else if (input.abuse === "clean") clear("公开滥用记录", input.abuseDetail, false);
  else aside("公开滥用记录", input.abuseDetail);

  if (input.webrtcLeak === "yes") hit(PURITY_POINTS.webrtc, "WebRTC 公网不一致", input.webrtcDetail);
  else if (input.webrtcLeak === "no") clear("WebRTC 公网不一致", input.webrtcDetail, false);
  else aside("WebRTC 公网不一致", input.webrtcDetail);

  if (input.timezone === "yes") hit(PURITY_POINTS.timezone, "时区不一致", input.timezoneDetail);
  else if (input.timezone === "no") clear("时区不一致", input.timezoneDetail, false);
  else aside("时区不一致", input.timezoneDetail);

  if (input.split === "yes") hit(PURITY_POINTS.split, "同族出口不一致", input.splitDetail);
  else if (input.split === "no") clear("同族出口不一致", input.splitDetail, false);
  else aside("同族出口不一致", input.splitDetail);

  if (!scored) {
    return { score: null, label: "无法计算", tone: "neutral", lines, formula: PURITY_FORMULA };
  }
  const capped = Math.max(0, Math.min(100, score));
  const label = purityLabel(capped);
  return { score: capped, label, tone: purityTone(label), lines, formula: PURITY_FORMULA };
}
