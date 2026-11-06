import { assembleIntel, type IpIntel } from "../shared/intel.ts";
import type { ScoreResult } from "../shared/score.ts";

export type Field = {
  section: string;
  label: string;
  value: string;
  source: string;
};

export type SessionMemo = { runs: number; ipChanges: number };

export type Reachability = { name: string; url: string; ok: boolean; ms: number | null };

export type DeviceView = {
  timezone: string;
  timezoneOffset: string;
  languages: string[];
  userAgent: string;
  cookieEnabled: boolean;
  webglRenderer: string | null;
  canvasHash: string | null;
  webglHash: string | null;
};

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function flag(code: string | null): string {
  if (!code || code.length !== 2 || !/^[A-Za-z]{2}$/.test(code)) return "";
  const points = [...code.toUpperCase()].map((char) => 0x1f1e6 + char.charCodeAt(0) - 65);
  return `${String.fromCodePoint(...points)} `;
}

function formatAsn(asn: string | null): string {
  if (!asn) return "—";
  return /^[0-9]+$/.test(asn) ? `AS${asn}` : asn;
}

function count(value: number | null): string {
  if (value === null) return "无法查询";
  return new Intl.NumberFormat("zh-CN").format(value);
}

function dial(score: number): string {
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - score / 100);
  return `<svg class="dial" viewBox="0 0 120 120" aria-hidden="true">
    <circle class="dial-track" cx="60" cy="60" r="${radius}"></circle>
    <circle class="dial-value" cx="60" cy="60" r="${radius}" stroke-dasharray="${circumference.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}"></circle>
  </svg>`;
}

function osAndBrowser(userAgent: string): string {
  const ua = userAgent.toLowerCase();
  const os = ua.includes("windows")
    ? "Windows"
    : ua.includes("mac os") || ua.includes("macintosh")
      ? "macOS"
      : ua.includes("android")
        ? "Android"
        : ua.includes("iphone") || ua.includes("ipad")
          ? "iOS"
          : ua.includes("linux")
            ? "Linux"
            : "未知系统";
  const browser = ua.includes("edg/")
    ? "Edge"
    : ua.includes("firefox")
      ? "Firefox"
      : ua.includes("chrome") || ua.includes("chromium")
        ? "Chrome"
        : ua.includes("safari")
          ? "Safari"
          : "未知浏览器";
  return `${os} · ${browser}`;
}

function short(value: string | null): string {
  if (!value) return "—";
  return value.length > 16 ? value.slice(0, 16) : value;
}

function rows(items: { label: string; value: string; note?: string }[]): string {
  return items
    .map(
      (item) => `<div class="kv">
        <dt>${escapeHtml(item.label)}</dt>
        <dd>${escapeHtml(item.value)}${item.note ? `<small>${escapeHtml(item.note)}</small>` : ""}</dd>
      </div>`,
    )
    .join("");
}

function ipFacts(score: ScoreResult): string {
  const exit = score.exit;
  const place = [exit.countryLabel, exit.region, exit.city].filter((item) => item && item !== "未知").join(" · ") || "地区未知";
  const org = exit.asOrganization || "组织名未知";
  return `<p class="ip-addr">${flag(exit.country)}${escapeHtml(exit.ip ?? "没有 IP")}</p>
    <p>${escapeHtml(place)}</p>
    <p>${escapeHtml(formatAsn(exit.asn))} · ${escapeHtml(org)}</p>`;
}

function chinaCard(score: ScoreResult): string {
  const exit = score.exit;
  const ipv4 = Boolean(exit.ip && !exit.ip.includes(":"));
  if (exit.country === "CN" && ipv4) {
    return `<article class="ip-card">
      <h3>中国出口 IPv4</h3>
      ${ipFacts(score)}
      <p class="src">边缘国家是中国，这条就是当前出口。</p>
    </article>`;
  }
  const why = !exit.ip
    ? "没有读到出口 IP。"
    : exit.ip.includes(":")
      ? "当前出口是 IPv6，没有另测到中国 IPv4。"
      : `边缘国家是${exit.countryLabel}，不是中国。本站没有中国探测点，不会编造另一条中国 IPv4。`;
  return `<article class="ip-card is-muted">
    <h3>中国出口 IPv4</h3>
    <p class="ip-addr">非中国出口</p>
    <p>${escapeHtml(why)}</p>
  </article>`;
}

function checks(score: ScoreResult): string {
  const items = [
    ["VPN", score.securityChecks.vpn],
    ["代理", score.securityChecks.proxy],
    ["Tor", score.securityChecks.tor],
    ["机器人", score.securityChecks.crawler],
    ["滥用记录", score.securityChecks.abuse],
  ] as const;
  return items
    .map(([label, item]) => {
      const tone = item.state === "未发现" || item.state === "无记录" ? "ok" : item.state === "无法查询" ? "neutral" : "bad";
      return `<article class="check tone-${tone}" title="${escapeHtml(item.note)}">
        <h3>${escapeHtml(label)}</h3>
        <p>${escapeHtml(item.state)}</p>
      </article>`;
    })
    .join("");
}

function stars(score: number): string {
  return Array.from({ length: 5 }, (_, index) => `<i class="${index < score ? "on" : ""}"></i>`).join("");
}

function scenes(score: ScoreResult): string {
  const items = [
    ["AI 应用", score.scenes.ai],
    ["社媒运营", score.scenes.social],
    ["TikTok", score.scenes.tiktok],
  ] as const;
  return items
    .map(([label, item]) => {
      const tone = item.advice === "推荐" ? "ok" : item.advice === "不推荐" ? "bad" : "warn";
      return `<article class="scene">
        <h3>${escapeHtml(label)}</h3>
        <p class="stars" aria-label="${item.score} / 5">${stars(item.score)}</p>
        <p class="badge tone-${tone}">${escapeHtml(item.advice)}</p>
      </article>`;
    })
    .join("");
}

function operatorKind(score: ScoreResult): string {
  if (score.attribute.kind === "datacenter") return "Hosting";
  if (score.attribute.kind === "residential" || score.attribute.kind === "native") return "ISP";
  return "未知";
}

function mark(score: ScoreResult): string {
  if (score.attribute.kind === "datacenter") return "机房IP";
  if (score.attribute.kind === "residential") return "住宅IP";
  if (score.attribute.kind === "native") return "原生IP";
  return "未标记";
}

export function renderPage(input: {
  status: string;
  score: ScoreResult;
  session: SessionMemo;
  intel: IpIntel | null;
  probes: Reachability[];
  udpHolder: string | null;
  device: DeviceView;
  observed: Field[];
  claimed: Field[];
  raw: unknown;
}): void {
  const status = document.querySelector("#status");
  if (status) status.textContent = input.status;
  const { score } = input;
  const intel =
    input.intel ??
    assembleIntel({
      ip: score.exit.ip,
      edgeCountry: score.exit.country,
      ptrBody: null,
      rdapIp: null,
      rdapAsn: null,
      prefixBody: null,
      routingBody: null,
      rpkiBody: null,
    });
  const udp = score.signals.find((item) => item.id === "udp");
  const leaked = score.mismatches.find((item) => item.label === "公网地址");
  const sameUdp = udp?.badge === "一致";
  const udpPlace = sameUdp
    ? [score.exit.countryLabel, score.exit.city].filter(Boolean).join(" · ")
    : input.udpHolder
      ? input.udpHolder
      : "归属地无法查询";

  const verdict = document.querySelector("#verdict");
  if (verdict) {
    const probeRows = input.probes
      .map((probe) => {
        const timing = probe.ms === null ? "无计时" : `${probe.ms} ms`;
        return `<div class="probe">
          <strong>${escapeHtml(probe.name)}</strong>
          <span>${probe.ok ? "浏览器已连通" : "没有连通"}</span>
          <b>${escapeHtml(timing)}</b>
        </div>`;
      })
      .join("");
    const attributeLabel = score.attribute.tag ? `${score.attribute.label} · ${score.attribute.tag}` : score.attribute.label;
    verdict.innerHTML = `<div class="stack" data-trust="${score.trust.score}" data-region="${score.regionSupport.state}" data-ai="${score.scenes.ai.advice}">
      <section class="block">
        <h2>出口 IP 对照</h2>
        <div class="ip-grid">
          ${chinaCard(score)}
          <article class="ip-card">
            <h3>Cloudflare 出口 IP</h3>
            ${ipFacts(score)}
            <p class="src">来源：CF-Connecting-IP 与 request.cf。边缘机房 ${escapeHtml(score.exit.colo ?? "未知")}。</p>
          </article>
          <article class="ip-card">
            <h3>Claude AI 出口 IP</h3>
            ${ipFacts(score)}
            <p class="src">本站也在 Cloudflare 后面，测到的就是这次访问的出口。Claude 从网络侧通常看到的是同一条访客出口。这里没有单独去连 claude.ai 再取一个 IP。</p>
          </article>
        </div>
      </section>

      <section class="score-row">
        <article class="trust-card tone-${score.trust.tone}">
          <h2>Claude AI 信任评分</h2>
          <div class="trust-gauge" role="img" aria-label="Claude AI Trust Score ${score.trust.score}，${score.trust.headline}，${score.trust.detail}">
            ${dial(score.trust.score)}
            <div class="trust-face"><strong>${score.trust.score}</strong></div>
          </div>
          <div class="scale" aria-hidden="true"><span>高危</span><span>25</span><span>50</span><span>75</span><span>可信</span></div>
          <div class="scale-bar" aria-hidden="true"><span style="width:${score.trust.score}%"></span></div>
          <p class="trust-status"><b>${escapeHtml(score.trust.headline)}</b> / ${escapeHtml(score.trust.detail)}</p>
          <p class="src">启发式估计，与 Anthropic 无关。</p>
        </article>
        <article class="region-card tone-${score.regionSupport.state === "正常" ? "ok" : score.regionSupport.state === "受限" ? "bad" : "neutral"}">
          <h2>Claude 支持地区</h2>
          <p class="big">${escapeHtml(score.regionSupport.state)}</p>
          <p>${escapeHtml(score.regionSupport.note)}</p>
        </article>
      </section>

      <section class="block">
        <h2>Claude AI 出口 IP 属性</h2>
        <dl class="grid">${rows([
          { label: "地区", value: score.exit.countryLabel },
          { label: "城市", value: [score.exit.region, score.exit.city].filter(Boolean).join(" · ") || "—" },
          { label: "IP 属性", value: attributeLabel },
          { label: "ASN", value: formatAsn(score.exit.asn) },
          { label: "运营商", value: score.exit.asOrganization ?? "—" },
        ])}</dl>
      </section>

      <section class="block">
        <h2>Claude AI 出口 IP 安全检测</h2>
        <div class="checks">${checks(score)}</div>
      </section>

      <section class="block">
        <h2>Claude 可用性检测</h2>
        <p class="src">浏览器计时，不是官方状态。到美国站点延迟偏高不一定是故障。</p>
        <div class="probes">${probeRows || `<p class="src">还没有探测结果。</p>`}</div>
      </section>

      <section class="pair">
        <article class="block">
          <h2>DNS 泄露检测</h2>
          <p class="big">无法判断</p>
          <p>浏览器不暴露系统解析器，页面也看不到有没有开 DoH。不能判断 DNS 是否泄露，所以不显示 DNS 出口 IP。</p>
        </article>
        <article class="block">
          <h2>WebRTC UDP 泄露检测</h2>
          <p class="big">${escapeHtml(udp?.badge ?? "无法判断")}</p>
          <p>UDP 出口：${escapeHtml(sameUdp ? (score.exit.ip ?? "—") : leaked ? leaked.detail : "没有解析出与边缘不同的公网地址")}</p>
          <p>归属地：${escapeHtml(udpPlace)}</p>
          <p class="src">${escapeHtml(udp?.note ?? "")}${input.udpHolder ? " 归属 ASN 来自 RIPEstat。" : ""}</p>
        </article>
      </section>

      <section class="block">
        <h2>用户设备信息</h2>
        <dl class="grid">${rows([
          { label: "时区", value: score.deviceHints.timezone, note: `${input.device.timezone} ${input.device.timezoneOffset}` },
          { label: "语言", value: score.deviceHints.language, note: score.deviceHints.languageNote },
          { label: "系统 / 浏览器", value: osAndBrowser(input.device.userAgent) },
          { label: "Cookie", value: input.device.cookieEnabled ? "已启用" : "未启用" },
          { label: "WebGL 渲染器", value: input.device.webglRenderer ?? "不可用" },
          { label: "Canvas 指纹", value: short(input.device.canvasHash) },
          { label: "WebGL 指纹", value: short(input.device.webglHash) },
        ])}</dl>
      </section>

      <section class="block">
        <h2>使用场景 / 类型</h2>
        <dl class="grid">${rows([
          { label: "IP 原生性", value: intel.broadcast.label, note: intel.broadcast.note },
          { label: "标记", value: mark(score) },
          { label: "运营商类型", value: operatorKind(score), note: "词表估计，不是 ASN 自报。" },
          { label: "人机流量", value: `人类 ${score.traffic.human}% · 机器 ${score.traffic.machine}%`, note: `${score.traffic.badge} · ${score.traffic.source}` },
        ])}</dl>
        <div class="meter traffic" aria-hidden="true"><span style="width:${score.traffic.human}%"></span></div>
        <div class="scenes">${scenes(score)}</div>
        <p class="src">场景分是 1–5 的估算，不是 TikTok 或 Claude 的官方准入。</p>
      </section>

      <section class="block">
        <h2>服务商 / ASN</h2>
        <dl class="grid">${rows([
          { label: "服务商", value: score.exit.asOrganization ?? intel.asn.registrant ?? "无法查询", note: "Cloudflare asOrganization；登记名来自 RDAP（若查到）。" },
          { label: "ASN", value: formatAsn(score.exit.asn) },
          { label: "ASN 归属", value: intel.asn.holder ?? intel.asn.registrant ?? score.exit.asOrganization ?? "无法查询" },
          { label: "ASN 自报类型", value: "无法查询", note: "公开 RDAP 通常不自报 Hosting/ISP。" },
          { label: "估计类型", value: operatorKind(score), note: "由组织名词表估计。" },
          { label: "IPv4 总量", value: intel.routing.state === "已查询" ? `${count(intel.routing.ipv4Addresses)} 个地址 / ${count(intel.routing.ipv4Prefixes)} 条前缀` : "无法查询", note: intel.routing.state === "已查询" ? "RIPEstat 宣告规模。" : "" },
          { label: "预估带宽", value: intel.bandwidth },
          { label: "注册日期", value: intel.asn.registered ?? intel.rdap.registered ?? "无法查询" },
          { label: "企业信息", value: intel.asn.registrant ?? intel.rdap.registrant ?? "无法查询" },
          { label: "网段", value: intel.rdap.range ?? intel.prefix ?? "无法查询", note: intel.rdap.name ? `RDAP ${intel.rdap.name}` : "" },
          { label: "登记类型", value: intel.rdap.type ?? "无法查询", note: "这是网段登记类型，不是 Hosting 标签。" },
        ])}</dl>
      </section>

      <section class="block">
        <h2>技术指标</h2>
        <dl class="grid">${rows([
          { label: "Bogon", value: intel.bogon ? "是" : "否", note: intel.bogonNote },
          { label: "广播", value: intel.broadcast.label, note: intel.broadcast.note },
          { label: "反向 DNS", value: intel.ptr.state === "有记录" ? (intel.ptr.value ?? "有记录") : intel.ptr.state },
        ])}</dl>
        <p><button type="button" id="port-stub">开放端口</button></p>
        <p id="port-result" class="src">不扫描端口。对访客或第三方地址做端口探测不在这次检查里。</p>
      </section>

      <section class="block">
        <h2>IP 情报</h2>
        <dl class="grid">${rows([
          { label: "风险标记", value: score.risk.band, note: score.risk.score === null ? "没有边缘数据，不给风险等级。" : `启发式风险 ${score.risk.score}。` },
          { label: "滥用等级", value: score.securityChecks.abuse.state, note: score.securityChecks.abuse.note },
          { label: "HTTP 蜜罐黑名单", value: intel.honeypot, note: "没有可用的免费蜜罐查询，不编造命中。" },
          { label: "RPKI", value: intel.rpki.state === "valid" ? "有效" : intel.rpki.state === "invalid" ? "无效" : intel.rpki.state === "unknown" ? "不确定" : "无法查询", note: intel.rpki.note },
        ])}</dl>
      </section>

      <section class="block">
        <h2>风险深度检测</h2>
        <div class="checks">${checks(score)}</div>
        <p class="src">VPN、代理、Tor 和爬虫都只看本次组织和浏览器字样。没有单独买情报库。</p>
      </section>

      <section class="history">
        <h2>历史</h2>
        <p class="badge">${escapeHtml(score.history.label)}</p>
        <p>${escapeHtml(score.history.note)} 本次会话第 ${input.session.runs} 次测量，只留在这个标签页。${input.session.ipChanges > 0 ? "出口 IP 有变化。" : input.session.runs > 1 ? "出口 IP 未变。" : ""}</p>
      </section>
    </div>`;
    document.querySelector("#port-stub")?.addEventListener("click", () => {
      const note = document.querySelector("#port-result");
      if (note) note.textContent = "没有发起端口扫描。结果保持为：不做这项检测。";
    });
  }

  const details = document.querySelector("#details");
  if (details) {
    const notes = score.notes.map((note) => `<li>${escapeHtml(note)}</li>`).join("");
    const mismatch =
      score.mismatches.length === 0
        ? `<p class="empty">这几组对照里没有明显矛盾。</p>`
        : score.mismatches
            .map((item) => `<article class="mismatch"><h3>${escapeHtml(item.label)}</h3><p>${escapeHtml(item.detail)}</p></article>`)
            .join("");
    details.innerHTML = `<details class="fold">
      <summary>评分依据</summary>
      <ul class="notes">${notes}</ul>
      <div class="mismatch-list">${mismatch}</div>
    </details>
    <details class="fold">
      <summary>信号明细</summary>
      <div class="split">
        <section><h2>观测到的</h2>${fieldsHtml(input.observed)}</section>
        <section><h2>声称的</h2>${fieldsHtml(input.claimed)}</section>
      </div>
    </details>`;
  }

  const raw = document.querySelector("#raw");
  if (raw) {
    raw.innerHTML = `<details class="fold"><summary>原始 JSON</summary><pre>${escapeHtml(JSON.stringify(input.raw, null, 2))}</pre></details>`;
  }
}

function fieldsHtml(fields: Field[]): string {
  const sections: string[] = [];
  for (const field of fields) {
    if (!sections.includes(field.section)) sections.push(field.section);
  }
  return sections
    .map((section) => {
      const body = fields
        .filter((field) => field.section === section)
        .map(
          (field) => `<article class="field"><h3>${escapeHtml(field.label)}</h3><p class="value">${escapeHtml(field.value)}</p><p class="source">${escapeHtml(field.source)}</p></article>`,
        )
        .join("");
      return `<h3 class="section-label">${escapeHtml(section)}</h3><div class="fields">${body}</div>`;
    })
    .join("");
}
