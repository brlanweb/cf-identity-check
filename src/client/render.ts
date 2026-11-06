import type { ScoreResult, SignalCard } from "../shared/score.ts";

export type Field = {
  section: string;
  label: string;
  value: string;
  source: string;
};

export type SessionMemo = {
  runs: number;
  ipChanges: number;
};

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatAsn(asn: string | null): string | null {
  if (!asn) return null;
  return /^[0-9]+$/.test(asn) ? `AS${asn}` : asn;
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

function radar(signals: SignalCard[]): string {
  const measured = signals.filter((signal) => signal.score !== null);
  const cx = 100;
  const cy = 100;
  const maxR = 62;
  const labelR = 84;
  const point = (index: number, total: number, radius: number): [number, number] => {
    const angle = -Math.PI / 2 + (index * 2 * Math.PI) / total;
    return [cx + radius * Math.cos(angle), cy + radius * Math.sin(angle)];
  };
  const rings = [0.35, 0.68, 1].map((scale) => {
    const pts = measured.map((_, index) => point(index, measured.length, maxR * scale).map((n) => n.toFixed(1)).join(","));
    return `<polygon class="radar-ring" points="${pts.join(" ")}"></polygon>`;
  });
  const spokes = measured.map((_, index) => {
    const [x, y] = point(index, measured.length, maxR);
    return `<line class="radar-spoke" x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}"></line>`;
  });
  const area = measured
    .map((signal, index) => point(index, measured.length, (maxR * (signal.score ?? 0)) / 100).map((n) => n.toFixed(1)).join(","))
    .join(" ");
  const dots = measured.map((signal, index) => {
    const [x, y] = point(index, measured.length, (maxR * (signal.score ?? 0)) / 100);
    return `<circle class="radar-dot" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3"></circle>`;
  });
  const short: Record<string, string> = { udp: "UDP", timezone: "时区", fingerprint: "指纹", security: "安全" };
  const labels = measured.map((signal, index) => {
    const [x, y] = point(index, measured.length, labelR);
    const text = `${short[signal.id] ?? signal.label} ${signal.score}`;
    return `<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" text-anchor="middle" dominant-baseline="middle">${escapeHtml(text)}</text>`;
  });
  const caption = measured.map((signal) => `${signal.label} ${signal.score}`).join("，");
  return `<svg class="radar" viewBox="-24 -18 248 236" role="img" aria-label="已测信号：${escapeHtml(caption)}。DNS 不可得。">
    ${rings.join("")}
    ${spokes.join("")}
    <polygon class="radar-area" points="${area}"></polygon>
    ${dots.join("")}
    ${labels.join("")}
  </svg>`;
}

function exitLine(exit: ScoreResult["exit"]): string {
  if (!exit.ip && exit.countryLabel === "未知" && !exit.city && !exit.asOrganization && !exit.asn && !exit.colo) {
    return "没有读到出口 IP";
  }
  const org = [formatAsn(exit.asn), exit.asOrganization].filter(Boolean).join(" ");
  const colo = exit.colo ? `边缘 ${exit.colo}` : "";
  const rest = [exit.countryLabel, exit.city, org, colo].filter((item): item is string => Boolean(item));
  const ip = exit.ip ? `<span class="exit-ip">${escapeHtml(exit.ip)}</span>` : "没有出口 IP";
  return rest.length ? `${ip} · ${rest.map((item) => escapeHtml(item)).join(" · ")}` : ip;
}

function signalCards(signals: SignalCard[]): string {
  return signals
    .map((signal) => {
      const value = signal.score === null ? "—" : String(signal.score);
      const width = signal.score === null ? 0 : signal.score;
      const empty = signal.score === null ? " is-empty" : "";
      return `<article class="signal tone-${signal.tone}" data-signal="${signal.id}">
        <h3>${escapeHtml(signal.label)}</h3>
        <p class="signal-score">${value}</p>
        <p class="badge tone-${signal.tone}">${escapeHtml(signal.badge)}</p>
        <span class="meter${empty}"><span style="width:${width}%"></span></span>
      </article>`;
    })
    .join("");
}

function sessionText(session: SessionMemo): string {
  const base = `本次会话第 ${session.runs} 次测量，只留在这个标签页。`;
  if (session.ipChanges > 0) return `${base}出口 IP 有变化。`;
  if (session.runs > 1) return `${base}出口 IP 未变。`;
  return base;
}

function historyTone(score: ScoreResult): string {
  if (score.history.appears) return "bad";
  if (score.history.label === "无公开记录") return "ok";
  return "neutral";
}

function fieldsHtml(fields: Field[]): string {
  const sections: string[] = [];
  for (const field of fields) {
    if (!sections.includes(field.section)) sections.push(field.section);
  }
  return sections
    .map((section) => {
      const rows = fields
        .filter((field) => field.section === section)
        .map(
          (field) => `<article class="field">
            <h3>${escapeHtml(field.label)}</h3>
            <p class="value">${escapeHtml(field.value)}</p>
            <p class="source">${escapeHtml(field.source)}</p>
          </article>`,
        )
        .join("");
      return `<h3 class="section-label">${escapeHtml(section)}</h3><div class="fields">${rows}</div>`;
    })
    .join("");
}

function mismatchesHtml(score: ScoreResult): string {
  if (score.mismatches.length === 0) return `<p class="empty">这几组对照里没有明显矛盾。</p>`;
  return score.mismatches
    .map(
      (item) => `<article class="mismatch severity-${item.severity}">
        <h3>${escapeHtml(item.label)}</h3>
        <p>${escapeHtml(item.detail)}</p>
      </article>`,
    )
    .join("");
}

export function renderPage(input: {
  status: string;
  score: ScoreResult;
  session: SessionMemo;
  observed: Field[];
  claimed: Field[];
  raw: unknown;
}): void {
  const status = document.querySelector("#status");
  if (status) status.textContent = input.status;

  const verdict = document.querySelector("#verdict");
  if (verdict) {
    const { score } = input;
    const riskValue = score.risk.score === null ? "—" : String(score.risk.score);
    const pill = score.attribute.tag ?? score.attribute.label;
    const pillClass = score.attribute.tag === "原生" ? "attr-native" : `attr-${score.attribute.kind}`;
    const riskAttr = score.risk.score === null ? "" : String(score.risk.score);
    verdict.innerHTML = `<section class="panel" data-trust="${score.trust.score}" data-purity="${score.purity.score}" data-risk="${riskAttr}" data-attribute="${score.attribute.kind}" data-native="${score.attribute.native ? "true" : "false"}" data-history="${escapeHtml(score.history.label)}">
      <div class="hero">
        <div class="trust tone-${score.trust.tone}">
          <div class="trust-gauge" role="img" aria-label="Claude AI Trust Score ${score.trust.score}，${score.trust.band}">
            ${dial(score.trust.score)}
            <div class="trust-face">
              <strong>${score.trust.score}</strong>
              <span>${score.trust.band}</span>
            </div>
          </div>
          <p class="trust-caption">Claude AI Trust Score</p>
        </div>
        <div class="hero-copy">
          <p class="exit">${exitLine(score.exit)}</p>
          <p class="summary">${escapeHtml(score.summary)}</p>
          <p class="fine">启发式估计，与 Anthropic 无关。</p>
          <div class="stats">
            <article class="stat tone-${score.purity.tone}">
              <h2>纯净度</h2>
              <strong>${score.purity.score}</strong>
              <p class="badge tone-${score.purity.tone}">${score.purity.band}</p>
            </article>
            <article class="stat tone-${score.risk.tone}">
              <h2>风险</h2>
              <strong>${riskValue}</strong>
              <p class="badge tone-${score.risk.tone}">${score.risk.band}</p>
            </article>
            <article class="stat attr-${score.attribute.kind}">
              <h2>属性</h2>
              <strong>${escapeHtml(score.attribute.label)}</strong>
              <p class="badge ${pillClass}">${escapeHtml(pill)}</p>
            </article>
          </div>
        </div>
      </div>
      <div class="board">
        <div class="radar-wrap">${radar(score.signals)}</div>
        <div class="cards">${signalCards(score.signals)}</div>
      </div>
      <section class="history">
        <h2>历史</h2>
        <p class="badge tone-${historyTone(score)}">${escapeHtml(score.history.label)}</p>
        <p>${escapeHtml(score.history.note)} ${escapeHtml(sessionText(input.session))}</p>
      </section>
    </section>`;
  }

  const details = document.querySelector("#details");
  if (details) {
    const notes = input.score.notes.map((note) => `<li>${escapeHtml(note)}</li>`).join("");
    details.innerHTML = `<details class="fold">
      <summary>评分依据</summary>
      <ul class="notes">${notes}</ul>
      <h3 class="section-label">差异</h3>
      <div class="mismatch-list">${mismatchesHtml(input.score)}</div>
    </details>
    <details class="fold">
      <summary>信号明细</summary>
      <div class="split">
        <section>
          <h2>观测到的</h2>
          ${fieldsHtml(input.observed)}
        </section>
        <section>
          <h2>声称的</h2>
          ${fieldsHtml(input.claimed)}
        </section>
      </div>
    </details>`;
  }

  const raw = document.querySelector("#raw");
  if (raw) {
    raw.innerHTML = `<details class="fold">
      <summary>原始 JSON</summary>
      <pre>${escapeHtml(JSON.stringify(input.raw, null, 2))}</pre>
    </details>`;
  }
}
