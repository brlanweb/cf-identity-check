import type { Axis, RiskScore, ScoreResult } from "../shared/score.ts";
import { STATUS_LABEL, type ServiceStatus } from "../shared/services.ts";

export type Field = {
  section: string;
  label: string;
  value: string;
  source: string;
};

const RING_LABEL: Record<string, string> = {
  network: "住宅",
  geo: "地理",
  client: "客户端",
  automation: "干净",
};

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function goodness(axis: Axis): number {
  const raw = axis.id === "automation" ? 100 - axis.score : axis.score;
  return Math.max(0, Math.min(100, Math.round(raw)));
}

function toneFor(score: number): RiskScore["tone"] {
  if (score >= 75) return "ok";
  if (score >= 50) return "warn";
  return "bad";
}

function dial(score: number, tone: RiskScore["tone"], label: string): string {
  const radius = 48;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - score / 100);
  return `<svg class="dial tone-${tone}" viewBox="0 0 120 120" role="img" aria-label="${escapeHtml(label)} ${score}">
    <circle class="dial-track" cx="60" cy="60" r="${radius}"></circle>
    <circle class="dial-value" cx="60" cy="60" r="${radius}" stroke-dasharray="${circumference.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}"></circle>
    <text class="dial-num" x="60" y="68" text-anchor="middle">${score}</text>
  </svg>`;
}

function miniDial(score: number, tone: RiskScore["tone"], label: string): string {
  const radius = 16;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - score / 100);
  return `<svg class="mini tone-${tone}" viewBox="0 0 40 40" aria-hidden="true">
    <circle class="dial-track" cx="20" cy="20" r="${radius}"></circle>
    <circle class="dial-value" cx="20" cy="20" r="${radius}" stroke-dasharray="${circumference.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}"></circle>
  </svg><span class="sr-only">${escapeHtml(label)} ${score}</span>`;
}

function statusGlyph(status: ServiceStatus): string {
  if (status === "ok") {
    return `<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3.2 8.2 6.4 11.2 12.8 4.6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"></path></svg>`;
  }
  if (status === "uncertain") {
    return `<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 8h8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"></path></svg>`;
  }
  return `<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4.2 4.2 11.8 11.8M11.8 4.2 4.2 11.8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"></path></svg>`;
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

function risksHtml(risks: RiskScore[]): string {
  return risks
    .map(
      (risk) => `<article class="score-card tone-${risk.tone}" data-risk="${risk.id}">
        <h2>${escapeHtml(risk.label)}</h2>
        ${dial(risk.score, risk.tone, `${risk.label} ${risk.status}`)}
        <p class="badge tone-${risk.tone}">${escapeHtml(risk.status)}</p>
      </article>`,
    )
    .join("");
}

function axesHtml(axes: Axis[]): string {
  return axes
    .map((axis) => {
      const score = goodness(axis);
      const label = RING_LABEL[axis.id] ?? axis.label;
      return `<article class="axis" title="${escapeHtml(axis.note)}">
        ${miniDial(score, toneFor(score), label)}
        <strong>${score}</strong>
        <span>${escapeHtml(label)}</span>
        <p class="sr-only">${escapeHtml(axis.note)}</p>
      </article>`;
    })
    .join("");
}

function matrixHtml(score: ScoreResult): string {
  return score.services
    .map((group) => {
      const chips = group.services
        .map(
          (service) => `<article class="chip status-${service.status}" data-service="${escapeHtml(service.id)}" data-status="${service.status}">
            <span class="chip-mark" aria-hidden="true">${escapeHtml(service.mark)}</span>
            <div class="chip-body">
              <div class="chip-top">
                <h3>${escapeHtml(service.name)}</h3>
                <span class="badge status-${service.status}">${statusGlyph(service.status)}${STATUS_LABEL[service.status]}</span>
              </div>
              <p>${escapeHtml(service.reason)}</p>
            </div>
          </article>`,
        )
        .join("");
      return `<section class="group" data-group="${group.id}">
        <h2>${escapeHtml(group.label)}</h2>
        <div class="chips">${chips}</div>
      </section>`;
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
  edgeError: string | null;
  score: ScoreResult;
  observed: Field[];
  claimed: Field[];
  raw: unknown;
}): void {
  const status = document.querySelector("#status");
  if (status) status.textContent = input.status;

  const verdict = document.querySelector("#verdict");
  if (verdict) {
    verdict.innerHTML = `<div class="scoreboard">${risksHtml(input.score.risks)}</div>
      <div class="axis-row">${axesHtml(input.score.axes)}</div>
      <div class="matrix">${matrixHtml(input.score)}</div>`;
  }

  const details = document.querySelector("#details");
  if (details) {
    details.innerHTML = `<details class="fold">
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
      <h2 class="fold-heading">差异</h2>
      <div class="mismatch-list">${mismatchesHtml(input.score)}</div>
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
