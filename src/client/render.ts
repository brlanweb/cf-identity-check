import type { ScoreResult } from "../shared/score.ts";

export type Field = {
  section: string;
  label: string;
  value: string;
  source: string;
};

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
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

function meter(score: number, tone: string): string {
  const width = Math.max(0, Math.min(100, score));
  return `<div class="meter ${tone}" aria-hidden="true"><span style="width:${width}%"></span></div>`;
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
    const reasons = input.score.reasons
      .map((reason) => `<li class="tone-${reason.tone}">${escapeHtml(reason.text)}</li>`)
      .join("");
    const axes = input.score.axes
      .map(
        (axis) => `<article class="axis">
          <div class="axis-top"><h3>${escapeHtml(axis.label)}</h3><strong>${axis.score}</strong></div>
          ${meter(axis.score, axis.id === "automation" ? "meter-risk" : "meter-good")}
          <p>${escapeHtml(axis.note)}</p>
        </article>`,
      )
      .join("");
    verdict.innerHTML = `<div class="verdict outlook-${input.score.outlook}">
      <p class="eyebrow">启发式展望 · YouTube / Claude</p>
      <p class="headline">${escapeHtml(input.score.headline)}</p>
      <p class="summary">${escapeHtml(input.score.summary)}</p>
      ${input.edgeError ? `<p class="edge-error">${escapeHtml(input.edgeError)}</p>` : ""}
      <div class="axes">${axes}</div>
      <ul class="reasons">${reasons}</ul>
    </div>`;
  }

  const observed = document.querySelector("#observed");
  if (observed) {
    observed.innerHTML = `<h2>观测到的</h2><p class="column-note">边缘网络测量，以及浏览器里比较难单独伪造一致的读数。</p>${fieldsHtml(input.observed)}`;
  }
  const claimed = document.querySelector("#claimed");
  if (claimed) {
    claimed.innerHTML = `<h2>声称的</h2><p class="column-note">User-Agent、Client Hints、Accept-Language、时区，以及脚本能读到的同类字段。</p>${fieldsHtml(input.claimed)}`;
  }

  const mismatches = document.querySelector("#mismatches");
  if (mismatches) {
    if (input.score.mismatches.length === 0) {
      mismatches.innerHTML = `<h2>差异</h2><p class="empty">这几组对照里没有明显矛盾。</p>`;
    } else {
      const rows = input.score.mismatches
        .map(
          (item) => `<article class="mismatch severity-${item.severity}">
            <h3>${escapeHtml(item.label)}</h3>
            <p>${escapeHtml(item.detail)}</p>
            <dl>
              <div><dt>声称</dt><dd>${escapeHtml(item.claimed)}</dd></div>
              <div><dt>观测</dt><dd>${escapeHtml(item.observed)}</dd></div>
            </dl>
          </article>`,
        )
        .join("");
      mismatches.innerHTML = `<h2>差异</h2><div class="mismatch-list">${rows}</div>`;
    }
  }

  const raw = document.querySelector("#raw");
  if (raw) {
    raw.innerHTML = `<details>
      <summary>原始 JSON</summary>
      <pre>${escapeHtml(JSON.stringify(input.raw, null, 2))}</pre>
    </details>`;
  }
}
