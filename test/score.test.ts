import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { scoreVisit, type ScoreInput } from "../src/shared/score.ts";

function visit(overrides: {
  edge?: Partial<NonNullable<ScoreInput["edge"]>> | null;
  claimed?: Partial<ScoreInput["claimed"]>;
  observed?: Partial<ScoreInput["observed"]>;
}): ScoreInput {
  const edge =
    overrides.edge === null
      ? null
      : {
          connectingIp: "203.0.113.10",
          country: "US",
          timezone: "America/New_York",
          asOrganization: "Comcast Cable Communications, LLC",
          colo: "EWR",
          city: "New York",
          ...overrides.edge,
        };
  return {
    edge,
    claimed: {
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
      chPlatform: "Windows",
      chMobile: false,
      acceptLanguage: "en-US,en;q=0.9",
      languages: ["en-US", "en"],
      timezone: "America/New_York",
      platform: "Win32",
      ...overrides.claimed,
    },
    observed: {
      webdriver: false,
      webglRenderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
      hardwareConcurrency: 8,
      maxTouchPoints: 0,
      screenWidth: 1920,
      screenHeight: 1080,
      outerWidth: 1440,
      outerHeight: 900,
      webrtcGlobalIps: ["203.0.113.10"],
      ...overrides.observed,
    },
  };
}

describe("scoreVisit", () => {
  it("rates a consistent residential US visit higher", () => {
    const result = scoreVisit(visit({}));
    assert.equal(result.outlook, "higher");
    assert.equal(result.headline, "偏高");
    assert.equal(result.mismatches.length, 0);
  });

  it("rates mainland China lower even on a residential network", () => {
    const result = scoreVisit(
      visit({
        edge: {
          country: "CN",
          timezone: "Asia/Shanghai",
          asOrganization: "China Telecom",
          city: "Shanghai",
          colo: "PVG",
        },
        claimed: { timezone: "Asia/Shanghai", acceptLanguage: "zh-CN,zh;q=0.9", languages: ["zh-CN", "zh"] },
      }),
    );
    assert.equal(result.outlook, "lower");
    assert.ok(result.reasons.some((reason) => reason.text.includes("中国大陆")));
  });

  it("rates a US cloud ASN as mixed", () => {
    const result = scoreVisit(
      visit({
        edge: { asOrganization: "Amazon Technologies Inc." },
      }),
    );
    assert.equal(result.outlook, "mixed");
    assert.ok(result.reasons.some((reason) => reason.text.includes("数据中心")));
  });

  it("downgrades when the browser timezone disagrees with the edge country", () => {
    const result = scoreVisit(visit({ claimed: { timezone: "Asia/Shanghai" } }));
    assert.equal(result.outlook, "mixed");
    assert.ok(result.reasons.some((reason) => reason.text.includes("时区")));
  });

  it("downgrades when webdriver is set", () => {
    const result = scoreVisit(visit({ observed: { webdriver: true } }));
    assert.equal(result.outlook, "mixed");
    assert.ok(result.reasons.some((reason) => reason.text.includes("webdriver")));
  });

  it("records a language mismatch without treating one mismatch as automation", () => {
    const result = scoreVisit(
      visit({
        claimed: { acceptLanguage: "zh-CN,zh;q=0.9", languages: ["en-US"] },
      }),
    );
    assert.equal(result.outlook, "higher");
    assert.ok(result.mismatches.some((item) => item.label === "语言"));
  });

  it("downgrades stacked client contradictions", () => {
    const result = scoreVisit(
      visit({
        claimed: {
          acceptLanguage: "zh-CN,zh;q=0.9",
          languages: ["en-US"],
          chPlatform: "macOS",
          platform: "MacIntel",
        },
      }),
    );
    assert.equal(result.outlook, "mixed");
    assert.ok(result.mismatches.some((item) => item.label === "系统平台"));
  });

  it("notes a WebRTC address that differs from the connecting IP", () => {
    const result = scoreVisit(visit({ observed: { webrtcGlobalIps: ["198.51.100.20"] } }));
    assert.ok(result.mismatches.some((item) => item.label === "公网地址"));
  });

  it("stays mixed when edge geography is missing", () => {
    const result = scoreVisit(visit({ edge: null }));
    assert.equal(result.outlook, "mixed");
    assert.ok(result.reasons.some((reason) => reason.text.includes("边缘")));
  });
});
