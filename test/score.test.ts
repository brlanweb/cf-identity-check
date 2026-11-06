import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { scoreVisit, type ScoreInput, type ScoreResult } from "../src/shared/score.ts";

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

function risk(result: ScoreResult, id: "spoof" | "fraud") {
  const found = result.risks.find((item) => item.id === id);
  assert.ok(found);
  return found;
}

describe("scoreVisit", () => {
  it("rates a consistent residential US visit higher", () => {
    const result = scoreVisit(visit({}));
    assert.equal(result.outlook, "higher");
    assert.equal(result.headline, "偏高");
    assert.equal(result.mismatches.length, 0);
    assert.deepEqual(
      result.services.map((group) => group.id),
      ["ai", "media"],
    );
    const names = result.services.flatMap((group) => group.services.map((service) => service.name));
    assert.deepEqual(names, [
      "Claude",
      "ChatGPT",
      "Gemini",
      "Grok",
      "Perplexity",
      "Copilot",
      "Poe",
      "Midjourney",
      "YouTube",
      "Netflix",
      "Disney+",
      "Spotify",
      "Twitch",
      "Google 服务",
    ]);
    assert.ok(result.services.every((group) => group.services.every((service) => service.status === "ok")));
    assert.equal(result.glances.find((item) => item.id === "network")?.value, "住宅宽带");
    assert.deepEqual(
      result.risks.map((item) => item.label),
      ["伪装度", "欺诈分"],
    );
    assert.equal(risk(result, "spoof").status, "低");
    assert.equal(risk(result, "fraud").status, "低");
    assert.ok(risk(result, "spoof").score < 30);
    assert.ok(risk(result, "fraud").score < 30);
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
    const services = result.services.flatMap((group) => group.services);
    assert.ok(services.every((service) => service.status === "friction"));
    assert.ok(services.find((service) => service.name === "YouTube")?.reason.includes("中国大陆"));
    assert.ok(services.find((service) => service.name === "ChatGPT")?.reason.includes("中国大陆"));
    assert.equal(result.glances.find((item) => item.id === "country")?.tone, "bad");
    assert.equal(risk(result, "spoof").score, 0);
    assert.equal(risk(result, "fraud").score, 0);
  });

  it("rates a US cloud ASN as mixed", () => {
    const result = scoreVisit(
      visit({
        edge: { asOrganization: "Amazon Technologies Inc." },
      }),
    );
    assert.equal(result.outlook, "mixed");
    assert.ok(result.reasons.some((reason) => reason.text.includes("数据中心")));
    const services = result.services.flatMap((group) => group.services);
    const status = (name: string) => services.find((service) => service.name === name)?.status;
    assert.equal(status("Claude"), "friction");
    assert.equal(status("ChatGPT"), "friction");
    assert.equal(status("Netflix"), "friction");
    assert.equal(status("Disney+"), "friction");
    assert.equal(status("Gemini"), "uncertain");
    assert.equal(status("Spotify"), "uncertain");
    assert.equal(status("YouTube"), "ok");
    assert.equal(status("Google 服务"), "ok");
    assert.match(services.find((service) => service.name === "YouTube")?.reason ?? "", /数据中心/);
    assert.equal(risk(result, "spoof").status, "中");
    assert.equal(risk(result, "fraud").status, "低");
    assert.ok(risk(result, "fraud").score < risk(result, "spoof").score);
  });

  it("downgrades when the browser timezone disagrees with the edge country", () => {
    const result = scoreVisit(visit({ claimed: { timezone: "Asia/Shanghai" } }));
    assert.equal(result.outlook, "mixed");
    assert.ok(result.reasons.some((reason) => reason.text.includes("时区")));
    assert.equal(risk(result, "spoof").status, "中");
    assert.equal(risk(result, "fraud").status, "低");
  });

  it("downgrades when webdriver is set", () => {
    const result = scoreVisit(visit({ observed: { webdriver: true } }));
    assert.equal(result.outlook, "mixed");
    assert.ok(result.reasons.some((reason) => reason.text.includes("webdriver")));
    assert.equal(risk(result, "fraud").status, "高");
    assert.ok(risk(result, "fraud").score >= 60);
    assert.equal(risk(result, "spoof").status, "低");
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
    assert.equal(risk(result, "spoof").score, 20);
    assert.equal(risk(result, "fraud").score, 10);
  });

  it("stays mixed when edge geography is missing", () => {
    const result = scoreVisit(visit({ edge: null }));
    assert.equal(result.outlook, "mixed");
    assert.ok(result.reasons.some((reason) => reason.text.includes("边缘")));
    assert.ok(result.services.every((group) => group.services.every((service) => service.status === "uncertain")));
  });

  it("splits services that are not on the same static list", () => {
    const result = scoreVisit(
      visit({
        edge: {
          country: "NG",
          timezone: "Africa/Lagos",
          asOrganization: "Spectranet broadband",
          city: "Lagos",
          colo: "LOS",
        },
        claimed: { timezone: "Africa/Lagos" },
      }),
    );
    const services = result.services.flatMap((group) => group.services);
    const status = (name: string) => services.find((service) => service.name === name);
    assert.equal(status("YouTube")?.status, "ok");
    assert.equal(status("ChatGPT")?.status, "ok");
    assert.equal(status("Netflix")?.status, "ok");
    assert.equal(status("Claude")?.status, "uncertain");
    assert.match(status("Claude")?.reason ?? "", /清单/);
    assert.equal(status("Disney+")?.status, "uncertain");
  });

  it("marks Tor exits as higher friction across the matrix", () => {
    const result = scoreVisit(visit({ edge: { country: "T1", asOrganization: "Tor" } }));
    assert.equal(result.outlook, "lower");
    assert.ok(result.services.every((group) => group.services.every((service) => service.status === "friction")));
    assert.equal(risk(result, "spoof").status, "中");
    assert.equal(risk(result, "fraud").status, "高");
  });

  it("does not treat a filtered region as fully blocked for every service", () => {
    const result = scoreVisit(
      visit({
        edge: {
          country: "IR",
          timezone: "Asia/Tehran",
          asOrganization: "Iran broadband",
          city: "Tehran",
          colo: "THR",
        },
        claimed: { timezone: "Asia/Tehran" },
      }),
    );
    const services = result.services.flatMap((group) => group.services);
    const status = (name: string) => services.find((service) => service.name === name)?.status;
    assert.equal(status("YouTube"), "friction");
    assert.equal(status("ChatGPT"), "friction");
    assert.equal(status("Netflix"), "uncertain");
    assert.equal(status("Google 服务"), "uncertain");
  });
});
