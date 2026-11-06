import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { AbuseRecord } from "../src/shared/history.ts";
import { scoreVisit, type ScoreInput, type ScoreResult, type SignalCard } from "../src/shared/score.ts";

function visit(overrides: {
  edge?: Partial<NonNullable<ScoreInput["edge"]>> | null;
  claimed?: Partial<ScoreInput["claimed"]>;
  observed?: Partial<ScoreInput["observed"]>;
  abuse?: AbuseRecord | null;
}): ScoreInput {
  const edge =
    overrides.edge === null
      ? null
      : {
          connectingIp: "203.0.113.10",
          country: "US",
          timezone: "America/New_York",
          asOrganization: "Comcast Cable Communications, LLC",
          asn: "7922",
          colo: "EWR",
          city: "New York",
          region: "New York",
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
      screenWidth: 1920,
      screenHeight: 1080,
      outerWidth: 1440,
      outerHeight: 900,
      webrtcGlobalIps: ["203.0.113.10"],
      webrtcCandidates: 1,
      webrtcError: null,
      webrtcMdns: false,
      canvasHash: "c".repeat(64),
      audioHash: "a".repeat(64),
      ...overrides.observed,
    },
    abuse: overrides.abuse ?? null,
  };
}

function signal(result: ScoreResult, id: SignalCard["id"]): SignalCard {
  const found = result.signals.find((item) => item.id === id);
  assert.ok(found);
  return found;
}

describe("scoreVisit", () => {
  it("scores a consistent residential exit as high trust", () => {
    const result = scoreVisit(visit({}));
    assert.equal(result.trust.score, 96);
    assert.equal(result.trust.band, "较高");
    assert.equal(result.purity.score, 92);
    assert.equal(result.purity.band, "高");
    assert.equal(result.risk.score, 0);
    assert.equal(result.risk.band, "低");
    assert.equal(result.attribute.label, "住宅");
    assert.equal(result.attribute.native, true);
    assert.equal(result.attribute.tag, "原生");
    assert.equal(result.history.label, "无历史库");
    assert.equal(signal(result, "dns").score, null);
    assert.equal(signal(result, "dns").badge, "不可得");
    assert.equal(signal(result, "udp").score, 96);
    assert.equal(signal(result, "timezone").score, 94);
    assert.equal(signal(result, "fingerprint").score, 100);
    assert.equal(signal(result, "security").score, 100);
    assert.deepEqual(
      result.signals.map((item) => item.id),
      ["dns", "udp", "timezone", "fingerprint", "security"],
    );
    assert.deepEqual(
      result.signals.map((item) => item.label),
      ["DNS", "UDP", "时区", "指纹", "安全性"],
    );
    assert.equal(result.mismatches.length, 0);
    assert.match(result.summary, /住宅/);
    assert.equal(result.exit.ip, "203.0.113.10");
    assert.equal(result.exit.asn, "7922");
    assert.equal(result.trust.headline, "良好");
    assert.equal(result.trust.detail, "主要信号整齐");
    assert.equal(result.regionSupport.state, "正常");
    assert.equal(result.scenes.ai.advice, "推荐");
    assert.equal(result.scenes.ai.score, 5);
    assert.equal(result.securityChecks.vpn.state, "未发现");
    assert.equal(result.securityChecks.abuse.state, "无法查询");
    assert.equal(result.traffic.badge, "人类为主");
    assert.equal(result.traffic.source, "估算");
  });

  it("does not punish a consistent mainland China residential exit in the trust score", () => {
    const us = scoreVisit(visit({}));
    const cn = scoreVisit(
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
    assert.equal(cn.trust.score, us.trust.score);
    assert.equal(cn.attribute.label, "住宅");
    assert.equal(cn.attribute.native, true);
    assert.equal(cn.purity.band, "高");
    assert.equal(cn.regionSupport.state, "受限");
    assert.equal(cn.scenes.ai.advice, "不推荐");
    assert.ok(cn.notes.some((note) => note.includes("不计入纯净度")));
    assert.equal(cn.summary.includes("无法"), false);
  });

  it("ignores Cloudflare colo when scoring", () => {
    const other = scoreVisit(visit({ edge: { colo: "LAX" } }));
    assert.equal(other.trust.score, 96);
    assert.equal(other.exit.colo, "LAX");
  });

  it("lowers purity and trust for a datacenter ASN", () => {
    const result = scoreVisit(visit({ edge: { asOrganization: "Amazon Technologies Inc." } }));
    assert.equal(result.attribute.label, "机房");
    assert.equal(result.attribute.kind, "datacenter");
    assert.equal(result.attribute.native, false);
    assert.equal(result.purity.score, 24);
    assert.equal(result.purity.band, "低");
    assert.equal(result.trust.score, 67);
    assert.equal(result.trust.band, "中等");
    assert.equal(result.risk.score, 32);
    assert.equal(result.risk.band, "中");
    assert.match(result.summary, /机房/);
    assert.equal(result.trust.headline, "良好");
    assert.equal(result.trust.detail, "该 IP 存在轻微风险");
    assert.equal(result.scenes.ai.advice, "不推荐");
    assert.equal(result.scenes.tiktok.score, 1);
  });

  it("lowers a VPN ASN further than a generic cloud ASN", () => {
    const cloud = scoreVisit(visit({ edge: { asOrganization: "Amazon Technologies Inc." } }));
    const vpn = scoreVisit(visit({ edge: { asOrganization: "Mullvad VPN AB" } }));
    assert.equal(vpn.attribute.label, "机房");
    assert.equal(vpn.attribute.tag, "VPN");
    assert.equal(vpn.purity.score, 12);
    assert.equal(vpn.trust.score, 54);
    assert.equal(vpn.risk.score, 44);
    assert.equal(vpn.securityChecks.vpn.state, "疑似");
    assert.ok(vpn.purity.score < cloud.purity.score);
    assert.ok(vpn.trust.score < cloud.trust.score);
  });

  it("treats an unclassified ISP name as native", () => {
    const result = scoreVisit(visit({ edge: { asOrganization: "Regional Telephone Cooperative" } }));
    assert.equal(result.attribute.label, "原生");
    assert.equal(result.attribute.kind, "native");
    assert.equal(result.purity.score, 74);
    assert.equal(result.purity.band, "中");
    assert.equal(result.trust.score, 90);
    assert.match(result.attribute.note, /RIR/);
  });

  it("keeps an IP with no ASN organization conservative", () => {
    const result = scoreVisit(visit({ edge: { asOrganization: "" } }));
    assert.equal(result.attribute.label, "未知");
    assert.equal(result.purity.score, 48);
    assert.equal(result.trust.score, 73);
    assert.equal(result.risk.band, "低");
  });

  it("drops trust when the browser timezone disagrees with the edge country", () => {
    const result = scoreVisit(visit({ claimed: { timezone: "Asia/Shanghai" } }));
    assert.equal(signal(result, "timezone").score, 28);
    assert.equal(signal(result, "timezone").badge, "偏差");
    assert.equal(result.attribute.label, "住宅");
    assert.equal(result.attribute.native, false);
    assert.equal(result.attribute.tag, null);
    assert.equal(result.purity.score, 82);
    assert.equal(result.trust.score, 69);
    assert.equal(result.risk.band, "中");
    assert.ok(result.mismatches.some((item) => item.label === "时区"));
  });

  it("caps trust when webdriver is set", () => {
    const result = scoreVisit(visit({ observed: { webdriver: true } }));
    assert.equal(signal(result, "security").score, 30);
    assert.equal(signal(result, "security").badge, "风险");
    assert.equal(result.trust.score, 30);
    assert.equal(result.trust.band, "较低");
    assert.equal(result.risk.score, 70);
    assert.equal(result.risk.band, "高");
    assert.match(result.summary, /自动化/);
    assert.equal(result.securityChecks.crawler.state, "疑似");
    assert.equal(result.traffic.badge, "机器偏多");
    assert.equal(result.traffic.human, 15);
  });

  it("caps trust for a headless user agent", () => {
    const result = scoreVisit(
      visit({
        claimed: {
          userAgent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/128.0.0.0 Safari/537.36",
        },
      }),
    );
    assert.equal(signal(result, "security").score, 30);
    assert.equal(result.trust.score, 30);
  });

  it("records a language mismatch without collapsing trust", () => {
    const result = scoreVisit(
      visit({
        claimed: { acceptLanguage: "zh-CN,zh;q=0.9", languages: ["en-US"] },
      }),
    );
    assert.equal(result.trust.score, 91);
    assert.equal(result.attribute.label, "住宅");
    assert.ok(result.mismatches.some((item) => item.label === "语言"));
    assert.equal(signal(result, "fingerprint").badge, "有差异");
  });

  it("drops trust when UA, Client Hints, and platform disagree", () => {
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
    assert.equal(signal(result, "fingerprint").score, 40);
    assert.equal(signal(result, "security").score, 70);
    assert.equal(result.trust.score, 69);
    assert.ok(result.mismatches.some((item) => item.label === "系统平台"));
  });

  it("flags a WebRTC address that differs from the exit IP", () => {
    const result = scoreVisit(visit({ observed: { webrtcGlobalIps: ["198.51.100.20"] } }));
    assert.equal(signal(result, "udp").score, 26);
    assert.equal(signal(result, "udp").badge, "不一致");
    assert.equal(result.trust.score, 64);
    assert.equal(result.purity.score, 78);
    assert.equal(result.risk.score, 36);
    assert.ok(result.mismatches.some((item) => item.label === "公网地址"));
    assert.equal(result.attribute.native, false);
  });

  it("does not call extra WebRTC addresses a full leak when the exit IP is present", () => {
    const result = scoreVisit(visit({ observed: { webrtcGlobalIps: ["203.0.113.10", "198.51.100.20"] } }));
    assert.equal(signal(result, "udp").score, 62);
    assert.equal(signal(result, "udp").badge, "部分");
    assert.equal(result.attribute.native, false);
    assert.equal(result.mismatches.some((item) => item.label === "公网地址"), false);
  });

  it("treats mDNS-only candidates as no public UDP leak", () => {
    const result = scoreVisit(
      visit({ observed: { webrtcGlobalIps: [], webrtcCandidates: 2, webrtcMdns: true } }),
    );
    assert.equal(signal(result, "udp").score, 76);
    assert.equal(signal(result, "udp").badge, "未泄漏");
    assert.match(signal(result, "udp").note, /mDNS/);
    assert.equal(result.attribute.native, true);
  });

  it("caps trust when edge geography is missing and does not invent risk", () => {
    const result = scoreVisit(visit({ edge: null }));
    assert.equal(result.trust.score, 59);
    assert.equal(result.trust.band, "偏低");
    assert.equal(result.attribute.label, "未知");
    assert.equal(result.risk.score, null);
    assert.equal(result.risk.band, "未知");
    assert.equal(result.history.label, "无历史库");
    assert.equal(signal(result, "dns").score, null);
    assert.match(result.summary, /边缘/);
  });

  it("marks Tor exits as datacenter anonymity, not a residential native path", () => {
    const result = scoreVisit(visit({ edge: { country: "T1", asOrganization: "Tor" } }));
    assert.equal(result.attribute.label, "机房");
    assert.equal(result.attribute.tag, "Tor");
    assert.equal(result.purity.score, 8);
    assert.equal(result.trust.score, 37);
    assert.equal(result.trust.band, "较低");
    assert.equal(result.risk.band, "高");
  });

  it("keeps a clean StopForumSpam miss separate from having no history database", () => {
    const result = scoreVisit(
      visit({
        abuse: { source: "stopforumspam", appears: false, frequency: 0, lastSeen: null, attempted: true },
      }),
    );
    assert.equal(result.history.label, "无公开记录");
    assert.equal(result.trust.score, 96);
    assert.equal(result.risk.score, 0);
    assert.equal(result.securityChecks.abuse.state, "无记录");
  });

  it("applies a real StopForumSpam hit without calling it a Claude record", () => {
    const result = scoreVisit(
      visit({
        abuse: {
          source: "stopforumspam",
          appears: true,
          frequency: 4,
          lastSeen: "2024-01-02 03:04:05",
          attempted: true,
        },
      }),
    );
    assert.equal(result.history.label, "有公开记录");
    assert.equal(result.history.frequency, 4);
    assert.match(result.history.note, /StopForumSpam/);
    assert.match(result.history.note, /不是 Claude/);
    assert.equal(result.trust.score, 84);
    assert.equal(result.risk.score, 32);
    assert.equal(result.risk.band, "中");
    assert.equal(result.securityChecks.abuse.state, "有公开记录");
  });

  it("leaves DNS unscored even when every other signal is present", () => {
    const result = scoreVisit(visit({}));
    assert.equal(signal(result, "dns").score, null);
    assert.match(signal(result, "dns").note, /解析器/);
    assert.ok(result.notes.some((note) => note.includes("DNS 缺测不计入")));
  });
});
