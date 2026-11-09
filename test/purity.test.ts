import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { purityLabel, purityScore, type PurityInput } from "../src/shared/purity.ts";

function input(partial: Partial<PurityInput>): PurityInput {
  return {
    tor: "unknown",
    torDetail: "tor",
    vpn: "unknown",
    vpnDetail: "vpn",
    proxy: "unknown",
    proxyDetail: "proxy",
    ipApiProxy: "unknown",
    ipApiProxyDetail: "ip-api",
    datacenter: "unknown",
    datacenterDetail: "dc",
    mobile: "unknown",
    mobileDetail: "mobile",
    broadcast: "unknown",
    broadcastDetail: "broadcast",
    abuse: "unknown",
    abuseDetail: "abuse",
    abuseHeavy: false,
    webrtcLeak: "unknown",
    webrtcDetail: "webrtc",
    timezone: "unknown",
    timezoneDetail: "tz",
    split: "unknown",
    splitDetail: "split",
    ...partial,
  };
}

describe("purity score", () => {
  it("uses the tick bands from 极度纯净 through 极度风险", () => {
    assert.equal(purityLabel(0), "极度纯净");
    assert.equal(purityLabel(14), "极度纯净");
    assert.equal(purityLabel(15), "纯净");
    assert.equal(purityLabel(24), "纯净");
    assert.equal(purityLabel(25), "一般");
    assert.equal(purityLabel(39), "一般");
    assert.equal(purityLabel(40), "轻微风险");
    assert.equal(purityLabel(49), "轻微风险");
    assert.equal(purityLabel(50), "高风险");
    assert.equal(purityLabel(69), "高风险");
    assert.equal(purityLabel(70), "极度风险");
    assert.equal(purityLabel(100), "极度风险");
  });

  it("does not turn a missing Tor list into a clean score", () => {
    assert.equal(purityScore(input({})).score, null);
    assert.equal(purityScore(input({ tor: "no" })).score, null);
    assert.equal(purityScore(input({ tor: "no" })).label, "无法计算");
  });

  it("adds only the signals that were actually returned", () => {
    const datacenter = purityScore(input({ datacenter: "yes", ipApiProxy: "no", tor: "no" }));
    assert.equal(datacenter.score, 18);
    assert.equal(datacenter.label, "纯净");

    const vpn = purityScore(input({ vpn: "yes" }));
    assert.equal(vpn.score, 40);
    assert.equal(vpn.label, "轻微风险");

    const merged = purityScore(input({ ipApiProxy: "yes", datacenter: "yes", tor: "no" }));
    assert.equal(merged.score, 30);
    assert.equal(merged.label, "一般");

    const tor = purityScore(input({ tor: "yes", datacenter: "yes", vpn: "yes" }));
    assert.equal(tor.score, 73);
    assert.equal(tor.label, "极度风险");
    assert.equal(tor.lines.find((line) => line.label === "VPN")?.points, null);
  });

  it("caps the sum at 100", () => {
    const result = purityScore(input({
      tor: "yes",
      datacenter: "yes",
      broadcast: "broadcast",
      abuse: "hit",
      abuseHeavy: true,
      webrtcLeak: "yes",
      timezone: "yes",
      split: "yes",
    }));
    assert.equal(result.score, 100);
    assert.equal(result.label, "极度风险");
  });
});
