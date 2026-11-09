import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { AbuseRecord } from "../src/shared/history.ts";
import { canonicalIp } from "../src/shared/ip.ts";
import { buildIpModel, type EchoHit } from "../src/shared/model.ts";
import { baseNetwork, type NetworkReport } from "../src/shared/report.ts";
import { unavailablePlace, type GeoPlace } from "../src/shared/sources.ts";

const ABUSE: AbuseRecord = { source: "none", appears: null, frequency: null, lastSeen: null, attempted: false };

function echoes(v4: string | null, v6: string | null): EchoHit[] {
  const v4canon = canonicalIp(v4);
  const v6canon = v6 ? canonicalIp(v6) : null;
  return [
    { name: "ipify", family: "v4", ip: v4, canonical: v4canon, error: v4 ? null : "没有连上" },
    { name: "ident.me", family: "v4", ip: v4, canonical: v4canon, error: v4 ? null : "没有连上" },
    { name: "ipify", family: "v6", ip: v6, canonical: v6canon, error: v6 ? null : "没有连上" },
    { name: "ident.me", family: "v6", ip: v6, canonical: v6canon, error: v6 ? null : "没有连上" },
  ];
}

function direct(): { ipinfo: GeoPlace; ipip: GeoPlace } {
  return { ipinfo: unavailablePlace("ipinfo-direct", "没有"), ipip: unavailablePlace("ipip", "没有") };
}

function model(network: NetworkReport | null, edgeIp: string | null, v4: string | null, v6: string | null = null) {
  return buildIpModel({
    network,
    echoes: echoes(v4, v6),
    direct: direct(),
    edge: { ip: edgeIp, timezone: "America/Los_Angeles", country: "US", colo: "SJC" },
    browserTimezone: "America/Los_Angeles",
    webrtcCandidates: [],
    webrtcError: null,
    abuse: ABUSE,
  });
}

describe("exit comparison", () => {
  it("flags a same-family difference and leaves dual-stack alone", () => {
    const split = model(baseNetwork("x"), "1.1.1.1", "2.2.2.2");
    assert.equal(split.headlineIp, "1.1.1.1");
    assert.equal(split.headlineSource, "CF-Connecting-IP");
    assert.equal(split.stackLabel, "IPv4 Only");
    assert.match(split.routingBanner ?? "", /2\.2\.2\.2/);

    const dual = model(baseNetwork("x"), "1.1.1.1", "1.1.1.1", "2606:4700:4700::1111");
    assert.equal(dual.stackLabel, "双栈");
    assert.equal(dual.routingBanner, null);
    assert.match(dual.stackNote, /IPv4/);
  });

  it("calls registration and geolocation disagreement 广播IP", () => {
    const network = baseNetwork("");
    network.skipReason = null;
    network.identity.registeredCountry = "JP";
    network.identity.registeredCountrySource = "RDAP network.country";
    network.places[0] = {
      id: "cloudflare",
      status: "已查询",
      ip: "1.1.1.1",
      countryCode: "US",
      country: "United States",
      region: "California",
      city: "Los Angeles",
      latitude: 34.05,
      longitude: -118.24,
      timezone: "America/Los_Angeles",
      note: "request.cf",
    };
    const page = model(network, "1.1.1.1", "1.1.1.1");
    assert.equal(page.origin.label, "广播IP");
    assert.equal(page.places[0]?.agreement, "不同");
    assert.equal(page.map?.source, "Cloudflare");
  });

  it("does not score a private edge address as a split route", () => {
    const page = model(baseNetwork("边缘地址不是公网，没有向外部数据源查询。"), "127.0.0.1", "8.8.8.8");
    assert.equal(page.edgePublic, false);
    assert.equal(page.headlineIp, "8.8.8.8");
    assert.equal(page.headlineSource, "浏览器回显");
    assert.equal(page.routingBanner, null);
    assert.equal(page.purity.score, null);
  });
});
