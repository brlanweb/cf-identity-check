import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { AbuseRecord } from "../src/shared/history.ts";
import { canonicalIp } from "../src/shared/ip.ts";
import { buildIpModel, presentedPlaces, presentedRisks, showRadar, type EchoHit } from "../src/shared/model.ts";
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

  it("hides secret gaps and keeps real misses", () => {
    const network = baseNetwork("x");
    const ip2 = network.places.find((place) => place.id === "ip2location");
    assert.ok(ip2);
    ip2.status = "未配置";
    network.risk.ip2location = { state: "未配置", isProxy: null, note: "未设置 IP2LOCATION_KEY。" };
    network.risk.ipapiIs = {
      state: "未配置",
      isVpn: null,
      isProxy: null,
      isTor: null,
      isDatacenter: null,
      isMobile: null,
      note: "未设置 IPAPI_IS_KEY。",
    };
    network.risk.proxycheck = { state: "无法查询", proxy: null, type: null, provider: null, note: "额度用完" };
    network.radar = { state: "未配置", human: null, bot: null, note: "未设置 CF_RADAR_TOKEN。" };
    const hidden = model(network, "1.1.1.1", "1.1.1.1");
    assert.equal(hidden.places.some((place) => place.id === "ip2location"), true);
    assert.equal(presentedPlaces(hidden.places).some((place) => place.id === "ip2location"), false);
    assert.equal(presentedRisks(hidden.risks).some((row) => row.value === "未配置"), false);
    assert.equal(presentedRisks(hidden.risks).some((row) => row.label === "proxycheck.io" && row.value === "无法查询"), true);
    network.risk.proxycheck = { state: "未配置", proxy: null, type: null, provider: null, note: "未设置 PROXYCHECK_KEY。" };
    const keyed = model(network, "1.1.1.1", "1.1.1.1");
    assert.equal(presentedRisks(keyed.risks).some((row) => row.label === "proxycheck.io"), false);
    network.risk.proxycheck = { state: "无法查询", proxy: null, type: null, provider: null, note: "额度用完" };
    assert.equal(presentedRisks(hidden.risks).some((row) => row.label === "欺诈黑名单"), true);
    assert.equal(showRadar(hidden.radar), false);
    assert.match(hidden.dnsNote, /权威域名/);

    network.radar = { state: "无法查询", human: null, bot: null, note: "Cloudflare Radar 没有返回。" };
    network.risk.ip2location = { state: "无法查询", isProxy: null, note: "IP2Location 拒绝了这次查询" };
    ip2.status = "无法查询";
    network.risk.ipapiIs = {
      state: "已查询",
      isVpn: null,
      isProxy: null,
      isTor: null,
      isDatacenter: null,
      isMobile: null,
      note: "这次响应没有风险字段。",
    };
    const visible = model(network, "1.1.1.1", "1.1.1.1");
    assert.equal(showRadar(visible.radar), true);
    assert.equal(presentedPlaces(visible.places).some((place) => place.id === "ip2location"), true);
    assert.equal(presentedRisks(visible.risks).some((row) => row.label === "IP2Location 代理" && row.value === "无法查询"), true);
    const ipapi = presentedRisks(visible.risks).find((row) => row.label === "ipapi.is 风险字段");
    assert.equal(ipapi?.value, "无法查询");
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
