import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  facilitySummary,
  facilityVotes,
  ipOrigin,
  parseBilibili,
  ipapiRiskFields,
  parseIpApi,
  parseIpinfo,
  parseIpip,
  parsePeeringDbWebsite,
  parseProxycheck,
  proxycheckReport,
  parseRadar,
  registrationCountry,
  toCountryCode,
} from "../src/shared/sources.ts";

describe("source parsers", () => {
  it("keeps each geo database's own place", () => {
    const ipApi = parseIpApi({
      status: "success",
      country: "United States",
      countryCode: "US",
      regionName: "Virginia",
      city: "Ashburn",
      lat: 39.03,
      lon: -77.5,
      timezone: "America/New_York",
      query: "8.8.8.8",
      hosting: true,
      proxy: false,
      mobile: false,
    });
    assert.equal(ipApi?.place.city, "Ashburn");
    assert.equal(ipApi?.hosting, true);
    assert.equal(ipApi?.proxy, false);

    const ipip = parseIpip({ ret: "ok", data: { ip: "1.2.3.4", location: ["美国", "弗吉尼亚州", "阿什本", "", "amazon.com"] } });
    assert.equal(ipip?.countryCode, "US");
    assert.equal(ipip?.city, "阿什本");
    assert.match(ipip?.note ?? "", /浏览器直连/);

    const bili = parseBilibili({
      code: 0,
      data: { addr: "216.246.215.107", country: "美国", province: "德克萨斯州", city: "达拉斯", latitude: "32.78183", longitude: "-96.79586" },
    });
    assert.equal(bili?.countryCode, "US");
    assert.equal(bili?.city, "达拉斯");
    assert.equal(bili?.latitude, 32.78183);

    const odd = parseBilibili({ code: 0, data: { addr: "8.8.8.8", country: "GOOGLE.COM", province: "GOOGLE.COM", city: "" } });
    assert.equal(odd?.countryCode, null);
    assert.match(odd?.note ?? "", /不像国家名/);

    const info = parseIpinfo({ ip: "8.8.8.8", city: "Mountain View", region: "California", country: "US", loc: "37.4056,-122.0775", timezone: "America/Los_Angeles", anycast: true }, "ipinfo");
    assert.equal(info?.city, "Mountain View");
    assert.equal(info?.latitude, 37.4056);
    assert.match(info?.note ?? "", /anycast/);
    assert.equal(toCountryCode("日本"), "JP");
  });

  it("does not invent a facility when sources disagree or stay silent", () => {
    const votes = facilityVotes({
      ipApiHosting: true,
      ipApiMobile: false,
      ipapiIsDatacenter: null,
      ipapiIsMobile: null,
      residential: true,
      mobile: false,
    });
    assert.equal(facilitySummary(votes, false).label, "不一致");
    assert.equal(facilitySummary([], true).label, "无法查询");
    assert.match(facilitySummary([], true).note, /不够标成住宅/);
  });

  it("reads proxycheck, radar, peeringdb, and RDAP registration country", () => {
    const proxy = parseProxycheck({ status: "ok", "8.8.8.8": { proxy: "no", type: "Business", provider: "Google LLC" } }, "8.8.8.8");
    assert.equal(proxy.proxy, false);
    assert.equal(proxy.type, "Business");
    const useful = proxycheckReport({
      body: { status: "ok", "1.1.1.1": { proxy: "no", type: "Wireless" } },
      ip: "1.1.1.1",
      hasKey: false,
      failureNote: "失败",
    });
    assert.equal(useful.state, "已查询");
    assert.equal(useful.type, "Wireless");
    const needsKey = proxycheckReport({
      body: { status: "error", message: "API key required" },
      ip: "1.1.1.1",
      hasKey: false,
      failureNote: "失败",
    });
    assert.equal(needsKey.state, "未配置");
    const quota = proxycheckReport({
      body: { status: "denied", message: "Daily query limit exceeded" },
      ip: "1.1.1.1",
      hasKey: false,
      failureNote: "失败",
    });
    assert.equal(quota.state, "无法查询");
    const transport = proxycheckReport({ body: null, ip: "1.1.1.1", hasKey: false, failureNote: "超时" });
    assert.equal(transport.state, "无法查询");
    assert.equal(transport.note, "超时");
    const keyedMiss = proxycheckReport({
      body: { status: "error", message: "API key required" },
      ip: "1.1.1.1",
      hasKey: true,
      failureNote: "失败",
    });
    assert.equal(keyedMiss.state, "无法查询");

    const radar = parseRadar({ success: true, result: { summary_0: { human: "25.54", bot: "74.46" } } });
    assert.deepEqual({ human: radar?.human, bot: radar?.bot }, { human: 25.54, bot: 74.46 });
    const fraction = parseRadar({ success: true, result: { summary_0: { human: "0.2554", bot: "0.7446" } } });
    assert.equal(fraction?.human, 25.54);
    const denied = parseRadar({ success: false, errors: [{ message: "Invalid API Token" }] });
    assert.match(denied?.note ?? "", /拒绝了 CF_RADAR_TOKEN/);

    assert.equal(parsePeeringDbWebsite({ data: [{ website: "https://code200.global/path" }] }), "code200.global");

    const network = registrationCountry({ country: "us", entities: [] });
    assert.equal(network?.code, "US");
    assert.match(network?.source ?? "", /network.country/);
    const address = registrationCountry({
      entities: [{ roles: ["registrant"], vcardArray: ["vcard", [["adr", { label: "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States" }, "text", []]]] }],
    });
    assert.equal(address?.code, "US");
    assert.match(address?.source ?? "", /登记地址/);
    assert.equal(ipOrigin("US", [{ source: "Cloudflare", countryCode: "JP" }]).label, "广播IP");
    assert.equal(ipOrigin("US", [{ source: "Cloudflare", countryCode: "US" }, { source: "IPIP", countryCode: "US" }]).label, "原生IP");
    assert.equal(ipOrigin(null, [{ source: "Cloudflare", countryCode: "US" }]).label, "无法判断");

    const geo = {
      place: {
        id: "ipapi-is" as const,
        status: "已查询" as const,
        ip: "8.8.8.8",
        countryCode: "US",
        country: "United States",
        region: null,
        city: "Ashburn",
        latitude: null,
        longitude: null,
        timezone: null,
        note: "按边缘 IP 查询。这次响应没有 is_vpn / is_datacenter 等风险字段。",
      },
      isVpn: null,
      isProxy: null,
      isTor: null,
      isDatacenter: null,
      isMobile: null,
    };
    assert.equal(ipapiRiskFields({ parsed: geo, hasKey: false, failureNote: "失败" }).state, "未配置");
    assert.equal(ipapiRiskFields({ parsed: { ...geo, isVpn: false }, hasKey: false, failureNote: "失败" }).state, "已查询");
    assert.equal(ipapiRiskFields({ parsed: geo, hasKey: true, failureNote: "失败" }).state, "已查询");
    assert.equal(ipapiRiskFields({ parsed: null, hasKey: false, failureNote: "失败" }).state, "无法查询");
    assert.equal(
      ipapiRiskFields({ parsed: { ...geo, place: { ...geo.place, status: "无法查询" } }, hasKey: false, failureNote: "失败" }).state,
      "无法查询",
    );
  });
});
