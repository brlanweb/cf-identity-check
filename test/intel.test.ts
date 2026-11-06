import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { assembleIntel, broadcastLabel, isBogon, parsePtr, parseRdapIp, parseRpki, parseRouting } from "../src/shared/intel.ts";

describe("intel lookups", () => {
  it("flags documentation and private addresses as bogons", () => {
    assert.equal(isBogon("203.0.113.10"), true);
    assert.equal(isBogon("127.0.0.1"), true);
    assert.equal(isBogon("8.8.8.8"), false);
  });

  it("labels a registration country that differs from the edge as broadcast", () => {
    const label = broadcastLabel("JP", "US");
    assert.equal(label.label, "日本 IP / 广播 IP");
    assert.match(label.note, /美国/);
    assert.equal(broadcastLabel("US", "US").label, "美国 IP / 原生");
    assert.match(broadcastLabel("US", null).label, /无法判断/);
  });

  it("reads a PTR answer and treats a failed lookup as unavailable", () => {
    assert.deepEqual(parsePtr({ Answer: [{ type: 12, data: "dns.google." }] }), { state: "有记录", value: "dns.google" });
    assert.equal(parsePtr({ Status: 3 }).state, "无记录");
    assert.equal(parsePtr(null).state, "无法查询");
  });

  it("reads RDAP network fields without inventing a hosting type", () => {
    const rdap = parseRdapIp({
      objectClassName: "ip network",
      name: "GOGL",
      type: "DIRECT ALLOCATION",
      country: "US",
      startAddress: "8.8.8.0",
      endAddress: "8.8.8.255",
      events: [{ eventAction: "registration", eventDate: "2023-12-28T17:24:33-05:00" }],
      entities: [{ roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "Google LLC"]]] }],
    });
    assert.equal(rdap.state, "已查询");
    assert.equal(rdap.type, "DIRECT ALLOCATION");
    assert.equal(rdap.country, "US");
    assert.equal(rdap.registrant, "Google LLC");
    assert.equal(rdap.registered, "2023-12-28");
  });

  it("keeps RPKI and honeypot honest when the lookup is missing", () => {
    assert.equal(parseRpki(null, null).state, "无法查询");
    assert.equal(parseRpki({ data: { status: "valid" } }, "8.8.8.0/24").state, "valid");
    assert.equal(parseRouting(null).state, "无法查询");
    const intel = assembleIntel({
      ip: "8.8.8.8",
      edgeCountry: "US",
      ptrBody: null,
      rdapIp: null,
      rdapAsn: null,
      prefixBody: null,
      routingBody: null,
      rpkiBody: null,
    });
    assert.equal(intel.honeypot, "无法查询");
    assert.equal(intel.bandwidth, "无法查询");
    assert.equal(intel.rpki.state, "无法查询");
    assert.equal(intel.broadcast.label, "美国 IP / 无法判断");
  });
});
