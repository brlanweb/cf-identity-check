import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { canonicalIp, classifyAddress, parseIceCandidate, sameIp } from "../src/shared/ip.ts";
import { torListHas } from "../src/shared/sources.ts";

describe("IP canonical form", () => {
  it("treats compressed IPv6 spellings as the same address", () => {
    assert.equal(canonicalIp("2001:DB8::1"), "2001:db8:0:0:0:0:0:1");
    assert.equal(sameIp("2001:db8:0:0:0:0:0:1", "2001:0db8::1"), true);
    assert.equal(canonicalIp("8.8.8.8"), "8.8.8.8");
    assert.equal(canonicalIp("::ffff:8.8.8.8"), "8.8.8.8");
    assert.equal(canonicalIp("not-an-ip"), null);
  });

  it("separates public, private, CGNAT, mDNS, and relay candidates", () => {
    assert.equal(classifyAddress("8.8.8.8"), "public");
    assert.equal(classifyAddress("192.168.1.1"), "private");
    assert.equal(classifyAddress("100.64.1.1"), "cgnat");
    assert.equal(classifyAddress("203.0.113.8"), "private");
    assert.equal(classifyAddress("2001:db8::1"), "private");
    assert.equal(classifyAddress("2606:4700:4700::1111"), "public");
    assert.deepEqual(parseIceCandidate("candidate:1 1 udp 1 8.8.8.8 9 typ srflx"), { ip: "8.8.8.8", kind: "public", typ: "srflx" });
    assert.equal(parseIceCandidate("candidate:1 1 udp 1 100.64.0.5 9 typ host").kind, "cgnat");
    assert.equal(parseIceCandidate("candidate:1 1 udp 1 abcd.local 9 typ host").kind, "mdns");
    assert.equal(parseIceCandidate("candidate:1 1 udp 1 1.2.3.4 9 typ relay").kind, "relay");
  });

  it("matches Tor exit lines exactly", () => {
    const list = "1.2.3.4\n8.8.8.8\n2001:db8::2\n";
    assert.equal(torListHas(list, "8.8.8.8"), true);
    assert.equal(torListHas(list, "1.2.3.40"), false);
    assert.equal(torListHas(list, "2001:0db8:0:0:0:0:0:2"), true);
    assert.equal(torListHas("<html>8.8.8.8</html>", "8.8.8.8"), false);
  });
});
