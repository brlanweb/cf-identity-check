import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { historyCopy, isReputationLookupIp, parseStopForumSpam } from "../src/shared/history.ts";

describe("isReputationLookupIp", () => {
  it("accepts public addresses and skips loopback or private ranges", () => {
    assert.equal(isReputationLookupIp("203.0.113.10"), true);
    assert.equal(isReputationLookupIp("1.1.1.1"), true);
    assert.equal(isReputationLookupIp("2606:4700:4700::1111"), true);
    assert.equal(isReputationLookupIp("127.0.0.1"), false);
    assert.equal(isReputationLookupIp("10.1.2.3"), false);
    assert.equal(isReputationLookupIp("192.168.1.4"), false);
    assert.equal(isReputationLookupIp("172.16.0.4"), false);
    assert.equal(isReputationLookupIp("100.64.0.1"), false);
    assert.equal(isReputationLookupIp("::1"), false);
    assert.equal(isReputationLookupIp("not an ip"), false);
  });
});

describe("parseStopForumSpam", () => {
  it("reads a clean public record", () => {
    const record = parseStopForumSpam({
      success: 1,
      ip: { value: "1.1.1.1", frequency: 0, appears: 0, asn: 13335 },
    });
    assert.deepEqual(record, {
      source: "stopforumspam",
      appears: false,
      frequency: 0,
      lastSeen: null,
      attempted: true,
    });
    assert.equal(historyCopy(record!).label, "无公开记录");
  });

  it("reads a hit with a last-seen time", () => {
    const record = parseStopForumSpam({
      success: 1,
      ip: { appears: 1, frequency: 4, lastseen: "2024-01-02 03:04:05" },
    });
    assert.equal(record?.appears, true);
    assert.equal(record?.frequency, 4);
    assert.equal(record?.lastSeen, "2024-01-02 03:04:05");
    const copy = historyCopy(record!);
    assert.equal(copy.label, "有公开记录");
    assert.match(copy.note, /4 次/);
    assert.match(copy.note, /不是 Claude/);
  });

  it("treats an empty last-seen string as unknown", () => {
    const record = parseStopForumSpam({ success: 1, ip: { appears: 0, frequency: 0, lastseen: "  " } });
    assert.equal(record?.lastSeen, null);
  });

  it("rejects bodies that are not a successful record", () => {
    assert.equal(parseStopForumSpam(null), null);
    assert.equal(parseStopForumSpam({ success: 0 }), null);
    assert.equal(parseStopForumSpam({ success: 1, ip: {} }), null);
    assert.equal(historyCopy({ source: "none", appears: null, frequency: null, lastSeen: null, attempted: false }).label, "无历史库");
    assert.equal(historyCopy({ source: "none", appears: null, frequency: null, lastSeen: null, attempted: true }).label, "无历史库");
  });
});
