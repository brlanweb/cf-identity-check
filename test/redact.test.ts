import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { splitHeaders } from "../src/shared/redact.ts";

describe("splitHeaders", () => {
  it("drops credential headers and keeps the rest", () => {
    const { headers, omittedHeaders } = splitHeaders([
      ["User-Agent", "Mozilla/5.0"],
      ["Accept-Language", "zh-CN,zh;q=0.9"],
      ["Cookie", "session=secret"],
      ["Authorization", "Bearer secret-token"],
      ["Proxy-Authorization", "Basic c2VjcmV0"],
      ["CF-Access-Jwt-Assertion", "jwt-secret"],
      ["CF-Connecting-IP", "203.0.113.8"],
    ]);

    assert.deepEqual(headers, {
      "user-agent": "Mozilla/5.0",
      "accept-language": "zh-CN,zh;q=0.9",
      "cf-connecting-ip": "203.0.113.8",
    });
    assert.deepEqual(omittedHeaders, [
      "cookie",
      "authorization",
      "proxy-authorization",
      "cf-access-jwt-assertion",
    ]);
    const encoded = JSON.stringify({ headers, omittedHeaders });
    assert.equal(encoded.includes("secret"), false);
    assert.equal(encoded.includes("jwt-secret"), false);
  });
});
