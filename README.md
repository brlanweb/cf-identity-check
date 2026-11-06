# cf-identity-check

Cloudflare Workers 小站：看**这一次访问的出口 IP**在边缘和浏览器两侧各露出了什么，并给出一个启发式的 **Claude AI Trust Score**。

分数描述的是「像 Claude 这类服务会看到的出口干不干净」，不是 Anthropic 官方结果，也不是连通性测试。页面不会去连接 Claude。

没有木马，不收集密码，服务器默认不保存访客。

English notes are below the Chinese sections.

## 首页看什么

打开就能看到，顺序和常见的 Claude 出口自查页接近：

1. **出口 IP 对照**：中国出口 IPv4（不是中国就明确写非中国出口，不另造一条 IP）、Cloudflare 出口、Claude AI 出口。后两张是同一次 `CF-Connecting-IP`，页面写明本站没有单独再连 claude.ai 取第二条地址。
2. **Claude AI Trust Score**（0–100），刻度从高危到可信，并给出「良好 / 该 IP 存在轻微风险」这类状态。
3. **Claude 支持地区**、出口属性、安全检测（VPN / 代理 / Tor / 机器人 / 滥用记录）。
4. **可用性**：浏览器对 claude.ai 和 anthropic.com 的计时，不是官方状态。
5. **DNS**：浏览器看不到解析器，状态是「无法判断」，不伪造 DNS 出口。
6. **WebRTC UDP**、设备信息（时区、语言、系统、Cookie、WebGL、Canvas）。
7. **使用场景、服务商 / ASN、技术指标、IP 情报、风险深度**。RDAP、RIPEstat、反向 DNS、RPKI 能查到才填；蜜罐、带宽和端口扫描保持「无法查询」或不做。

机房和 VPN 词会压低纯净度和信任分。住宅且时区、UDP 与出口一致时，属性里再标「原生」。

**历史**：本次标签页里的重复测量；公网出口 IP 会问一次 [StopForumSpam](https://www.stopforumspam.org/)。查不到是「无法查询」或「无记录」，不编造滥用分。StopForumSpam 不是 Claude 的记录。

评分依据、信号明细、原始 JSON 默认折叠。

各项大致是：

- **DNS**：浏览器不暴露系统解析器或 DoH，`request.cf` 也没有解析器。这一项标成「不可得」，不计入信任分。
- **UDP**：WebRTC / STUN 公网地址和 `CF-Connecting-IP` 是否一致。mDNS 隐藏本机地址时，只说明没看到公网泄漏。
- **时区**：浏览器时区对边缘国家和时区。
- **指纹**：UA、Client Hints、平台、语言、屏幕，加上 canvas / WebGL / audio 有没有采到。
- **安全性**：`webdriver`、无头或自动化 UA、软件渲染，以及上面的伪装矛盾。

信任分按纯净度 30%、UDP 16%、时区 18%、指纹 14%、安全性 22% 加权，再对机房、VPN、Tor、泄漏和自动化扣分。国家是否在 Claude 的常见服务范围里只写在折叠说明中，**不计入纯净度**。`colo` 是 Cloudflare 机房，不拿来判断用户是不是机房网络。

## 免责声明

这是启发式估计，不是鉴定。

- 与 Anthropic 无隶属关系，页面也不连接 Claude。
- ASN 词表和国家说明是写死的近似值。
- 没有 RIR 归属库，分不出「广播 IP」和「原生分配」时会写明。
- 本项目不提供绕过地区限制或平台风控的方法。

## 架构

```text
浏览器
  ├─ 静态页面（Vite 构建，Workers Assets 托管）
  └─ GET /api/edge
        Hono Worker
          读取 request.cf 与请求头
          丢掉 Cookie、Authorization、Proxy-Authorization、CF-Access-Jwt-Assertion
          可选：用出口 IP 查询 StopForumSpam（失败则当作无历史库）
          返回 JSON，不写数据库、KV、Cookie 或日志

页面在本地算出信任分。重复测量的次数只留在 sessionStorage。
```

| 路径 | 作用 |
| --- | --- |
| `/` | 静态首页 |
| `GET /api/edge` | 只读的边缘 JSON。`Cache-Control: no-store` |

`wrangler.jsonc` 把 `/api/*` 设为 `run_worker_first`，其它路径先走静态资源。`@cloudflare/vite-plugin` 会在构建时写入资源目录，源配置里不要再手填 `assets.directory`。

本地 `npm run dev` 跑在 workerd 里。`request.cf` 可能是空的，也可能是运行时填的示例。国家、城市、ASN 以部署到 Cloudflare 之后的结果为准。

## 本地开发

```bash
npm install
npm run dev
```

另有：

```bash
npm test
npm run typecheck
npm run build
npm run preview
```

## 部署

需要 Node.js 22+ 和一个 Cloudflare 账号。

```bash
npm install
npx wrangler login
npm run deploy
```

`npm run deploy` 会先 `vite build`，再 `wrangler deploy`。Worker 名称在 `wrangler.jsonc` 的 `name` 字段，默认是 `cf-identity-check`。

## 隐私

- Worker 不把请求写入 KV、D1、R2 或 Cookie。
- `/api/edge` 回传 IP、地理和请求头，供**当前页面**展示。Cookie、Authorization、Proxy-Authorization、Set-Cookie、Cloudflare Access JWT 只记录「已省略」的名字，不回传值。
- 出口 IP 是公网地址时，Worker 会把该 IP 发给 StopForumSpam 做一次公开垃圾记录查询。本站不保存返回值。内网、回环、没有 IP 或查询失败时，页面显示「无历史库」。
- 不回传 mTLS 客户端证书和自定义主机元数据。
- canvas / 音频哈希在浏览器内计算。
- WebRTC 会联系 `stun.cloudflare.com` 和 `stun.l.google.com`。
- 检测存储时会写入 `__cf_identity_check_probe` 并立刻删除。
- 会话里的测量次数写在 `sessionStorage`（`cf-identity-check-session`），只保留最近若干次的出口 IP 和信任分，关闭标签页就没了。

## 许可

[MIT](LICENSE)

---

# English

`cf-identity-check` scores the **current exit IP** as a heuristic **Claude AI Trust Score**. It is not affiliated with Anthropic. Availability timings in the browser are not an official status page.

Nothing is stored on the server by default.

## What the page shows

Three exit cards: China IPv4 only when the edge country is China, otherwise a clear “not a China exit” card; the Cloudflare exit from `CF-Connecting-IP`; and the same address again as the Claude exit, with a note that this site does not open a second path to claude.ai.

The trust gauge runs from 高危 to 可信. Next to it: supported-region heuristic, IP attributes, and VPN / proxy / Tor / crawler / abuse checks. DNS stays **无法判断** because the browser does not expose the resolver. WebRTC UDP is compared with the edge IP. Device rows cover timezone, language, OS, cookie, WebGL, and canvas.

Lower sections cover scene estimates (labeled 估算), ASN data from RDAP and RIPEstat when those lookups return, bogon and PTR, and IP intel. Honeypot lists, bandwidth, and port scans stay unavailable. RPKI is shown only when RIPEstat returns it. Registration country versus edge country is the only broadcast-versus-native signal; if RDAP has no country, the label is 无法判断.

Weights are still purity 30%, UDP 16%, timezone 18%, fingerprint 14%, security 22%. A commonly unsupported country changes the 支持地区 badge and the scene caps. It does not by itself zero the purity of a residential network.

## Disclaimer

Heuristic only. ASN word lists are static. “Native” from the word list is not an RIR allocation proof. This project does not help bypass regional or platform controls.

## Architecture

Static files are built with Vite and served as Workers Assets. `GET /api/edge` reads `request.cf` and request headers, drops credential headers, and for a public exit IP queries StopForumSpam, RDAP, RIPEstat, and a PTR via DNS-over-HTTPS. It does not write a database, KV, cookies, or request logs. Scoring runs in the browser. Session repeats live in `sessionStorage` only.

`wrangler.jsonc` sets `run_worker_first` for `/api/*`. The Cloudflare Vite plugin fills `assets.directory` during build.

Under `npm run dev`, `request.cf` may be empty or sample data. It is not the production visitor.

## Develop

```bash
npm install
npm run dev
```

Also: `npm test`, `npm run typecheck`, `npm run build`, `npm run preview`.

## Deploy

Node.js 22+ and a Cloudflare account.

```bash
npm install
npx wrangler login
npm run deploy
```

## Privacy

The Worker stores nothing. `/api/edge` is `Cache-Control: no-store`. Credential headers are omitted. When the exit IP is public, that IP is sent to StopForumSpam, RDAP, RIPEstat, and a PTR lookup. Results are not stored. Loopback and private addresses are not sent. Canvas and audio hashes stay in the browser. WebRTC uses `stun.cloudflare.com` and `stun.l.google.com`. The storage probe writes `__cf_identity_check_probe` and deletes it immediately. Session measurement counts stay in `sessionStorage` until the tab closes.

## License

[MIT](LICENSE)
