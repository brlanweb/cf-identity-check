# cf-identity-check

Cloudflare Workers 小站：把一次普通访问已经暴露的边缘信号和浏览器信号并排看清楚，再给一个**只供参考**的启发式判断——这次网络像不像能直接使用 YouTube、Claude 这类按地区和网络类型限制访问的服务。

没有木马，不收集密码，默认不保存访客。

English notes are below the Chinese sections.

## 它做什么

打开首页会看到三块：

1. **观测到的**：Worker 在边缘读到的 `CF-Connecting-IP`、`request.cf`（机房、国家/地区、城市、ASN 组织、TLS、往返时间等），加上浏览器测量（屏幕、WebGL、canvas / 音频哈希、WebRTC 候选、`navigator.webdriver`、硬件并发、设备内存、网络信息、权限、存储是否可用）。
2. **声称的**：User-Agent、Client Hints、`Accept-Language`、时区、`navigator.platform`、`navigator.languages`、`navigator.userAgentData`。
3. **启发式展望**：偏低 / 中等 / 偏高，并给出短理由。页面同时列出对不上的项目。

判断分成四条，都在浏览器里算完，不回传评分：

- 住宅宽带，还是云厂商 / 托管 / VPN 出口
- 浏览器时区和边缘时区是否一致
- UA、Client Hints、语言、屏幕是否互相矛盾
- 有没有自动化迹象（`webdriver`、无头浏览器字样、SwiftShader / llvmpipe）

## 免责声明

这是启发式估计，不是鉴定，也不是连通性测试。

- 页面**不会**去连接 YouTube 或 Claude。
- 国家/地区清单和 ASN 词表是写死的近似值，服务商的政策会变。
- “偏高”不保证打得开，“偏低”也不保证一定打不开。
- 本项目不提供、也不意图提供绕过地区限制的方法。

## 架构

```text
浏览器
  ├─ 静态页面（Vite 构建，Workers Assets 托管）
  └─ GET /api/edge
        Hono Worker
          读取 request.cf 与请求头
          丢掉 Cookie、Authorization、Proxy-Authorization、CF-Access-Jwt-Assertion
          返回 JSON，不写数据库、KV、Cookie 或日志

页面在本地对照「声称」和「观测」，算出展望。
```

| 路径 | 作用 |
| --- | --- |
| `/` | 静态首页 |
| `GET /api/edge` | 只读的边缘 JSON。`Cache-Control: no-store` |

`wrangler.jsonc` 把 `/api/*` 设为 `run_worker_first`，其它路径先走静态资源。`@cloudflare/vite-plugin` 会在构建时写入资源目录，源配置里不要再手填 `assets.directory`。

本地 `npm run dev` 跑在 workerd 里。`request.cf` 可能是空的，也可能是运行时填的示例或宿主机信息，不等于线上访客。国家、城市、ASN 以部署到 Cloudflare 之后的结果为准。

## 本地开发

```bash
npm install
npm run dev
```

开发服务器默认是 Vite（Cloudflare 插件）。另有：

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

`npm run deploy` 会先 `vite build`，再 `wrangler deploy`。首次部署可以按提示使用账号的 `*.workers.dev` 子域。Worker 名称在 `wrangler.jsonc` 的 `name` 字段，默认是 `cf-identity-check`。

只想看构建产物时运行 `npm run build`。Vite 插件会生成带 `assets.directory` 的输出配置，供 `wrangler deploy` 使用。

## 隐私

- Worker 不把请求写入 KV、D1、R2 或 Cookie。
- `/api/edge` 回传 IP、地理和请求头，供**当前页面**展示。Cookie、Authorization、Proxy-Authorization、Set-Cookie、Cloudflare Access JWT 只记录“已省略”的名字，不回传值。
- 不回传 mTLS 客户端证书和自定义主机元数据。
- canvas / 音频哈希在浏览器内计算。
- WebRTC 会联系 `stun.cloudflare.com` 和 `stun.l.google.com`，用来列出候选地址。
- 检测 `localStorage` / `sessionStorage` 时会写入 `__cf_identity_check_probe` 并立刻删除。
- 重新测量只是再请求一次 `/api/edge`，仍然不落库。

## 许可

[MIT](LICENSE)

---

# English

`cf-identity-check` is a Cloudflare Workers site that shows the edge and browser signals a normal visit already exposes, then places claimed values beside them. It adds a heuristic outlook for whether that visit looks like it can open services that restrict access by region and network type, such as YouTube and Claude.

No malware. No credential collection. Nothing is stored by default.

## What it shows

1. **Observed:** `CF-Connecting-IP` and the Worker `request.cf` object (colo, country, city, ASN organization, TLS, RTT, and related fields), plus browser measurements: screen, WebGL, canvas and audio hashes, WebRTC candidates, `navigator.webdriver`, hardware concurrency, device memory, connection info, a permissions snapshot, and storage availability.
2. **Claimed:** User-Agent, Client Hints, `Accept-Language`, timezone, `navigator.platform`, `navigator.languages`, and `navigator.userAgentData`.
3. **Heuristic outlook:** lower, mixed, or higher, with short reasons and the mismatches that produced them.

Scoring runs in the browser. The four axes are residential vs hosting/VPN, timezone consistency, client consistency, and automation signals.

## Disclaimer

The outlook is a heuristic, not a verdict and not a connectivity test.

- The page does not contact YouTube or Claude.
- The country notes and ASN word lists are static approximations. Provider policy changes.
- “Higher” does not mean a service will load. “Lower” does not mean it cannot.
- This project does not help bypass regional restrictions.

## Architecture

Static files are built with Vite and served as Workers Assets. `GET /api/edge` is an Hono handler. It reads `request.cf` and request headers, drops `Cookie`, `Authorization`, `Proxy-Authorization`, `Set-Cookie`, and `CF-Access-Jwt-Assertion`, and returns JSON. It does not write a database, KV, cookies, or request logs.

`wrangler.jsonc` sets `run_worker_first` for `/api/*`. The Cloudflare Vite plugin fills `assets.directory` during build; leave it unset in the source config.

Under `npm run dev`, `request.cf` may be empty or filled with runtime sample or host data. It is not the production visitor. Geography and ASN come from Cloudflare after deploy.

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

`npm run deploy` runs `vite build` and then `wrangler deploy`. The Worker name defaults to `cf-identity-check` in `wrangler.jsonc`.

## Privacy

The Worker stores nothing. `/api/edge` is `Cache-Control: no-store` and is only there so the open page can render the current visit. Credential headers are omitted. Canvas and audio hashes stay in the browser. WebRTC uses the public STUN servers `stun.cloudflare.com` and `stun.l.google.com`. The storage probe writes `__cf_identity_check_probe` and deletes it immediately.

## License

[MIT](LICENSE)
