# cf-identity-check

Cloudflare Workers 页面：看**这一次访问的出口 IP**，把几家公开数据库的结果并排摆出来，再按查到的信号算一个 **纯净度系数**。

纯净度不是 IPPure 或任何一家的官方分数。查不到就写「无法查询」或「无法判断」，不补一个看起来合理的数。需要密钥、而密钥又没配的项目不出现在页面上；密钥配上之后，对应的一块会自己回来。

原来的 **Claude AI 信任分**还在第二个标签里。那一页仍是启发式，不连接 Claude，也与 Anthropic 无关。

English notes are below the Chinese sections.

## 首页在核对什么

1. **出口地址。** Worker 读 `CF-Connecting-IP`。浏览器再分别请求只解析 IPv4 的 `api.ipify.org`、`v4.ident.me`，以及只解析 IPv6 的 `api6.ipify.org`、`v6.ident.me`。两个回显一致才算这个协议族的地址。徽章是 `IPv4 Only`、`IPv6 Only` 或 `双栈`。同族地址和边缘不一致时，页面直接写出来，不当成同一个出口。
2. **位置。** 每家单独一格，不合成一个答案：Cloudflare `request.cf`、ipinfo.io、ip-api.com、ipapi.co、ipwho.is、ipapi.is、IP2Location、IPIP（浏览器直连 `myip.ipip.net`）、Bilibili（按边缘 IP 查公开接口）。登记国和其中某家的国家不同，就标成 **广播 IP**；都一致才是 **原生 IP**。对不上国家代码就写「无法判断」。
3. **ASN、名称、域名、范围。** ASN 优先用 Cloudflare，其次 RIPEstat，再其次 ipwho.is。名称按 RDAP、RIPEstat、Cloudflare 分别列出。域名来自 PeeringDB 的网站字段和 ipwho.is 的 `connection.domain`。范围优先用 RDAP 的起止地址，BGP 前缀另列 RIPEstat。
4. **机房 / 住宅 / 移动，以及 VPN、代理、Tor。** 只采用来源自己的字段：ip-api.com 的 hosting / proxy / mobile，proxycheck.io 的 type，ipapi.is 的 `is_*`（免费响应里常常没有），IP2Location 的 `is_proxy`，以及 Tor Project 的 `torbulkexitlist`。来源打架就标「不一致」。`Business` 不拿来当成住宅或机房。
5. **人机流量比。** 配置了 `CF_RADAR_TOKEN` 时，用 Cloudflare Radar 的 HTTP bot class（近 7 日，按 ASN）。没配置时这一项不显示，也不会用估算数字代替。
6. **纯净度系数。** 0–100 的风险分，越低越纯净。刻度是 0、15、25、40、50、70、100，对应极度纯净、纯净、一般、轻微风险、高风险、极度风险。明细里每一项都写出来。
7. **WebRTC。** STUN：`stun.cloudflare.com:3478`、`stun.l.google.com:19302`、`stun.chat.bilibili.com:3478`、`stun.miwifi.com:3478`。候选分成公网、私网、CGNAT、mDNS、中继。只有公网候选才会和已知出口比较；只看到 mDNS 时是「无法判断」，不当成没有泄露。
8. **DNS。** 「无法判断」。本站没有权威 DNS，看不见是哪台解析器来查一个一次性名字。
9. **指纹和地图。** 时区、语言、UA、屏幕、Canvas / WebGL / 音频哈希。地图用 Leaflet 和 OpenStreetMap 瓦片（样式压暗），针落在有坐标的来源上，不把几家坐标取平均。优先用 Cloudflare 的经纬度。边缘地址不是公网时，不用本地 `request.cf` 里的示例时区或城市。

本地 `npm run dev` 时 `request.cf` 经常是空的，`CF-Connecting-IP` 也可能不是公网地址。那种情况下外部库不会拿内网地址去查，浏览器回显仍然有效。

## 纯净度怎么加

从 0 起加，上限 100。同一类匿名信号只取最高一档。

| 信号 | 加分 |
| --- | --- |
| Tor 出口列表、proxycheck 或 ipapi.is 标成 Tor | +55 |
| VPN（proxycheck type 或 ipapi.is `is_vpn`） | +40 |
| 其它明确代理 | +28 |
| 仅 ip-api.com 的合并 `proxy` 字段为 true | +12 |
| 机房 / hosting / `is_datacenter` | +18 |
| 移动，且没有按机房计分 | +6 |
| 登记国 ≠ 地理位置国家 | +10 |
| StopForumSpam 命中（次数 ≥ 3 则 +20） | +12 |
| WebRTC 公网地址不在已知出口里 | +12 |
| 浏览器时区和边缘位置不一致 | +8 |
| 同族浏览器回显 ≠ `CF-Connecting-IP` | +14 |

没有任何一项「查到了是或否」足以起算时，分数是「无法计算」，而不是 0% 极度纯净。未返回的项目写「未计入」。

## 哪些来源现在就能用

不需要密钥，部署后由 Worker 按 `CF-Connecting-IP` 查询，并在边缘缓存公开结果：

| 来源 | 用途 |
| --- | --- |
| `request.cf` / `CF-Connecting-IP` | 边缘 IP、地理、ASN |
| RDAP（rdap.org） | 登记范围、登记国、ASN 名称 |
| RIPEstat | BGP 前缀、持有者、路由规模、RPKI |
| PeeringDB | AS 网站域名 |
| ip-api.com | 地理，以及 hosting / proxy / mobile |
| ipapi.co | 地理。额度紧，失败就显示无法查询 |
| ipwho.is | 地理，以及公司域名 |
| ipapi.is | 地理。免费响应通常没有风险布尔值 |
| ipinfo.io | 地理。无 token 也能查，额度有限 |
| Bilibili `getInfoNew` | 按边缘 IP 查。个别任播地址会返回机构名而不是国家，页面按原文显示 |
| proxycheck.io | 代理 / VPN / 类型。无 key 时额度更低 |
| Tor Project `torbulkexitlist` | 是否为出口节点 |
| StopForumSpam | 公开垃圾记录 |
| 浏览器：ipify、ident.me | 独立的 IPv4 / IPv6 回显 |
| 浏览器：ipinfo.io、myip.ipip.net | 浏览器这条路径上对方看到的地址 |
| 浏览器：STUN | WebRTC 候选 |

可选密钥（`npx wrangler secret put <NAME>`，本地放在不提交的 `.dev.vars`，样例是 `.dev.vars.example`）：

| 变量 | 不配置时 |
| --- | --- |
| `CF_RADAR_TOKEN` | 不显示人机流量比 |
| `IPINFO_TOKEN` | 仍会调用 ipinfo.io，额度更低，结果照常显示 |
| `IPAPI_IS_KEY` | 地理照常显示。没有密钥、响应里也没有风险字段时，不显示那一行风险。密钥配上且字段返回后，这一行会再出现。整次查询失败仍显示「无法查询」 |
| `PROXYCHECK_KEY` | 仍会调用，额度更低。有结果就显示。查询失败或额度用完仍显示「无法查询」。只有接口明确要求密钥、又没有配时，这一行才隐藏 |
| `IP2LOCATION_KEY` | 不显示 IP2Location 的定位和代理行 |

## 做不到、因此没有编造的部分

- **DNS 泄露。** 没有自己的权威域名，无法观察解析器。状态保持「无法判断」。
- **欺诈黑名单。** 没有接入支付或欺诈评分。StopForumSpam 只代表公开垃圾发帖记录。
- **IP2Location** 和 **Radar 人机比** 在没有密钥时不显示，也不会用别的数字顶上。配上密钥后会重新出现。
- **ipapi.is 免费档** 往往不返回 `is_vpn` / `is_datacenter`。页面不会把缺字段当成「否」。
- **住宅。** 只有来源明确给出 Residential / ISP 才标住宅。`hosting: false` 不够。

## 架构

```text
浏览器
  ├─ 静态页（Vite，Workers Assets）
  ├─ IPv4 / IPv6 回显、ipinfo.io、myip.ipip.net、STUN
  └─ GET /api/edge
        Hono Worker
          读取 CF-Connecting-IP 与 request.cf
          丢掉 Cookie、Authorization、Proxy-Authorization、CF-Access-Jwt-Assertion
          只对公网出口 IP 查询上表里的公开接口
          用 Cache API 短时缓存这些公开响应（缓存键不含密钥）
          不写 KV、D1、Cookie，也不记访问日志
```

`wrangler.jsonc` 让 `/api/*` 走 `run_worker_first`。不要手填 `assets.directory`，构建时由 Cloudflare Vite 插件写入。

## 本地开发

```bash
npm install
npm run dev
```

```bash
npm test
npm run typecheck
npm run build
```

## 部署

需要 Node.js 22+ 和一个 Cloudflare 账号。

```bash
npm install
npx wrangler login
# 可选：
# npx wrangler secret put CF_RADAR_TOKEN
npm run deploy
```

## 隐私

- Worker 不把这次访问写入 KV、D1、R2 或 Cookie。
- `/api/edge` 是 `Cache-Control: no-store`。边缘缓存的是按 IP 查出的公开注册和地理结果，用来少打第三方，不是访问日志。
- 公网出口 IP 会发给上表中的第三方。内网和回环地址不发。
- 浏览器还会自己去连 ipify、ident.me、ipinfo.io、myip.ipip.net，以及上面列出的 STUN。地图瓦片来自 OpenStreetMap。
- Cookie、Authorization、Proxy-Authorization、Set-Cookie、Cloudflare Access JWT 只留名字。
- Canvas 和音频哈希在浏览器里计算。
- 存储探测会写入 `__cf_identity_check_probe` 并马上删掉。
- 信任分标签里的重复次数只在 `sessionStorage`。

## 许可

[MIT](LICENSE)

---

# English

The homepage compares the exit IP seen by Cloudflare with separate browser IPv4 and IPv6 echoes, then shows geolocation, ASN, and risk answers **per source**. The purity score is a documented risk sum from those answers. Missing data stays unavailable. Cards that exist only because a secret is unset are omitted until that secret is configured. It is not an IPPure, ipinfo, or Anthropic product.

The Claude trust tab is unchanged in intent: a heuristic, not a connection to Claude.

## Sources

Live without secrets: Cloudflare `request.cf`, RDAP, RIPEstat, PeeringDB, ip-api.com, ipapi.co, ipwho.is, ipapi.is (geo; risk booleans often absent), ipinfo.io, Bilibili's IP lookup, proxycheck.io, the Tor exit list, StopForumSpam, plus browser calls to ipify, ident.me, ipinfo.io, myip.ipip.net, and the STUN servers listed above.

Optional secrets: `CF_RADAR_TOKEN` (ASN human/bot ratio; the row is hidden until set), `IPINFO_TOKEN` (still queried, lower quota, still shown), `PROXYCHECK_KEY` (still queried; a failed or rate-limited answer stays visible, and the row is hidden only when the API says a key is required), `IPAPI_IS_KEY` (geo stays; the risk row is hidden only when the key is absent and the response has no risk booleans), `IP2LOCATION_KEY` (that place and proxy row stay hidden until set). See `.dev.vars.example`.

DNS leak detection stays **无法判断** because this site has no authoritative nameserver. There is no fraud-score feed. Purity does not treat a failed lookup as a clean result.

`GET /api/edge` is `Cache-Control: no-store`. Public lookup bodies are cached at the edge by IP. Visits are not stored.

## Develop and deploy

Node.js 22+.

```bash
npm install
npm test
npm run typecheck
npm run build
npm run dev
npx wrangler login
npm run deploy
```
