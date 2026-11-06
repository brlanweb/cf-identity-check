import { countryLabel } from "./score.ts";

export type IpIntel = {
  bogon: boolean;
  bogonNote: string;
  ptr: { state: "有记录" | "无记录" | "无法查询"; value: string | null };
  rdap: {
    state: "已查询" | "无法查询";
    name: string | null;
    type: string | null;
    country: string | null;
    registered: string | null;
    registrant: string | null;
    range: string | null;
  };
  asn: {
    state: "已查询" | "无法查询";
    name: string | null;
    registered: string | null;
    registrant: string | null;
    holder: string | null;
  };
  routing: {
    state: "已查询" | "无法查询";
    ipv4Prefixes: number | null;
    ipv4Addresses: number | null;
  };
  rpki: { state: "valid" | "invalid" | "unknown" | "无法查询"; prefix: string | null; note: string };
  prefix: string | null;
  broadcast: { label: string; note: string };
  honeypot: "无法查询";
  bandwidth: "无法查询";
};

const UNAVAILABLE_RDAP: IpIntel["rdap"] = {
  state: "无法查询",
  name: null,
  type: null,
  country: null,
  registered: null,
  registrant: null,
  range: null,
};

export function isBogon(ip: string | null): boolean {
  if (!ip) return false;
  const text = ip.toLowerCase();
  if (text === "::1" || text.startsWith("fe80:") || text.startsWith("fc") || text.startsWith("fd")) return true;
  const parts = text.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && (b === 168 || b === 0)) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51 && parts[2] === 100) return true;
  if (a === 203 && b === 0 && parts[2] === 113) return true;
  if (a >= 224) return true;
  return false;
}

export function reverseV4(ip: string | null): string | null {
  if (!ip || ip.includes(":")) return null;
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  return `${parts.reverse().join(".")}.in-addr.arpa`;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function day(value: string | null): string | null {
  if (!value) return null;
  return value.slice(0, 10);
}

function vcardName(entity: unknown): string | null {
  if (!entity || typeof entity !== "object") return null;
  const vcard = (entity as { vcardArray?: unknown }).vcardArray;
  if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) return null;
  for (const row of vcard[1]) {
    if (Array.isArray(row) && row[0] === "fn" && typeof row[3] === "string" && row[3].trim()) return row[3].trim();
  }
  return null;
}

function registrantName(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const entities = (body as { entities?: unknown }).entities;
  if (!Array.isArray(entities)) return null;
  for (const entity of entities) {
    if (!entity || typeof entity !== "object") continue;
    const roles = (entity as { roles?: unknown }).roles;
    if (Array.isArray(roles) && roles.includes("registrant")) return vcardName(entity);
  }
  return null;
}

function registrationDate(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const events = (body as { events?: unknown }).events;
  if (!Array.isArray(events)) return null;
  for (const event of events) {
    if (!event || typeof event !== "object") continue;
    if ((event as { eventAction?: unknown }).eventAction === "registration") {
      return day(text((event as { eventDate?: unknown }).eventDate));
    }
  }
  return null;
}

export function parsePtr(body: unknown): { state: IpIntel["ptr"]["state"]; value: string | null } {
  if (!body || typeof body !== "object") return { state: "无法查询", value: null };
  const answers = (body as { Answer?: unknown }).Answer;
  if (Array.isArray(answers)) {
    for (const answer of answers) {
      if (!answer || typeof answer !== "object") continue;
      const data = text((answer as { data?: unknown }).data);
      if ((answer as { type?: unknown }).type === 12 && data) return { state: "有记录", value: data.replace(/\.$/, "") };
    }
  }
  return { state: "无记录", value: null };
}

export function parseRdapIp(body: unknown): IpIntel["rdap"] {
  if (!body || typeof body !== "object") return UNAVAILABLE_RDAP;
  const record = body as {
    name?: unknown;
    type?: unknown;
    country?: unknown;
    startAddress?: unknown;
    endAddress?: unknown;
    objectClassName?: unknown;
  };
  if (record.objectClassName && record.objectClassName !== "ip network") return UNAVAILABLE_RDAP;
  const start = text(record.startAddress);
  const end = text(record.endAddress);
  return {
    state: "已查询",
    name: text(record.name),
    type: text(record.type),
    country: text(record.country)?.toUpperCase() ?? null,
    registered: registrationDate(body),
    registrant: registrantName(body),
    range: start && end ? `${start} – ${end}` : null,
  };
}

export function parseRdapAsn(body: unknown): Pick<IpIntel["asn"], "name" | "registered" | "registrant"> | null {
  if (!body || typeof body !== "object") return null;
  const record = body as { objectClassName?: unknown; name?: unknown };
  if (record.objectClassName && record.objectClassName !== "autnum") return null;
  return {
    name: text(record.name),
    registered: registrationDate(body),
    registrant: registrantName(body),
  };
}

export function parsePrefixOverview(body: unknown): { prefix: string | null; holder: string | null } {
  if (!body || typeof body !== "object") return { prefix: null, holder: null };
  const data = (body as { data?: unknown }).data;
  if (!data || typeof data !== "object") return { prefix: null, holder: null };
  const prefix = text((data as { resource?: unknown }).resource);
  const asns = (data as { asns?: unknown }).asns;
  const first = Array.isArray(asns) ? asns[0] : null;
  const holder = first && typeof first === "object" ? text((first as { holder?: unknown }).holder) : null;
  return { prefix, holder };
}

export function parseRouting(body: unknown): IpIntel["routing"] {
  if (!body || typeof body !== "object") return { state: "无法查询", ipv4Prefixes: null, ipv4Addresses: null };
  const data = (body as { data?: unknown }).data;
  if (!data || typeof data !== "object") return { state: "无法查询", ipv4Prefixes: null, ipv4Addresses: null };
  const space = (data as { announced_space?: unknown }).announced_space;
  const v4 = space && typeof space === "object" ? (space as { v4?: unknown }).v4 : null;
  if (!v4 || typeof v4 !== "object") return { state: "无法查询", ipv4Prefixes: null, ipv4Addresses: null };
  const prefixes = (v4 as { prefixes?: unknown }).prefixes;
  const ips = (v4 as { ips?: unknown }).ips;
  return {
    state: "已查询",
    ipv4Prefixes: typeof prefixes === "number" ? prefixes : null,
    ipv4Addresses: typeof ips === "number" ? ips : null,
  };
}

export function parseRpki(body: unknown, prefix: string | null): IpIntel["rpki"] {
  if (!body || typeof body !== "object") {
    return { state: "无法查询", prefix, note: "RIPEstat 没有返回 RPKI 结果，不编造有效或无效。" };
  }
  const data = (body as { data?: unknown }).data;
  const status = data && typeof data === "object" ? text((data as { status?: unknown }).status) : null;
  if (status === "valid" || status === "invalid" || status === "unknown") {
    return {
      state: status,
      prefix,
      note: status === "valid" ? "RIPEstat 对这条宣告前缀给出了有效 ROA。" : status === "invalid" ? "RIPEstat 认为这条宣告和 ROA 不一致。" : "RIPEstat 没有给出确定的 ROA 结论。",
    };
  }
  return { state: "无法查询", prefix, note: "返回里没有可用的 RPKI 状态。" };
}

export function broadcastLabel(edgeCountry: string | null, registeredCountry: string | null): IpIntel["broadcast"] {
  const edge = edgeCountry?.toUpperCase() ?? "";
  if (!edge || edge === "XX" || edge === "T1") {
    return { label: "无法判断", note: "没有可靠的边缘国家，不能比较归属地和广播地。" };
  }
  const place = countryLabel(edge).replace(/（[A-Z0-9]+）$/, "");
  const registered = registeredCountry?.toUpperCase() ?? "";
  if (!registered) {
    return { label: `${place} IP / 无法判断`, note: "RDAP 没有登记国家，不能判断是原生还是广播。" };
  }
  if (registered === edge) {
    return { label: `${place} IP / 原生`, note: "RDAP 登记国家和边缘地理位置一致。这只说明登记地。" };
  }
  return {
    label: `${place} IP / 广播 IP`,
    note: `边缘地理位置是${place}，RDAP 登记国家是${countryLabel(registered)}。`,
  };
}

export function assembleIntel(input: {
  ip: string | null;
  edgeCountry: string | null;
  ptrBody: unknown | null;
  rdapIp: unknown | null;
  rdapAsn: unknown | null;
  prefixBody: unknown | null;
  routingBody: unknown | null;
  rpkiBody: unknown | null;
}): IpIntel {
  const bogon = isBogon(input.ip);
  const rdap = parseRdapIp(input.rdapIp);
  const asnRecord = parseRdapAsn(input.rdapAsn);
  const prefix = parsePrefixOverview(input.prefixBody);
  const routing = parseRouting(input.routingBody);
  return {
    bogon,
    bogonNote: bogon ? "这个地址在内置的保留、文档或内网列表里。" : "不在内置 Bogon 列表里。",
    ptr: parsePtr(input.ptrBody),
    rdap,
    asn: {
      state: asnRecord || prefix.holder ? "已查询" : "无法查询",
      name: asnRecord?.name ?? null,
      registered: asnRecord?.registered ?? null,
      registrant: asnRecord?.registrant ?? null,
      holder: prefix.holder,
    },
    routing,
    rpki: parseRpki(input.rpkiBody, prefix.prefix),
    prefix: prefix.prefix,
    broadcast: broadcastLabel(input.edgeCountry, rdap.country),
    honeypot: "无法查询",
    bandwidth: "无法查询",
  };
}
