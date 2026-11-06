export type ServiceStatus = "ok" | "uncertain" | "friction";

export type ServiceOutlook = {
  id: string;
  name: string;
  mark: string;
  status: ServiceStatus;
  reason: string;
};

export type ServiceGroup = {
  id: "ai" | "media";
  label: string;
  services: ServiceOutlook[];
};

export type ServiceContext = {
  hasEdge: boolean;
  country: string;
  countryName: string;
  network: "residential" | "hosting" | "unknown";
  tor: boolean;
  geoConflict: boolean;
  clientScore: number;
  automationScore: number;
};

export const STATUS_LABEL: Record<ServiceStatus, string> = {
  ok: "较可能可用",
  uncertain: "不确定",
  friction: "较高阻力",
};

type DatacenterStance = "strict" | "moderate" | "light";

type Profile = {
  id: string;
  name: string;
  mark: string;
  category: "ai" | "media";
  blocked: readonly string[];
  limited: readonly string[];
  allow: readonly string[] | null;
  datacenter: DatacenterStance;
};

/**
 * Static approximation of where each service is widely reported as unavailable,
 * only partly available, or commonly offered. This is not a live policy list
 * and not a connectivity test. The page never contacts these services.
 */
const CLAUDE_ALLOW = [
  "US", "CA", "GB", "IE", "AU", "NZ", "JP", "KR", "SG", "HK", "TW", "IN", "IL", "AE", "BR", "MX",
  "DE", "FR", "NL", "BE", "LU", "AT", "CH", "IT", "ES", "PT", "SE", "NO", "DK", "FI", "IS",
  "PL", "CZ", "SK", "HU", "RO", "BG", "GR", "HR", "SI", "EE", "LV", "LT", "CY", "MT",
] as const;

const DISNEY_ALLOW = [
  "US", "CA", "MX", "BR", "AR", "CL", "CO", "PE", "UY",
  "GB", "IE", "DE", "FR", "IT", "ES", "PT", "NL", "BE", "LU", "CH", "AT", "SE", "NO", "DK", "FI", "IS",
  "PL", "CZ", "HU", "RO", "GR", "SK", "BG", "HR", "SI", "EE", "LV", "LT", "TR",
  "AU", "NZ", "JP", "KR", "SG", "HK", "TW", "IN", "TH", "MY", "ID", "PH",
] as const;

const SANCTIONED = ["CN", "KP", "IR", "SY", "CU"] as const;

const PROFILES: readonly Profile[] = [
  {
    id: "claude",
    name: "Claude",
    mark: "Cl",
    category: "ai",
    blocked: ["CN", "RU", "BY", "IR", "KP", "SY", "CU"],
    limited: [],
    allow: CLAUDE_ALLOW,
    datacenter: "strict",
  },
  {
    id: "chatgpt",
    name: "ChatGPT",
    mark: "GPT",
    category: "ai",
    blocked: ["CN", "RU", "BY", "IR", "KP", "SY", "CU"],
    limited: ["VE"],
    allow: null,
    datacenter: "strict",
  },
  {
    id: "gemini",
    name: "Gemini",
    mark: "Ge",
    category: "ai",
    blocked: ["CN", "IR", "KP", "CU", "SY", "TM", "ER"],
    limited: ["RU"],
    allow: null,
    datacenter: "moderate",
  },
  {
    id: "grok",
    name: "Grok",
    mark: "Gk",
    category: "ai",
    blocked: [...SANCTIONED],
    limited: ["RU"],
    allow: null,
    datacenter: "moderate",
  },
  {
    id: "perplexity",
    name: "Perplexity",
    mark: "Px",
    category: "ai",
    blocked: [...SANCTIONED],
    limited: ["RU"],
    allow: null,
    datacenter: "moderate",
  },
  {
    id: "copilot",
    name: "Copilot",
    mark: "Cp",
    category: "ai",
    blocked: [...SANCTIONED],
    limited: ["RU"],
    allow: null,
    datacenter: "moderate",
  },
  {
    id: "poe",
    name: "Poe",
    mark: "Poe",
    category: "ai",
    blocked: [...SANCTIONED],
    limited: ["RU"],
    allow: null,
    datacenter: "moderate",
  },
  {
    id: "midjourney",
    name: "Midjourney",
    mark: "Mj",
    category: "ai",
    blocked: ["CN", "KP", "IR", "SY"],
    limited: ["RU", "CU"],
    allow: null,
    datacenter: "moderate",
  },
  {
    id: "youtube",
    name: "YouTube",
    mark: "YT",
    category: "media",
    blocked: ["CN", "IR", "TM", "KP", "ER", "SY", "CU"],
    limited: [],
    allow: null,
    datacenter: "light",
  },
  {
    id: "netflix",
    name: "Netflix",
    mark: "N",
    category: "media",
    blocked: ["CN", "KP", "SY", "RU"],
    limited: ["IR", "CU", "TM", "ER"],
    allow: null,
    datacenter: "strict",
  },
  {
    id: "disney",
    name: "Disney+",
    mark: "D+",
    category: "media",
    blocked: ["CN", "KP", "SY", "RU"],
    limited: ["IR", "CU"],
    allow: DISNEY_ALLOW,
    datacenter: "strict",
  },
  {
    id: "spotify",
    name: "Spotify",
    mark: "Sp",
    category: "media",
    blocked: ["CN", "KP", "SY", "IR", "RU"],
    limited: ["CU"],
    allow: null,
    datacenter: "moderate",
  },
  {
    id: "twitch",
    name: "Twitch",
    mark: "Tw",
    category: "media",
    blocked: ["CN", "KP", "IR"],
    limited: ["RU", "SY", "TM"],
    allow: null,
    datacenter: "moderate",
  },
  {
    id: "google",
    name: "Google 服务",
    mark: "G",
    category: "media",
    blocked: ["CN", "KP", "TM", "ER"],
    limited: ["IR", "SY", "CU"],
    allow: null,
    datacenter: "light",
  },
];

const GROUPS = [
  { id: "ai", label: "AI 助手与接口" },
  { id: "media", label: "地区限制的媒体与平台" },
] as const;

function judge(profile: Profile, ctx: ServiceContext, country: string): { status: ServiceStatus; reason: string } {
  if (!ctx.hasEdge) {
    return { status: "uncertain", reason: "缺少边缘地区，无法对照。" };
  }
  if (ctx.tor) {
    return { status: "friction", reason: "Tor 出口，平台经常直接拒绝。" };
  }

  let status: ServiceStatus;
  let reason: string;
  let replaceable = false;

  if (country && profile.blocked.includes(country)) {
    status = "friction";
    reason = country === "CN" ? "中国大陆通常无法直接使用。" : `${ctx.countryName} 通常不在直接可用范围。`;
  } else if (country && profile.limited.includes(country)) {
    status = "uncertain";
    reason = "该地区通常只有部分可用。";
  } else if (!country) {
    status = "uncertain";
    reason = "没有可靠的国家/地区代码。";
    replaceable = true;
  } else if (profile.allow && !profile.allow.includes(country)) {
    status = "uncertain";
    reason = "不在静态已开放地区清单。";
  } else if (ctx.network === "hosting") {
    if (profile.datacenter === "strict") {
      status = "friction";
      reason = "数据中心或 VPN 出口，经常被拒绝。";
    } else if (profile.datacenter === "moderate") {
      status = "uncertain";
      reason = "数据中心或 VPN 出口，时松时紧。";
    } else {
      status = "ok";
      reason = "数据中心出口通常不是硬拦截。";
      replaceable = true;
    }
  } else if (ctx.network === "unknown") {
    status = "uncertain";
    reason = "组织名看不出住宅还是机房。";
    replaceable = true;
  } else {
    status = "ok";
    reason = "住宅宽带，不在常见限制地区。";
    replaceable = true;
  }

  if (ctx.automationScore >= 45 && status !== "friction" && (status === "ok" || replaceable)) {
    return { status: "uncertain", reason: "有自动化迹象，更容易被拦住。" };
  }
  if (status === "ok" && ctx.geoConflict) {
    return { status: "uncertain", reason: "浏览器时区与边缘位置不一致。" };
  }
  if (status === "ok" && ctx.clientScore < 55) {
    return { status: "uncertain", reason: "浏览器平台或语言互相矛盾。" };
  }
  return { status, reason };
}

export function evaluateServices(ctx: ServiceContext): ServiceGroup[] {
  const country = ctx.country.toUpperCase();
  const usable = country && country !== "XX" && country !== "T1" ? country : "";
  return GROUPS.map((group) => ({
    id: group.id,
    label: group.label,
    services: PROFILES.filter((profile) => profile.category === group.id).map((profile) => {
      const result = judge(profile, ctx, usable);
      return {
        id: profile.id,
        name: profile.name,
        mark: profile.mark,
        status: result.status,
        reason: result.reason,
      };
    }),
  }));
}
