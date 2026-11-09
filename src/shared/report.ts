import { SERVER_SOURCE_IDS, unavailablePlace, type GeoPlace, type QueryState } from "./sources.ts";

export type RiskFlag = {
  state: QueryState;
  note: string;
};

export type NetworkReport = {
  queriedIp: string | null;
  skipReason: string | null;
  places: GeoPlace[];
  risk: {
    tor: RiskFlag & { listed: boolean | null };
    ipApi: RiskFlag & { hosting: boolean | null; proxy: boolean | null; mobile: boolean | null };
    proxycheck: RiskFlag & { proxy: boolean | null; type: string | null; provider: string | null };
    ipapiIs: RiskFlag & {
      isVpn: boolean | null;
      isProxy: boolean | null;
      isTor: boolean | null;
      isDatacenter: boolean | null;
      isMobile: boolean | null;
    };
    ip2location: RiskFlag & { isProxy: boolean | null };
  };
  identity: {
    asn: string | null;
    asnSource: string | null;
    names: { value: string; source: string }[];
    domains: { value: string; source: string }[];
    range: { value: string; source: string } | null;
    prefix: { value: string; source: string } | null;
    registeredCountry: string | null;
    registeredCountrySource: string | null;
    ptr: { state: "有记录" | "无记录" | "无法查询"; value: string | null };
    rpki: { state: string; note: string };
  };
  radar: {
    state: QueryState;
    human: number | null;
    bot: number | null;
    note: string;
  };
};

export function baseNetwork(note: string): NetworkReport {
  return {
    queriedIp: null,
    skipReason: note,
    places: SERVER_SOURCE_IDS.map((id) => unavailablePlace(id, note)),
    risk: {
      tor: { state: "无法查询", listed: null, note },
      ipApi: { state: "无法查询", hosting: null, proxy: null, mobile: null, note },
      proxycheck: { state: "无法查询", proxy: null, type: null, provider: null, note },
      ipapiIs: {
        state: "无法查询",
        isVpn: null,
        isProxy: null,
        isTor: null,
        isDatacenter: null,
        isMobile: null,
        note,
      },
      ip2location: { state: "无法查询", isProxy: null, note },
    },
    identity: {
      asn: null,
      asnSource: null,
      names: [],
      domains: [],
      range: null,
      prefix: null,
      registeredCountry: null,
      registeredCountrySource: null,
      ptr: { state: "无法查询", value: null },
      rpki: { state: "无法查询", note },
    },
    radar: { state: "无法查询", human: null, bot: null, note },
  };
}
