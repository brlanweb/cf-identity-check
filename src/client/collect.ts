import { sha256 } from "./hash.ts";

export type BrowserReport = {
  timezone: string;
  timezoneOffsetMinutes: number;
  timezoneOffset: string;
  locale: string;
  languages: string[];
  userAgent: string;
  platform: string;
  vendor: string;
  webdriver: boolean;
  hardwareConcurrency: number | null;
  deviceMemory: number | null;
  maxTouchPoints: number;
  cookieEnabled: boolean;
  doNotTrack: string | null;
  globalPrivacyControl: boolean | null;
  pdfViewerEnabled: boolean | null;
  screen: {
    width: number;
    height: number;
    availWidth: number;
    availHeight: number;
    colorDepth: number;
    pixelDepth: number;
  };
  window: {
    innerWidth: number;
    innerHeight: number;
    outerWidth: number;
    outerHeight: number;
    devicePixelRatio: number;
  };
  connection: {
    effectiveType: string | null;
    downlink: number | null;
    rtt: number | null;
    saveData: boolean | null;
    type: string | null;
  } | null;
  userAgentData: {
    mobile: boolean | null;
    platform: string | null;
    brands: string | null;
    architecture: string | null;
    bitness: string | null;
    model: string | null;
    platformVersion: string | null;
    fullVersionList: string | null;
    wow64: boolean | null;
  } | null;
  webgl: {
    vendor: string;
    renderer: string;
    unmaskedVendor: string | null;
    unmaskedRenderer: string | null;
  } | null;
  canvasHash: string | null;
  audioHash: string | null;
  webrtc: {
    candidates: string[];
    ips: string[];
    globalIps: string[];
    mdns: boolean;
    error: string | null;
  };
  permissions: Record<string, string>;
  storage: Record<string, boolean>;
  errors: string[];
};

type NetworkInformation = {
  effectiveType?: string;
  downlink?: number;
  rtt?: number;
  saveData?: boolean;
  type?: string;
};

type HighEntropy = {
  architecture?: string;
  bitness?: string;
  model?: string;
  platformVersion?: string;
  fullVersionList?: { brand: string; version: string }[];
  wow64?: boolean;
  mobile?: boolean;
  platform?: string;
  brands?: { brand: string; version: string }[];
};

type UserAgentData = {
  mobile?: boolean;
  platform?: string;
  brands?: { brand: string; version: string }[];
  getHighEntropyValues?: (hints: string[]) => Promise<HighEntropy>;
};

function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(fallback), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        clearTimeout(timer);
        resolve(fallback);
      },
    );
  });
}

function formatOffset(minutesEast: number): string {
  const sign = minutesEast >= 0 ? "+" : "-";
  const abs = Math.abs(minutesEast);
  const hours = Math.floor(abs / 60);
  const minutes = abs % 60;
  return `UTC${sign}${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
}

function canvasSample(): string | null {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 280;
    canvas.height = 64;
    const context = canvas.getContext("2d");
    if (!context) return null;
    context.fillStyle = "#1b2418";
    context.fillRect(0, 0, 280, 64);
    context.font = "16px sans-serif";
    context.fillStyle = "#d6f25c";
    context.fillText("cf-identity-check 身份核对", 8, 26);
    context.fillStyle = "rgba(240, 195, 106, 0.85)";
    context.fillText("Cwm fjordbank glyphs vext quiz", 8, 50);
    context.strokeStyle = "#8fdf7a";
    context.strokeRect(2.5, 2.5, 275, 59);
    return canvas.toDataURL();
  } catch {
    return null;
  }
}

async function audioSample(): Promise<string | null> {
  const Ctor = window.OfflineAudioContext ?? (window as Window & { webkitOfflineAudioContext?: typeof OfflineAudioContext }).webkitOfflineAudioContext;
  if (!Ctor) return null;
  const context = new Ctor(1, 44100, 44100);
  const oscillator = context.createOscillator();
  oscillator.type = "triangle";
  oscillator.frequency.value = 10000;
  const compressor = context.createDynamicsCompressor();
  oscillator.connect(compressor);
  compressor.connect(context.destination);
  oscillator.start(0);
  const buffer = await context.startRendering();
  const samples = buffer.getChannelData(0).subarray(4500, 5000);
  let total = 0;
  for (const sample of samples) total += Math.abs(sample);
  return sha256(total.toString());
}

function webglInfo(): BrowserReport["webgl"] {
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl");
    if (!gl) return null;
    const ext = gl.getExtension("WEBGL_debug_renderer_info");
    return {
      vendor: String(gl.getParameter(gl.VENDOR)),
      renderer: String(gl.getParameter(gl.RENDERER)),
      unmaskedVendor: ext ? String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)) : null,
      unmaskedRenderer: ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : null,
    };
  } catch {
    return null;
  }
}

function isGlobalIp(ip: string): boolean {
  if (ip.includes(":")) {
    const text = ip.toLowerCase();
    if (text === "::1" || text.startsWith("fe80:") || text.startsWith("fc") || text.startsWith("fd")) return false;
    return text.includes(":");
  }
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part) || part < 0 || part > 255)) return false;
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 192 && b === 168) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

function ipFromCandidate(candidate: string): string | null {
  const parts = candidate.split(" ");
  const ip = parts[4];
  if (!ip || ip.endsWith(".local")) return null;
  return ip;
}

function collectWebRtc(): Promise<BrowserReport["webrtc"]> {
  return new Promise((resolve) => {
    const candidates: string[] = [];
    const ips = new Set<string>();
    let settled = false;
    let pc: RTCPeerConnection;
    const finish = (error: string | null) => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timer);
      try {
        pc.close();
      } catch {
        /* already closed */
      }
      const list = [...ips];
      resolve({
        candidates,
        ips: list,
        globalIps: list.filter(isGlobalIp),
        mdns: candidates.some((candidate) => candidate.includes(".local")),
        error,
      });
    };
    const timer = window.setTimeout(() => finish(null), 3500);
    try {
      pc = new RTCPeerConnection({
        iceServers: [{ urls: ["stun:stun.cloudflare.com:3478", "stun:stun.l.google.com:19302"] }],
      });
    } catch {
      finish("浏览器没有提供 WebRTC。");
      return;
    }
    pc.onicecandidate = (event) => {
      if (!event.candidate) {
        finish(null);
        return;
      }
      candidates.push(event.candidate.candidate);
      const ip = ipFromCandidate(event.candidate.candidate);
      if (ip) ips.add(ip);
    };
    pc.createDataChannel("cf-identity-check");
    pc.createOffer()
      .then((offer) => pc.setLocalDescription(offer))
      .catch(() => finish("WebRTC offer 失败。"));
  });
}

async function permissionsSnapshot(): Promise<Record<string, string>> {
  const names = ["geolocation", "notifications", "camera", "microphone", "persistent-storage", "midi", "clipboard-read"];
  const result: Record<string, string> = {};
  if (!navigator.permissions?.query) {
    result.permissions = "unsupported";
    return result;
  }
  await Promise.all(
    names.map(async (name) => {
      try {
        const status = await navigator.permissions.query({ name: name as PermissionName });
        result[name] = status.state;
      } catch {
        result[name] = "unsupported";
      }
    }),
  );
  return result;
}

function storageSnapshot(): Record<string, boolean> {
  const probe = (storage: Storage | undefined): boolean => {
    if (!storage) return false;
    const key = "__cf_identity_check_probe";
    try {
      storage.setItem(key, "1");
      storage.removeItem(key);
      return true;
    } catch {
      return false;
    }
  };
  return {
    cookieEnabled: navigator.cookieEnabled,
    localStorage: probe(window.localStorage),
    sessionStorage: probe(window.sessionStorage),
    indexedDB: "indexedDB" in window,
  };
}

function brandsText(brands: { brand: string; version: string }[] | undefined): string | null {
  if (!brands?.length) return null;
  return brands.map((brand) => `${brand.brand} ${brand.version}`).join(", ");
}

export async function collectBrowser(): Promise<BrowserReport> {
  const errors: string[] = [];
  const nav = navigator as Navigator & {
    deviceMemory?: number;
    globalPrivacyControl?: boolean;
    connection?: NetworkInformation;
    userAgentData?: UserAgentData;
  };
  const minutesEast = -new Date().getTimezoneOffset();
  const canvas = canvasSample();
  let canvasHash: string | null = null;
  if (canvas) canvasHash = await sha256(canvas);
  else errors.push("无法读取 canvas。");

  const audioHash = await withTimeout(audioSample(), 2500, null);
  if (!audioHash) errors.push("无法完成音频采样。");

  let userAgentData: BrowserReport["userAgentData"] = null;
  const uaData = nav.userAgentData;
  if (uaData) {
    let high: HighEntropy = {};
    if (uaData.getHighEntropyValues) {
      high = await withTimeout(
        uaData.getHighEntropyValues(["architecture", "bitness", "model", "platformVersion", "fullVersionList", "wow64"]),
        1500,
        {},
      );
    }
    userAgentData = {
      mobile: uaData.mobile ?? null,
      platform: uaData.platform ?? null,
      brands: brandsText(uaData.brands),
      architecture: high.architecture ?? null,
      bitness: high.bitness ?? null,
      model: high.model ?? null,
      platformVersion: high.platformVersion ?? null,
      fullVersionList: brandsText(high.fullVersionList),
      wow64: high.wow64 ?? null,
    };
  }

  const connection = nav.connection
    ? {
        effectiveType: nav.connection.effectiveType ?? null,
        downlink: nav.connection.downlink ?? null,
        rtt: nav.connection.rtt ?? null,
        saveData: nav.connection.saveData ?? null,
        type: nav.connection.type ?? null,
      }
    : null;

  return {
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone ?? "",
    timezoneOffsetMinutes: minutesEast,
    timezoneOffset: formatOffset(minutesEast),
    locale: navigator.language,
    languages: navigator.languages ? [...navigator.languages] : navigator.language ? [navigator.language] : [],
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    vendor: navigator.vendor,
    webdriver: navigator.webdriver,
    hardwareConcurrency: navigator.hardwareConcurrency ?? null,
    deviceMemory: nav.deviceMemory ?? null,
    maxTouchPoints: navigator.maxTouchPoints ?? 0,
    cookieEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack,
    globalPrivacyControl: nav.globalPrivacyControl ?? null,
    pdfViewerEnabled: navigator.pdfViewerEnabled ?? null,
    screen: {
      width: screen.width,
      height: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      colorDepth: screen.colorDepth,
      pixelDepth: screen.pixelDepth,
    },
    window: {
      innerWidth: window.innerWidth,
      innerHeight: window.innerHeight,
      outerWidth: window.outerWidth,
      outerHeight: window.outerHeight,
      devicePixelRatio: window.devicePixelRatio,
    },
    connection,
    userAgentData,
    webgl: webglInfo(),
    canvasHash,
    audioHash,
    webrtc: await collectWebRtc(),
    permissions: await permissionsSnapshot(),
    storage: storageSnapshot(),
    errors,
  };
}
