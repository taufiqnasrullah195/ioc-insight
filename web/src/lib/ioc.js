// IOC type auto-detection (mirrors backend normalizer — display hint only)
const RE_HEX = /^[0-9a-fA-F]+$/;
const RE_IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const RE_DOMAIN = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;

export function refang(text) {
  return text
    .trim()
    .replace(/hxxps/gi, "https")
    .replace(/hxxp/gi, "http")
    .replace(/\[\.\]|\(\.\)|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[at\]/gi, "@");
}

export function detectType(raw) {
  const v = refang(raw);
  if (!v) return null;
  if (RE_IPV4.test(v)) return "ipv4";
  if (v.includes(":")) {
    try { return "ipv6"; } catch { /* fallthrough */ }
  }
  if (RE_HEX.test(v) && [32, 40, 64].includes(v.length)) return "hash";
  if (/^https?:\/\//i.test(v)) return "url";
  if (RE_DOMAIN.test(v)) return "domain";
  return null;
}

export const VERDICT_COLORS = {
  MALICIOUS: "text-red-400 border-red-900/60",
  SUSPICIOUS: "text-amber-400 border-amber-800/60",
  CLEAN: "text-emerald-400 border-emerald-900/60",
  UNKNOWN: "text-slate-300 border-slate-700",
};

export const VERDICT_BG = {
  MALICIOUS: "from-amber-400 to-red-500",
  SUSPICIOUS: "from-yellow-400 to-amber-500",
  CLEAN: "from-emerald-400 to-green-500",
  UNKNOWN: "from-slate-400 to-slate-500",
};

export const ACTION_LABEL = {
  BLOCK: "⛔ BLOCK at perimeter",
  ESCALATE_L2: "⬆ Escalate to L2",
  LIKELY_FALSE_POSITIVE: "✓ Likely false positive",
  MONITOR: "◉ Monitor",
  INVESTIGATE: "🔍 Investigate",
};
