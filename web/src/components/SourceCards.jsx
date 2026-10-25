function formatResult(r) {
  if (!r.success) return { main: "—", sub: r.error || "unavailable", dim: true };
  switch (r.source) {
    case "virustotal":
      return { main: `${r.malicious_votes}/${r.total_engines}`, sub: "engines flagged malicious", danger: r.malicious_votes >= 3 };
    case "abuseipdb":
      return { main: `${Math.round(r.reputation_score ?? 0)}%`, sub: `abuse confidence · ${r.malicious_votes} reports`, danger: (r.reputation_score ?? 0) >= 40 };
    case "otx":
      return { main: `${r.malicious_votes}`, sub: "OTX pulses", danger: r.malicious_votes >= 5 };
    case "whois_age":
      return { main: `${r.malicious_votes}d`, sub: `domain age${r.tags.includes("newly-registered") ? " — newly registered!" : ""}`, danger: r.tags.includes("newly-registered") };
    default:
      return { main: "ok", sub: "" };
  }
}

const NAMES = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  otx: "AlienVault OTX",
  whois_age: "WHOIS Age",
};

export default function SourceCards({ results }) {
  return (
    <div className="grid grid-cols-2 gap-4">
      {results.map((r) => {
        const f = formatResult(r);
        return (
          <div key={r.source}
               className={`bg-panel border rounded-xl p-4 ${f.dim ? "border-border opacity-60" : "border-border"}`}>
            <div className="flex justify-between items-center mb-2">
              <span className="font-semibold text-sm text-slate-200">{NAMES[r.source] ?? r.source}</span>
              <span className={`text-[10px] ${r.from_cache ? "text-slate-500" : "text-emerald-400"}`}>
                {r.from_cache ? "cached" : "live"}
              </span>
            </div>
            <div className={`font-mono text-2xl font-bold ${f.danger ? "text-red-400" : f.dim ? "text-slate-500" : "text-slate-200"}`}>
              {f.main}
            </div>
            <div className="text-[11px] text-slate-400 mt-1">{f.sub}</div>
          </div>
        );
      })}
    </div>
  );
}
