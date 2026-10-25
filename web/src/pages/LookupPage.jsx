import { useState } from "react";
import { lookup } from "../api.js";
import SearchBar from "../components/SearchBar.jsx";
import VerdictCard from "../components/VerdictCard.jsx";
import SourceCards from "../components/SourceCards.jsx";
import ReportPanel from "../components/ReportPanel.jsx";

export default function LookupPage() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function run(ioc, lang) {
    setLoading(true);
    setError(null);
    try {
      const data = await lookup(ioc, lang);
      setResult(data);
    } catch (e) {
      setError(e.message);
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <SearchBar onSubmit={run} loading={loading} />

      {error && (
        <div className="bg-red-500/10 border border-red-900/60 text-red-300 rounded-xl p-4 text-sm">
          {error}
        </div>
      )}

      {!result && !error && !loading && (
        <div className="text-center text-slate-600 py-16 text-sm">
          Paste an IOC above to begin analysis.
        </div>
      )}

      {loading && (
        <div className="text-center text-slate-500 py-16 text-sm animate-pulse">
          ⠿ enriching across threat-intel sources…
        </div>
      )}

      {result && !loading && (
        <div className="grid grid-cols-3 gap-6">
          <div className="col-span-2 space-y-6">
            <VerdictCard result={result} />
            <SourceCards results={result.analyzer_results} />
          </div>
          <ReportPanel
            report={result.ai?.report_markdown}
            model={result.ai?.model}
            lang={result.ai?.lang}
            durationMs={result.duration_ms}
          />
        </div>
      )}
    </div>
  );
}
