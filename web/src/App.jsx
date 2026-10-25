import { useState } from "react";
import LookupPage from "./pages/LookupPage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";

export default function App() {
  const [page, setPage] = useState("lookup");

  return (
    <div className="min-h-screen bg-bg text-slate-200">
      <header className="border-b border-border px-6 py-4 flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-accent/20 flex items-center justify-center text-accent font-bold">◉</div>
        <div>
          <div className="font-bold text-sm">IOC Insight</div>
          <div className="text-[10px] text-slate-500">SOC L1 Triage · built by TheWiseParadise</div>
        </div>
        <nav className="ml-8 flex gap-1 text-sm">
          {[["lookup", "⌕ Lookup"], ["history", "🗂 History"]].map(([key, label]) => (
            <button key={key}
                    onClick={() => setPage(key)}
                    className={`px-3 py-2 rounded-lg ${page === key ? "bg-accent/10 text-accent" : "text-slate-400 hover:bg-slate-800/50"}`}>
              {label}
            </button>
          ))}
        </nav>
      </header>
      <main className="p-6 max-w-7xl mx-auto">
        {page === "lookup" ? <LookupPage /> : <HistoryPage />}
      </main>
    </div>
  );
}
