import { useState } from "react";
import { detectType } from "../lib/ioc.js";

const LANGS = [
  { code: "en", label: "EN" },
  { code: "de", label: "DE" },
  { code: "id", label: "ID" },
];

export default function SearchBar({ onSubmit, loading }) {
  const [value, setValue] = useState("");
  const [lang, setLang] = useState("en");
  const type = detectType(value);

  return (
    <div className="bg-panel border border-border rounded-xl p-4">
      <div className="flex gap-3">
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && type && onSubmit(value, lang)}
          placeholder="Paste IOC — IP, domain, URL, hash (hxxp://, [.] defanged OK)"
          className="font-mono flex-1 bg-bg border border-border rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-accent"
        />
        <select
          value={lang}
          onChange={(e) => setLang(e.target.value)}
          className="bg-bg border border-border rounded-lg px-3 text-sm text-slate-200"
        >
          {LANGS.map((l) => (
            <option key={l.code} value={l.code}>{l.label}</option>
          ))}
        </select>
        <button
          onClick={() => type && onSubmit(value, lang)}
          disabled={!type || loading}
          className="bg-accent hover:bg-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed text-slate-900 font-semibold px-6 rounded-lg text-sm"
        >
          {loading ? "Analyzing…" : "Analyze"}
        </button>
      </div>
      <div className="text-[11px] text-slate-500 mt-2">
        {value
          ? type
            ? <>Detected type: <span className="text-accent font-mono">{type}</span> · cached results used when fresh</>
            : <span className="text-amber-400">unrecognized IOC format</span>
          : "Supports IPv4, IPv6, domain, URL, MD5/SHA1/SHA256"}
      </div>
    </div>
  );
}
