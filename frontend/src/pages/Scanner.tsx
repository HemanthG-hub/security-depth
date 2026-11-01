import { useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { FileUp, LoaderCircle, RotateCcw, ScanLine, ShieldCheck, UploadCloud } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageTitle } from "@/components/AppShell";
import { ApiError, apiPost } from "@/lib/api";
import type { ScanResult } from "@/lib/types";

const SAMPLE_PYTHON = `from flask import Flask, request
import os
import sqlite3
import subprocess

app = Flask(__name__)
password = "prod_admin_password_123"

@app.get("/user")
def get_user():
    user_id = request.args["id"]
    query = f"SELECT * FROM users WHERE id = {user_id}"
    subprocess.run("grep " + user_id, shell=True)
    return open("/srv/files/" + user_id).read()
`;

const SAMPLE_IOT = `#include <WiFi.h>
#include <PubSubClient.h>

const char* WIFI_SSID = "factory-network";
const char* WIFI_PASSWORD = "wifi-secret-2024";
const char* MQTT_BROKER = "mqtt://broker.local";

void setup() {
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  client.setServer(MQTT_BROKER, 1883);
  ArduinoOTA.begin();
}
`;

const SAMPLE_JS = `const express = require("express");
const app = express();
const apiKey = "sk_live_123456789";

app.get("/search", (req, res) => {
  const query = "SELECT * FROM products WHERE name = '" + req.query.q + "'";
  db.query(query);
  res.send(req.query.q);
});
`;

const presets = [
  { label: "Python API", code: SAMPLE_PYTHON, testId: "load-preset-python" },
  { label: "IoT firmware", code: SAMPLE_IOT, testId: "load-preset-iot" },
  { label: "JavaScript API", code: SAMPLE_JS, testId: "load-preset-js" },
];

export default function Scanner() {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("auto");
  const [aiMode, setAiMode] = useState<"MOCK_AI" | "LIVE_AI">("MOCK_AI");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: () => apiPost<ScanResult>("/scans", { code, language, file_name: fileName, ai_mode: aiMode }),
    onSuccess: (scan) => {
      toast.success("Scan complete", { description: `${scan.vulnerabilities.length} finding(s) mapped to ${scan.language}.` });
      navigate(`/dashboard/${scan.id}`);
    },
    onError: () => toast.error("Scan could not be completed", { description: aiMode === "LIVE_AI" ? "Check the backend LLM_API_KEY and provider settings, then try again." : "Check the code size and try again." }),
  });
  const repositoryMutation = useMutation({
    mutationFn: () => apiPost<ScanResult>("/scans/github", { repository_url: repositoryUrl, ai_mode: aiMode }),
    onSuccess: (scan) => {
      toast.success("Repository scan complete", { description: `${scan.files_scanned} file(s), ${scan.vulnerabilities.length} finding(s).` });
      navigate(`/dashboard/${scan.id}`);
    },
    onError: (error) => {
      const body = error instanceof ApiError ? error.body : null;
      const description = body && typeof body === "object" && "detail" in body && typeof body.detail === "string"
        ? body.detail
        : "Check the GitHub URL, repository access, and backend configuration.";
      toast.error("Repository scan failed", { description });
    },
  });

  const loadFile = (file: File) => {
    if (file.size > 120_000) {
      toast.error("File is too large", { description: "Source files must be 120 KB or smaller." });
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setCode(String(reader.result ?? ""));
      setFileName(file.name.replace(/[^a-zA-Z0-9._-]/g, "_"));
      toast.success("Source loaded", { description: file.name });
    };
    reader.readAsText(file);
  };

  const scan = () => {
    if (!code.trim()) {
      toast.error("Add source code first", { description: "Paste code, upload a file, or load a preset." });
      return;
    }
    mutation.mutate();
  };

  const scanRepository = () => {
    if (!repositoryUrl.trim()) {
      toast.error("Enter a GitHub repository URL");
      return;
    }
    repositoryMutation.mutate();
  };

  return <div><PageTitle eyebrow="analysis console / 02" title="Scan source code before it ships." description="Paste code, load a file, or scan a GitHub repository. Deterministic findings remain the scoring source; live AI is optional." />
    <div className="mb-6 grid gap-4 lg:grid-cols-[minmax(220px,0.7fr)_minmax(0,1.3fr)]">
      <Card className="border-slate-800 bg-[#0f172a]"><CardContent className="p-4"><label htmlFor="ai-mode-select" className="font-mono text-[10px] uppercase tracking-widest text-slate-500">Analysis context</label><select id="ai-mode-select" data-testid="ai-mode-select" value={aiMode} onChange={(event) => setAiMode(event.target.value as "MOCK_AI" | "LIVE_AI")} className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-[#090d16] px-3 text-xs text-slate-200 outline-none focus:border-cyan-300"><option value="MOCK_AI">Local / mock context</option><option value="LIVE_AI">Live LLM provider</option></select><p className="mt-2 text-[11px] leading-5 text-slate-500">Live mode sends source to the backend-configured provider. It does not change deterministic findings or score.</p></CardContent></Card>
      <Card className="border-slate-800 bg-[#0f172a]"><CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-end"><div className="min-w-0 flex-1"><label htmlFor="github-repository-url" className="font-mono text-[10px] uppercase tracking-widest text-slate-500">GitHub repository</label><input id="github-repository-url" data-testid="github-repository-url" type="url" value={repositoryUrl} onChange={(event) => setRepositoryUrl(event.target.value)} placeholder="https://github.com/owner/repository" className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-[#090d16] px-3 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-300" /><p className="mt-2 text-[11px] leading-5 text-slate-500">Public repos need no credentials. Private repos require a backend GitHub token. Source is never executed.</p></div><Button type="button" data-testid="scan-github-repository-button" onClick={scanRepository} disabled={repositoryMutation.isPending} className="bg-cyan-300 text-slate-950 hover:bg-cyan-200">{repositoryMutation.isPending ? <><LoaderCircle className="size-4 animate-spin" /> Scanning</> : <><ScanLine className="size-4" /> Scan repository</>}</Button></CardContent></Card>
    </div>
    <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_320px]">
      <Card className="overflow-hidden border-slate-800 bg-[#0f172a]"><CardHeader className="border-b border-slate-800/80 bg-[#131c2e]/50"><div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"><CardTitle className="flex items-center gap-2 font-heading text-base text-slate-100"><ScanLine className="size-4 text-cyan-300" /> Source input</CardTitle><div className="flex items-center gap-2"><label htmlFor="language-select" className="font-mono text-[10px] uppercase tracking-widest text-slate-500">Language</label><select id="language-select" data-testid="language-select" value={language} onChange={(event) => setLanguage(event.target.value)} className="h-8 rounded-md border border-slate-700 bg-[#090d16] px-2 text-xs text-slate-200 outline-none focus:border-cyan-300"><option value="auto">Auto-detect</option><option value="python">Python</option><option value="javascript">JavaScript</option><option value="typescript">TypeScript</option><option value="sql">SQL</option><option value="c++">C / C++</option><option value="arduino">Arduino / ESP32</option></select></div></div></CardHeader><CardContent className="p-0"><div className="relative flex min-h-[540px] bg-[#090d16]"><div className="hidden w-12 select-none border-r border-slate-800/70 py-4 text-right font-mono text-[11px] leading-6 text-slate-700 sm:block">{(code || " ").split("\n").map((_, index) => <div key={index} className="pr-3">{index + 1}</div>)}</div><textarea data-testid="code-input-textarea" value={code} onChange={(event) => setCode(event.target.value)} spellCheck={false} placeholder="// Paste untrusted source code here...\n// Nothing is executed during analysis." className="min-h-[540px] flex-1 resize-none border-0 bg-transparent p-4 font-mono text-xs leading-6 text-slate-300 outline-none placeholder:text-slate-700" /></div><div className="flex flex-col gap-3 border-t border-slate-800/80 bg-[#131c2e]/60 p-4 sm:flex-row sm:items-center sm:justify-between"><div className="flex flex-wrap items-center gap-2"><input ref={inputRef} id="file-upload-input" data-testid="file-upload-input" type="file" accept=".py,.js,.jsx,.ts,.tsx,.sql,.c,.cc,.cpp,.h,.hpp,.ino,.txt" className="hidden" onChange={(event) => { const file = event.target.files?.[0]; if (file) loadFile(file); }} /><Button type="button" variant="outline" size="sm" data-testid="upload-source-button" onClick={() => inputRef.current?.click()} className="border-slate-700 text-slate-300"><UploadCloud className="size-3.5" /> Upload source</Button><Button type="button" variant="ghost" size="sm" data-testid="clear-code-button" onClick={() => { setCode(""); setFileName(null); }} className="text-slate-500 hover:text-slate-200"><RotateCcw className="size-3.5" /> Clear</Button>{fileName && <span className="flex items-center gap-1 font-mono text-[10px] text-cyan-300/80"><FileUp className="size-3" /> {fileName}</span>}</div><Button type="button" size="lg" data-testid="scan-code-button" onClick={scan} disabled={mutation.isPending} className="bg-cyan-300 font-semibold text-slate-950 shadow-[0_0_22px_rgba(0,240,255,0.18)] hover:bg-cyan-200">{mutation.isPending ? <><LoaderCircle className="size-4 animate-spin" /> Analyzing...</> : <><ShieldCheck className="size-4" /> Scan code</>}</Button></div></CardContent></Card>
      <div className="space-y-6"><Card className="border-slate-800 bg-[#0f172a]"><CardHeader><CardTitle className="font-heading text-base text-slate-100">Load a threat pattern</CardTitle></CardHeader><CardContent className="space-y-2">{presets.map((preset) => <button key={preset.testId} type="button" data-testid={preset.testId} onClick={() => { setCode(preset.code); setFileName(null); setLanguage("auto"); }} className="group flex w-full items-center justify-between rounded-lg border border-slate-800 bg-[#131c2e] px-3 py-3 text-left transition-colors hover:border-cyan-300/40 hover:bg-cyan-300/5"><span><span className="block text-xs font-semibold text-slate-200">{preset.label}</span><span className="mt-1 block font-mono text-[10px] text-slate-600">preset / demo data</span></span><ScanLine className="size-4 text-slate-600 transition-colors group-hover:text-cyan-300" /></button>)}</CardContent></Card><Card className="border-cyan-300/15 bg-cyan-300/[0.03]"><CardContent className="p-5"><div className="flex items-start gap-3"><ShieldCheck className="mt-0.5 size-4 shrink-0 text-cyan-300" /><div><h3 className="text-sm font-semibold text-slate-200" data-testid="safe-analysis-title">Safe analysis by design</h3><p className="mt-2 text-xs leading-5 text-slate-500" data-testid="safe-analysis-description">Uploaded files are treated as untrusted text. We never execute source code, and mock AI mode keeps the demo functional without an API key.</p></div></div></CardContent></Card></div>
    </div>
  </div>;
}
