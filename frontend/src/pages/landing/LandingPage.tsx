import React, { useEffect, useRef, useState } from 'react';
import { 
  ShieldAlert, 
  FileText, 
  Globe, 
  FileCode, 
  Terminal, 
  Database, 
  ExternalLink, 
  Bell, 
  Copy, 
  Check, 
  Download, 
  Lock,
  ArrowRight,
  Eye,
  Info
} from 'lucide-react';
import { createToken, downloadArtifact, getPublicConfig, CreateTokenResponse } from '../../api';

declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement, opts: Record<string, unknown>) => string;
      reset: (id?: string) => void;
      remove: (id?: string) => void;
    };
  }
}

interface TokenTypeOption {
  id: string;
  name: string;
  icon: React.ReactNode;
  category: string;
  description: string;
  badge: string;
}

const TOKEN_TYPES: TokenTypeOption[] = [
  {
    id: 'webbug',
    name: 'Web Bug / Pixel',
    icon: <Globe className="w-5 h-5 text-amber-400" />,
    category: 'Web & Email',
    description: '1x1 hidden image pixel embedded into emails, HTML pages, or markdown documentation.',
    badge: 'Zero-Click'
  },
  {
    id: 'pdf',
    name: 'Acrobat PDF',
    icon: <FileText className="w-5 h-5 text-red-400" />,
    category: 'Files & Decoys',
    description: 'Byte-exact PDF template that triggers an external URI action upon opening.',
    badge: 'Byte-Exact 76B'
  },
  {
    id: 'docx',
    name: 'Word Document (.docx)',
    icon: <FileCode className="w-5 h-5 text-blue-400" />,
    category: 'Files & Decoys',
    description: 'OpenXML Word document with an external footer relationship tracking pixel.',
    badge: 'Office XML'
  },
  {
    id: 'envfile',
    name: 'Decoy .env File',
    icon: <FileCode className="w-5 h-5 text-emerald-400" />,
    category: 'Credentials',
    description: 'Realistic environment file with decoy AWS, Database, Stripe, or GitHub credentials.',
    badge: 'Recipe Shuffler'
  },
  {
    id: 'kubeconfig',
    name: 'Kubeconfig Token',
    icon: <Terminal className="w-5 h-5 text-purple-400" />,
    category: 'Cloud & Infra',
    description: 'Fake cluster config alerting on kubectl get pods, version discovery, or cluster-info.',
    badge: 'K8s Wildcard'
  },
  {
    id: 'mysql',
    name: 'MySQL Honeypot',
    icon: <Database className="w-5 h-5 text-cyan-400" />,
    category: 'Database Trap',
    description: 'Fake MySQL server capturing client IP, username, and attributes before access denied.',
    badge: 'TCP Protocol'
  },
  {
    id: 'slowredirect',
    name: 'Slow Redirect (Fingerprint)',
    icon: <Eye className="w-5 h-5 text-rose-400" />,
    category: 'Intelligence',
    description: 'Interstitial webpage that collects Canvas hash, WebGL, timezone, and screen metrics.',
    badge: 'Device Fingerprint'
  }
];

interface Props {
  onNavigateManage: (key: string) => void;
}

export const LandingPage: React.FC<Props> = ({ onNavigateManage }) => {
  const [selectedType, setSelectedType] = useState<string>('webbug');
  const [label, setLabel] = useState<string>('');
  const [targetURL, setTargetURL] = useState<string>('https://google.com');
  const [envRecipe, setEnvRecipe] = useState<string>('aws');
  const [notifyChannel, setNotifyChannel] = useState<string>('none');
  const [webhookURL, setWebhookURL] = useState<string>('');
  const [webhookSecret, setWebhookSecret] = useState<string>('');
  const [telegramChatID, setTelegramChatID] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CreateTokenResponse | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [turnstileSiteKey, setTurnstileSiteKey] = useState<string>('');
  const [turnstileToken, setTurnstileToken] = useState<string>('');
  const turnstileRef = useRef<HTMLDivElement | null>(null);
  const turnstileWidgetId = useRef<string | undefined>(undefined);

  // Si el operador activó Cloudflare Turnstile, se carga el widget. Antes el frontend NUNCA lo cargaba, así
  // que activar TURNSTILE_SECRET_KEY hacía que TODAS las creaciones fallaran con 403.
  useEffect(() => {
    getPublicConfig().then((c) => setTurnstileSiteKey(c.turnstile_site_key || ''));
  }, []);

  useEffect(() => {
    if (!turnstileSiteKey) return;
    const render = () => {
      if (!window.turnstile || !turnstileRef.current || turnstileWidgetId.current) return;
      turnstileWidgetId.current = window.turnstile.render(turnstileRef.current, {
        sitekey: turnstileSiteKey,
        theme: 'dark',
        callback: (tok: string) => setTurnstileToken(tok),
        'expired-callback': () => setTurnstileToken(''),
        'error-callback': () => setTurnstileToken(''),
      });
    };
    if (window.turnstile) {
      render();
      return;
    }
    const s = document.createElement('script');
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    s.async = true;
    s.onload = render;
    document.head.appendChild(s);
  }, [turnstileSiteKey]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const payload = {
        type: selectedType,
        label: label || `Canary ${selectedType.toUpperCase()} Token`,
        target_url: selectedType === 'slowredirect' ? targetURL : undefined,
        notify_channel: notifyChannel,
        webhook_url: notifyChannel === 'webhook' ? webhookURL : undefined,
        webhook_secret: notifyChannel === 'webhook' ? webhookSecret : undefined,
        telegram_chat_id: notifyChannel === 'telegram' ? telegramChatID : undefined,
        options: selectedType === 'envfile' ? { recipe: envRecipe } : undefined,
        turnstile_token: turnstileSiteKey ? turnstileToken : undefined,
      };

      const res = await createToken(payload);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Error creating canary token');
    } finally {
      setLoading(false);
      if (turnstileSiteKey && window.turnstile) {
        // el token de Turnstile es de un solo uso
        window.turnstile.reset(turnstileWidgetId.current);
        setTurnstileToken('');
      }
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="text-center mb-10">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 text-xs font-semibold uppercase tracking-wider mb-4">
          <ShieldAlert className="w-4 h-4 text-yellow-500" />
          Tactical Deception & Intrusion Detection
        </div>
        <h1 className="text-4xl font-extrabold text-white tracking-tight sm:text-5xl">
          Canary Token Generator
        </h1>
        <p className="mt-3 text-lg text-slate-400 max-w-2xl mx-auto">
          Plant high-fidelity digital tripwires inside files, databases, credentials, and infrastructure. 
          Get real-time forensic alerts the instant an attacker discovers them.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Form Column */}
        <div className="lg:col-span-7 space-y-6">
          <form onSubmit={handleSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
            <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-yellow-500 text-slate-950 text-xs flex items-center justify-center font-bold">1</span>
              Select Canary Token Type
            </h2>

            {/* Token Selector Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-6">
              {TOKEN_TYPES.map((type) => (
                <button
                  type="button"
                  key={type.id}
                  onClick={() => setSelectedType(type.id)}
                  className={`p-3.5 rounded-lg border text-left transition-all relative ${
                    selectedType === type.id
                      ? 'bg-yellow-500/10 border-yellow-500 ring-1 ring-yellow-500/50'
                      : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-2.5">
                      <div className="p-1.5 rounded bg-slate-900 border border-slate-800">
                        {type.icon}
                      </div>
                      <div>
                        <div className="font-semibold text-sm text-slate-100">{type.name}</div>
                        <div className="text-xs text-slate-400">{type.category}</div>
                      </div>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 mt-2 line-clamp-2 leading-relaxed">
                    {type.description}
                  </p>
                  <span className="inline-block mt-2 text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-800 text-yellow-400 border border-slate-700">
                    {type.badge}
                  </span>
                </button>
              ))}
            </div>

            {/* Token Metadata Config */}
            <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2 pt-2 border-t border-slate-800">
              <span className="w-6 h-6 rounded-full bg-yellow-500 text-slate-950 text-xs flex items-center justify-center font-bold">2</span>
              Token Deployment Details
            </h2>

            <div className="space-y-4 mb-6">
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                  Deployment Memo / Label
                </label>
                <input
                  type="text"
                  value={label}
                maxLength={120}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="e.g. AWS Keys placed in CI/CD runner #4 or Finance_Salaries.pdf"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-yellow-500"
                />
              </div>

              {/* Type-Specific Fields */}
              {selectedType === 'envfile' && (
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                    Decoy Recipe Template
                  </label>
                  <select
                    value={envRecipe}
                    onChange={(e) => setEnvRecipe(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-yellow-500"
                  >
                    <option value="aws">AWS Deployment Secrets (AKIA / STS Canary)</option>
                    <option value="db">PostgreSQL Database Master Credentials</option>
                    <option value="github">GitHub Actions CI/CD Deployment Token</option>
                    <option value="stripe">Stripe Merchant Live API Keys</option>
                    <option value="combo">Multi-Cloud Full Stack Decoy (.env bundle)</option>
                  </select>
                </div>
              )}

              {selectedType === 'slowredirect' && (
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                    Target Destination URL
                  </label>
                  <input
                    type="url"
                    value={targetURL}
                    onChange={(e) => setTargetURL(e.target.value)}
                    placeholder="https://company-internal-wiki.com/login"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-yellow-500"
                    required
                  />
                  <p className="text-xs text-slate-400 mt-1">
                    Victims will be smoothly forwarded here after their device canvas & WebGL fingerprints are exfiltrated.
                  </p>
                </div>
              )}
            </div>

            {/* Notification Channel */}
            <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2 pt-2 border-t border-slate-800">
              <span className="w-6 h-6 rounded-full bg-yellow-500 text-slate-950 text-xs flex items-center justify-center font-bold">3</span>
              Real-time Alerting Channel
            </h2>

            <div className="space-y-4 mb-6">
              <div className="grid grid-cols-3 gap-2">
                {['none', 'webhook', 'telegram'].map((ch) => (
                  <button
                    key={ch}
                    type="button"
                    onClick={() => setNotifyChannel(ch)}
                    className={`py-2 px-3 rounded-lg border text-center text-xs font-semibold uppercase tracking-wider transition ${
                      notifyChannel === ch
                        ? 'bg-yellow-500/20 border-yellow-500 text-yellow-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    {ch === 'none' ? 'Web Dashboard Only' : ch}
                  </button>
                ))}
              </div>

              {notifyChannel === 'webhook' && (
                <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Webhook URL (POST)
                    </label>
                    <input
                      type="url"
                      value={webhookURL}
                      onChange={(e) => setWebhookURL(e.target.value)}
                      placeholder="https://siem.corp.internal/api/canary-alerts"
                      className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-yellow-500"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      HMAC SHA256 Signature Secret (Optional)
                    </label>
                    <input
                      type="text"
                      value={webhookSecret}
                      onChange={(e) => setWebhookSecret(e.target.value)}
                      placeholder="canary-signing-secret"
                      className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-yellow-500"
                    />
                  </div>
                </div>
              )}

              {notifyChannel === 'telegram' && (
                <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Telegram Chat ID
                    </label>
                    <input
                      type="text"
                      value={telegramChatID}
                      onChange={(e) => setTelegramChatID(e.target.value)}
                      placeholder="-100123456789 or @channel"
                      className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-yellow-500"
                      required
                    />
                  </div>
                </div>
              )}
            </div>

            {error && (
              <div className="p-3 bg-red-950/50 border border-red-500/50 rounded-lg text-red-200 text-xs mb-4">
                {error}
              </div>
            )}

            {turnstileSiteKey && <div ref={turnstileRef} className="mb-4 flex justify-center" />}

            <button
              type="submit"
              disabled={loading || (!!turnstileSiteKey && !turnstileToken)}
              className="w-full py-3.5 px-4 bg-yellow-500 hover:bg-yellow-400 text-slate-950 font-bold rounded-lg shadow-lg hover:shadow-yellow-500/20 transition flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? (
                <span>Fabricating Canary Artifact...</span>
              ) : (
                <>
                  <Lock className="w-4 h-4" />
                  <span>Generate Canary Token</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right Output Column */}
        <div className="lg:col-span-5">
          {result ? (
            <div className="bg-slate-900 border border-yellow-500/40 rounded-xl p-6 shadow-2xl space-y-5 animate-in fade-in duration-300">
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse"></span>
                  <h3 className="font-bold text-white text-lg">Canary Active & Armed</h3>
                </div>
                <span className="text-xs font-mono uppercase bg-yellow-500/10 text-yellow-400 px-2 py-0.5 rounded border border-yellow-500/20">
                  {result.token.type}
                </span>
              </div>

              {/* Secret Manage Key Box */}
              <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg space-y-2">
                <div className="flex items-center justify-between text-xs font-semibold text-amber-400">
                  <span>Secret Management URL</span>
                  <span className="text-[11px] text-amber-400/80 font-normal">Save this link</span>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    readOnly
                    value={result.manage_url}
                    className="w-full bg-slate-950 border border-amber-500/30 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200 select-all"
                  />
                  <button
                    onClick={() => handleCopy(result.manage_url, 'manage')}
                    className="p-1.5 rounded bg-slate-800 text-slate-200 hover:bg-slate-700"
                    title="Copy manage link"
                  >
                    {copiedKey === 'manage' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
                <button
                  onClick={() => onNavigateManage(result.manage_key)}
                  className="w-full mt-2 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-xs font-semibold rounded border border-amber-500/30 flex items-center justify-center gap-1.5 transition"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  View Incident & Event Dashboard
                </button>
              </div>

              {/* Download Artifact Button */}
              {result.download_url && (
                <div>
                  <button
                    type="button"
                    onClick={() =>
                      downloadArtifact(result.manage_key, result.artifact_name || 'artifact').catch((e) => setError(e.message))
                    }
                    className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg shadow flex items-center justify-center gap-2 text-sm transition"
                  >
                    <Download className="w-4 h-4" />
                    Download Bait File ({result.artifact_name || 'artifact'})
                  </button>
                </div>
              )}

              {/* Snippet / Trigger URL */}
              {result.snippet && (
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-semibold text-slate-300">Decoy Snippet / Injection</span>
                    <button
                      onClick={() => handleCopy(result.snippet || '', 'snippet')}
                      className="text-xs text-yellow-400 hover:underline flex items-center gap-1"
                    >
                      {copiedKey === 'snippet' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      Copy Code
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-48">
                    {result.snippet}
                  </pre>
                </div>
              )}

              {/* Instructions */}
              <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-400 space-y-1">
                <div className="font-semibold text-slate-300 flex items-center gap-1">
                  <Info className="w-3.5 h-3.5 text-yellow-500" /> Deployment Tactics:
                </div>
                <p className="leading-relaxed">{result.instructions}</p>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-8 text-center space-y-4">
              <div className="w-16 h-16 rounded-full bg-slate-800/80 border border-slate-700 mx-auto flex items-center justify-center text-yellow-400">
                <Bell className="w-8 h-8" />
              </div>
              <h3 className="text-lg font-bold text-slate-200">Tripwire Ready to Deploy</h3>
              <p className="text-xs text-slate-400 max-w-sm mx-auto leading-relaxed">
                Choose your deception vector on the left and configure your alert channel.
                Once created, you will receive instant download packages, copyable snippets, and a private incident inspection link.
              </p>
              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800/80 text-left text-xs text-slate-400 space-y-2">
                <div className="font-semibold text-slate-300">Forensics Collected per Trigger:</div>
                <ul className="list-disc list-inside space-y-1">
                  <li>Direct Source IP & Cloudflare IP resolution</li>
                  <li>MaxMind GeoIP City & Country location</li>
                  <li>User-Agent & Client Hints (Sec-CH-UA)</li>
                  <li>Device Fingerprint (Canvas Hash, WebGL, Cores)</li>
                  <li>Rate limiting & Deduplication storm protection</li>
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
