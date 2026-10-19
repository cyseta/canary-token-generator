import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, 
  ArrowLeft, 
  RefreshCw, 
  Power, 
  Download, 
  Globe, 
  Clock, 
  Terminal, 
  Eye, 
  Layers,
  ChevronLeft,
  ChevronRight,
  Code,
  Trash2
} from 'lucide-react';
import { getManageToken, toggleTokenActive, deleteToken, downloadArtifact, CanaryToken, CanaryEvent } from '../../api';

interface Props {
  manageKey: string;
  onBack: () => void;
}

export const ManagePage: React.FC<Props> = ({ manageKey, onBack }) => {
  const [token, setToken] = useState<CanaryToken | null>(null);
  const [events, setEvents] = useState<CanaryEvent[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [offset, setOffset] = useState<number>(0);
  const limit = 20;

  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<CanaryEvent | null>(null);

  const fetchDetails = async (pageOffset = offset) => {
    try {
      setError(null);
      const data = await getManageToken(manageKey, limit, pageOffset);
      setToken(data.token);
      setEvents(data.events || []);
      setTotal(data.total || 0);
      setOffset(pageOffset);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch token telemetry');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDetails(0);
  }, [manageKey]);

  const handleToggle = async () => {
    if (!token) return;
    try {
      const updated = await toggleTokenActive(manageKey, !token.is_active);
      setToken(updated);
    } catch (err: any) {
      alert(err.message || 'Failed to update token state');
    }
  };

  const handleDelete = async () => {
    if (!window.confirm('Delete this token and ALL its recorded events? This cannot be undone.')) return;
    try {
      await deleteToken(manageKey);
      onBack();
    } catch (err: any) {
      alert(err.message || 'Failed to delete token');
    }
  };

  const handleDownload = () => {
    downloadArtifact(manageKey).catch((err: any) => alert(err.message || 'Failed to download artifact'));
  };

  const handleRefresh = () => {
    setRefreshing(true);
    fetchDetails(offset);
  };

  const parseJSON = (str?: string) => {
    if (!str) return {};
    try {
      return JSON.parse(str);
    } catch {
      return { raw: str };
    }
  };

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-16 text-center">
        <RefreshCw className="w-8 h-8 text-yellow-400 animate-spin mx-auto mb-4" />
        <p className="text-slate-400 text-sm">Querying canary sensor telemetry...</p>
      </div>
    );
  }

  if (error || !token) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-16 text-center">
        <div className="p-6 bg-red-950/40 border border-red-500/40 rounded-xl space-y-4">
          <ShieldAlert className="w-10 h-10 text-red-400 mx-auto" />
          <h2 className="text-lg font-bold text-white">Canary Sensor Not Found</h2>
          <p className="text-sm text-slate-300">{error || 'Invalid or revoked management key.'}</p>
          <button
            onClick={onBack}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg inline-flex items-center gap-2"
          >
            <ArrowLeft className="w-4 h-4" /> Back to Generator
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      {/* Top Bar Navigation */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="text-xs font-semibold text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Generator
        </button>
        <div className="flex items-center gap-3">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-lg text-xs font-semibold text-slate-300 flex items-center gap-1.5 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleToggle}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
              token.is_active
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30'
                : 'bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30'
            }`}
          >
            <Power className="w-3.5 h-3.5" />
            {token.is_active ? 'Sensor Armed (Active)' : 'Sensor Disarmed (Silenced)'}
          </button>
        </div>
      </div>

      {/* Sensor Metadata Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <h2 className="text-xl font-bold text-white">{token.label}</h2>
              <span className="text-xs font-mono uppercase bg-yellow-500/10 text-yellow-400 px-2 py-0.5 rounded border border-yellow-500/20">
                {token.type}
              </span>
            </div>
            <p className="text-xs font-mono text-slate-400">Token ID: {token.id}</p>
          </div>
          <div className="flex items-center gap-6">
            <div className="text-right">
              <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Total Hits</div>
              <div className="text-2xl font-extrabold text-yellow-400">{token.hit_count}</div>
            </div>
            {['pdf', 'docx', 'envfile', 'kubeconfig', 'webbug', 'mysql'].includes(token.type) && (
              <button
                type="button"
                onClick={handleDownload}
                className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 flex items-center gap-2 transition"
              >
                <Download className="w-3.5 h-3.5" />
                Artifact
              </button>
            )}
            <button
              type="button"
              onClick={handleDelete}
              className="px-3.5 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-300 text-xs font-semibold rounded-lg border border-red-500/30 flex items-center gap-2 transition"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Delete
            </button>
          </div>
        </div>

        {/* Details Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-4 text-xs">
          <div>
            <span className="text-slate-500 block mb-0.5 font-semibold">Alert Channel</span>
            <span className="text-slate-300 font-mono uppercase">{token.notify_channel}</span>
          </div>
          <div>
            <span className="text-slate-500 block mb-0.5 font-semibold">Created Timestamp</span>
            <span className="text-slate-300">{new Date(token.created_at).toLocaleString()}</span>
          </div>
          <div>
            <span className="text-slate-500 block mb-0.5 font-semibold">Sensor Trigger URL</span>
            <span className="text-slate-300 font-mono break-all">/t/{token.id}</span>
          </div>
        </div>
      </div>

      {/* Events Stream Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-bold text-white text-sm flex items-center gap-2">
            <Layers className="w-4 h-4 text-yellow-400" />
            Sensor Incident Log ({total} recorded)
          </h3>
          <span className="text-xs text-slate-500">
            Deduplication Window: 5m silence interval per IP
          </span>
        </div>

        {events.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-sm">
            No activations recorded yet. Plant the canary bait in your target environment to begin logging telemetry.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Trigger Time</th>
                  <th className="py-3 px-4">Source IP</th>
                  <th className="py-3 px-4">GeoIP Location</th>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4">User-Agent</th>
                  <th className="py-3 px-4 text-right">Inspection</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {events.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 whitespace-nowrap text-slate-400 font-mono">
                      <div className="flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-slate-500" />
                        {new Date(ev.created_at).toLocaleTimeString()}
                      </div>
                      <div className="text-[10px] text-slate-600">
                        {new Date(ev.created_at).toLocaleDateString()}
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono font-semibold text-yellow-300">
                      {ev.source_ip}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5">
                        <Globe className="w-3.5 h-3.5 text-slate-500" />
                        <span className="font-semibold text-slate-200">
                          {ev.country || 'Unknown'}
                        </span>
                        {ev.city && <span className="text-slate-400">({ev.city})</span>}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono uppercase text-[10px] border border-slate-700">
                        {ev.protocol}
                      </span>
                    </td>
                    <td className="py-3 px-4 max-w-xs truncate text-slate-400" title={ev.user_agent}>
                      {ev.user_agent || 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedEvent(ev)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-yellow-400 text-xs font-semibold transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        {total > limit && (
          <div className="p-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <div>
              Showing {offset + 1} to {Math.min(offset + limit, total)} of {total} events
            </div>
            <div className="flex items-center gap-2">
              <button
                disabled={offset === 0}
                onClick={() => fetchDetails(Math.max(0, offset - limit))}
                className="p-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                disabled={offset + limit >= total}
                onClick={() => fetchDetails(offset + limit)}
                className="p-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Forensic Inspection Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-base flex items-center gap-2">
                <Code className="w-4 h-4 text-yellow-400" />
                Raw Forensic Payload — {selectedEvent.source_ip}
              </h3>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <div>
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                HTTP Headers
              </div>
              <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-48">
                {JSON.stringify(parseJSON(selectedEvent.headers), null, 2)}
              </pre>
            </div>

            {selectedEvent.fingerprint && selectedEvent.fingerprint !== '{}' && (
              <div>
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                  Device Hardware & Canvas Fingerprint
                </div>
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-yellow-300 overflow-x-auto whitespace-pre-wrap max-h-48">
                  {JSON.stringify(parseJSON(selectedEvent.fingerprint), null, 2)}
                </pre>
              </div>
            )}

            <div className="text-right pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
