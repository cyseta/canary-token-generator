export interface CreateTokenPayload {
  type: string;
  label: string;
  target_url?: string;
  notify_channel: string;
  webhook_url?: string;
  webhook_secret?: string;
  telegram_chat_id?: string;
  turnstile_token?: string;
  options?: Record<string, any>;
}

/** Vista segura de la configuración de notificación (el backend nunca devuelve secretos ni la URL completa). */
export interface NotifySummary {
  webhook_host?: string;
  has_webhook_secret?: boolean;
  telegram_chat_id?: string;
}

export interface CanaryToken {
  id: string;
  type: string;
  label: string;
  target_url?: string;
  notify_channel: string;
  notify: NotifySummary;
  hit_count: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CanaryEvent {
  id: string;
  token_id: string;
  source_ip: string;
  user_agent: string;
  referer?: string;
  protocol: string;
  country?: string;
  city?: string;
  headers?: string;
  fingerprint?: string;
  created_at: string;
}

export interface CreateTokenResponse {
  token: CanaryToken;
  /** Secreto de gestión: se muestra UNA sola vez; el servidor solo conserva su hash. */
  manage_key: string;
  manage_url: string;
  artifact_name?: string;
  content_type?: string;
  snippet?: string;
  instructions?: string;
  download_url?: string;
  trigger_url?: string;
  metadata?: Record<string, any>;
}

export interface ManageResponse {
  token: CanaryToken;
  events: CanaryEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface PublicConfig {
  turnstile_site_key: string;
}

const API_BASE = '';
const KEY_HEADER = 'X-Manage-Key';

async function parse<T>(res: Response, fallback: string): Promise<T> {
  let data: any = null;
  try {
    data = await res.json();
  } catch {
    /* respuesta no JSON */
  }
  if (!res.ok || !data || !data.success) {
    throw new Error((data && data.error) || fallback);
  }
  return data.data as T;
}

export async function getPublicConfig(): Promise<PublicConfig> {
  try {
    const res = await fetch(`${API_BASE}/api/config`);
    return await parse<PublicConfig>(res, 'config');
  } catch {
    return { turnstile_site_key: '' };
  }
}

export async function createToken(payload: CreateTokenPayload): Promise<CreateTokenResponse> {
  const res = await fetch(`${API_BASE}/api/tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return parse<CreateTokenResponse>(res, 'Failed to create canary token');
}

// La clave de gestión viaja en una CABECERA (no en la URL): así no queda en logs de acceso ni en el historial.
export async function getManageToken(manageKey: string, limit = 50, offset = 0): Promise<ManageResponse> {
  const res = await fetch(`${API_BASE}/api/manage?limit=${limit}&offset=${offset}`, {
    headers: { [KEY_HEADER]: manageKey },
    cache: 'no-store',
  });
  return parse<ManageResponse>(res, 'Failed to fetch token details');
}

export async function toggleTokenActive(manageKey: string, isActive: boolean): Promise<CanaryToken> {
  const res = await fetch(`${API_BASE}/api/manage/toggle`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', [KEY_HEADER]: manageKey },
    body: JSON.stringify({ is_active: isActive }),
  });
  return parse<CanaryToken>(res, 'Failed to toggle token state');
}

export async function deleteToken(manageKey: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/manage`, { method: 'DELETE', headers: { [KEY_HEADER]: manageKey } });
  await parse<unknown>(res, 'Failed to delete token');
}

/** Descarga el artefacto autenticándose con la clave de gestión (un <a href> no puede enviar cabeceras). */
export async function downloadArtifact(manageKey: string, fallbackName = 'artifact'): Promise<void> {
  const res = await fetch(`${API_BASE}/api/manage/download`, { headers: { [KEY_HEADER]: manageKey } });
  if (!res.ok) {
    throw new Error('Failed to download artifact');
  }
  const cd = res.headers.get('Content-Disposition') || '';
  const m = /filename="?([^";]+)"?/i.exec(cd);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = m ? m[1] : fallbackName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
