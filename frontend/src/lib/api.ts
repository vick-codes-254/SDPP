// Typed API client with in-memory + localStorage tokens and one-shot refresh.

const BASE = "/api/v1";

let accessToken: string | null = localStorage.getItem("sdpp_access");
let refreshToken: string | null = localStorage.getItem("sdpp_refresh");

export function setTokens(access: string, refresh: string): void {
  accessToken = access;
  refreshToken = refresh;
  localStorage.setItem("sdpp_access", access);
  localStorage.setItem("sdpp_refresh", refresh);
}

export function clearTokens(): void {
  accessToken = null;
  refreshToken = null;
  localStorage.removeItem("sdpp_access");
  localStorage.removeItem("sdpp_refresh");
}

export function isAuthenticated(): boolean {
  return accessToken !== null;
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

async function tryRefresh(): Promise<boolean> {
  if (!refreshToken) return false;
  const res = await fetch(`${BASE}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (!res.ok) {
    clearTokens();
    return false;
  }
  const data = await res.json();
  setTokens(data.access_token, data.refresh_token);
  return true;
}

async function request(path: string, init: RequestInit = {}, retry = true): Promise<Response> {
  const headers = new Headers(init.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (res.status === 401 && retry && refreshToken) {
    if (await tryRefresh()) return request(path, init, false);
  }
  return res;
}

async function unwrap<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let code = "error";
    let detail = res.statusText;
    try {
      const body = await res.json();
      code = body.error ?? code;
      detail = body.detail ?? detail;
    } catch {
      /* non-JSON */
    }
    throw new ApiError(res.status, code, detail);
  }
  return (await res.json()) as T;
}

export const api = {
  async login(identifier: string, password: string) {
    const res = await fetch(`${BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier, password }),
    });
    const data = await unwrap<{ access_token: string; refresh_token: string }>(res);
    setTokens(data.access_token, data.refresh_token);
    return data;
  },
  async logout() {
    if (refreshToken) {
      await request("/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      }).catch(() => undefined);
    }
    clearTokens();
  },
  async get<T>(path: string): Promise<T> {
    return unwrap<T>(await request(path));
  },
  async post<T>(path: string, body?: unknown): Promise<T> {
    return unwrap<T>(
      await request(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    );
  },
  async patch<T>(path: string, body?: unknown): Promise<T> {
    return unwrap<T>(
      await request(path, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    );
  },
  async put<T>(path: string, body?: unknown): Promise<T> {
    return unwrap<T>(
      await request(path, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    );
  },
  async del<T>(path: string): Promise<T> {
    return unwrap<T>(await request(path, { method: "DELETE" }));
  },
  async upload<T>(path: string, file: File, fields: Record<string, string>): Promise<T> {
    const form = new FormData();
    form.append("upload", file);
    for (const [k, v] of Object.entries(fields)) form.append(k, v);
    return unwrap<T>(await request(path, { method: "POST", body: form }));
  },
  async download(path: string): Promise<Blob> {
    const res = await request(path);
    if (!res.ok) throw new ApiError(res.status, "download_failed", "Download failed");
    return res.blob();
  },
};
