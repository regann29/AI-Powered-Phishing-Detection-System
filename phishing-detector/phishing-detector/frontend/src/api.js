const BASE = import.meta.env.VITE_API_URL ?? "";

export class ApiError extends Error {
  constructor(message, status, field) {
    super(message);
    this.status = status;
    this.field = field;
  }
}

async function request(path, { method = "GET", body, token } = {}) {
  let response;
  try {
    response = await fetch(`${BASE}/api${path}`, {
      method,
      headers: {
        ...(body ? { "Content-Type": "application/json" } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError("Cannot reach the server. Check that the backend is running.", 0);
  }

  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = data.error ?? {};
    throw new ApiError(err.message ?? "The request failed.", response.status, err.field);
  }
  return data;
}

export const api = {
  register: (email, password) => request("/auth/register", { method: "POST", body: { email, password } }),
  login: (email, password) => request("/auth/login", { method: "POST", body: { email, password } }),
  scanUrl: (token, url) => request("/scan/url", { method: "POST", token, body: { url } }),
  scanEmail: (token, email) => request("/scan/email", { method: "POST", token, body: email }),
  history: (token) => request("/scans?per_page=20", { token }),
  deleteScan: (token, id) => request(`/scans/${id}`, { method: "DELETE", token }),
};
