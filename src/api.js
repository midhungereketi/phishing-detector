export async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(`/api${path}`, {
      credentials: 'same-origin',
      ...options,
      headers: { 'Content-Type': 'application/json', 'X-PhishGuard': '1', ...options.headers },
    });
  } catch {
    throw new Error('Cannot reach the API. Start the Python backend on port 8000.');
  }
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data?.detail;
    const message = Array.isArray(detail) ? detail.map(item => `${item.loc.at(-1)}: ${item.msg}`).join('; ') : detail;
    const error = new Error(message || 'API unavailable. Check that the Python backend is running.');
    error.status = response.status;
    throw error;
  }
  return data;
}

export const send = (path, body, method = 'POST') => api(path, { method, body: JSON.stringify(body) });
export const formatDate = value => new Date(value).toLocaleString();
