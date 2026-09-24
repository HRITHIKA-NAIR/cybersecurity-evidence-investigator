import { accessToken } from "./auth";

const API_URL =
  import.meta.env.VITE_API_URL ||
  "http://127.0.0.1:8001";

async function requestJson(path, options = {}) {
  const token = await accessToken();
  let response;
  try { response = await fetch(
    `${API_URL}${path}`,
    { ...options, credentials: "omit", headers: { ...options.headers, Authorization: `Bearer ${token}` }, signal: options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(180000)]) : AbortSignal.timeout(180000) }
  ); } catch (cause) {
    if (options.signal?.aborted) throw cause;
    const error = new Error(cause.name === 'TimeoutError'
      ? 'The request timed out. It may still finish on the server. Check My investigations before submitting again.'
      : navigator.onLine === false
        ? 'You are offline. Reconnect and try again. Your input is still on this page.'
        : 'The service could not be reached. It may be waking up. Wait a moment, then try again.');
    error.cause = cause;
    throw error;
  }
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(
      (typeof data.detail === "string" ? data.detail : null) ||
        "The investigation request failed."
    );
    error.status = response.status;
    throw error;
  }

  return data;
}

export function getInvestigations(signal) {
  return requestJson("/investigations?summary=true", { signal });
}

export function getInvestigation(id, signal) {
  return requestJson(`/investigations/${id}`, { signal });
}

export function investigateText(content, signal) {
  return requestJson("/investigate", {
    method: "POST",
    signal,
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ content }),
  });
}

export function investigateFile(file, signal) {
  const formData = new FormData();
  formData.append("file", file);

  return requestJson("/investigate-file", {
    method: "POST",
    body: formData,
    signal,
  });
}

export function challengeInvestigation(
  investigationId, signal
) {
  return requestJson("/challenge", {
    method: "POST",
    signal,
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      investigation_id: investigationId,
    }),
  });
}

export function deleteInvestigation(id) {
  return requestJson(`/investigations/${id}`, { method: 'DELETE' });
}
