const API_URL =
  import.meta.env.VITE_API_URL ||
  "http://127.0.0.1:8001";

let authToken = null;

// Called by AuthContext on login/logout/startup. Kept as a plain module
// -level setter (rather than reading localStorage on every request) so
// there is exactly one place that decides what token is "current".
export function setAuthToken(token) {
  authToken = token || null;
}

export class AuthError extends Error {}

async function requestJson(path, options = {}) {
  const headers = {
    ...(options.headers || {}),
  };

  if (authToken) {
    headers.Authorization = `Bearer ${authToken}`;
  }

  const response = await fetch(
    `${API_URL}${path}`,
    { ...options, headers }
  );
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      data.detail ||
      "The investigation request failed.";

    if (response.status === 401) {
      throw new AuthError(message);
    }

    throw new Error(message);
  }

  return data;
}

export function registerUser(email, password) {
  return requestJson("/auth/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email, password }),
  });
}

export function loginUser(email, password) {
  return requestJson("/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email, password }),
  });
}

export function getInvestigations() {
  return requestJson("/investigations");
}

export function investigateText(content) {
  return requestJson("/investigate", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ content }),
  });
}

export function investigateFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  return requestJson("/investigate-file", {
    method: "POST",
    body: formData,
  });
}

export function challengeInvestigation(
  investigationId
) {
  return requestJson("/challenge", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      investigation_id: investigationId,
    }),
  });
}
