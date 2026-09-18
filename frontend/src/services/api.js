const API_URL =
  import.meta.env.VITE_API_URL ||
  "http://127.0.0.1:8001";

async function requestJson(path, options) {
  const response = await fetch(
    `${API_URL}${path}`,
    options
  );
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.detail ||
        "The investigation request failed."
    );
  }

  return data;
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
