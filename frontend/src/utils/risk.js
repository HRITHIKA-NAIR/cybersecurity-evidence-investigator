export function getRiskClass(verdict) {
  if (verdict === "High Risk") {
    return "risk-high";
  }

  if (verdict === "Suspicious") {
    return "risk-suspicious";
  }

  if (verdict === "Low Risk") {
    return "risk-low";
  }

  return "risk-inconclusive";
}

export function getSeverityClass(severity) {
  return `severity-${String(
    severity || "info"
  ).toLowerCase()}`;
}
