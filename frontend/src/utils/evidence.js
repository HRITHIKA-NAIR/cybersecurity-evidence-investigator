export function buildEvidenceIndex(items = []) {
  return new Map(
    items.map((item) => [item.id, item])
  );
}

export function evidenceLabel(item) {
  if (!item) {
    return "Evidence unavailable";
  }

  return (
    item.provenance?.summary ||
    `${item.source}: ${formatValue(item.value)}`
  );
}

export function formatValue(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return "Not available";
  }

  if (typeof value === "string") {
    return value;
  }

  return JSON.stringify(value, null, 2);
}
