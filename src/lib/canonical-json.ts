function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }

  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b)
    );
    const out: Record<string, unknown> = {};
    for (const [key, child] of entries) {
      out[key] = sortValue(child);
    }
    return out;
  }

  return value;
}

export function canonicalStringify(value: unknown): string {
  return JSON.stringify(sortValue(value));
}
