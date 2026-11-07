function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }

  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b)
    );
    // Preserve every own JSON key, including __proto__. Assigning that key to
    // a normal object invokes its prototype setter and silently omits it from
    // the serialized value, creating collisions in signatures and request hashes.
    const out: Record<string, unknown> = Object.create(null);
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
