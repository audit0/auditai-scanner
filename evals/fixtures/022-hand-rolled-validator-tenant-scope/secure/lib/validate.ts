/**
 * Hand-written request validator (no zod dependency): checks the search payload's shape. The
 * tenantId it produces is validated but still caller-supplied, so the route below never uses it
 * to scope a query — it is only good enough to know the request was well-formed.
 */
export interface InvoiceSearch {
  tenantId: string;
  status: string | null;
}

export function parseInvoiceSearch(body: unknown): InvoiceSearch {
  if (typeof body !== "object" || body === null) {
    throw new Error("Invalid request body");
  }
  const b = body as Record<string, unknown>;
  if (typeof b.tenantId !== "string" || b.tenantId.length === 0) {
    throw new Error("tenantId is required");
  }
  const status = typeof b.status === "string" ? b.status : null;
  return { tenantId: b.tenantId, status };
}
