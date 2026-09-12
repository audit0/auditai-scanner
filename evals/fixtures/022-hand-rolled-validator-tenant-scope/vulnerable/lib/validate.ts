/**
 * Hand-written request validator (no zod dependency): just enough shape-checking that the route
 * "looks" validated. It happily accepts a caller-chosen tenantId — validation is not authorization.
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
