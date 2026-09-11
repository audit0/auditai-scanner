import { integer, pgTable, text, uuid } from "drizzle-orm/pg-core";

export const tenants = pgTable("tenants", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
});

export const profiles = pgTable("profiles", {
  id: uuid("id").primaryKey(),
  tenantId: uuid("tenant_id").notNull(),
  email: text("email").notNull(),
});

export const invoices = pgTable("invoices", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull(),
  amountCents: integer("amount_cents").notNull(),
  status: text("status").notNull().default("open"),
});
