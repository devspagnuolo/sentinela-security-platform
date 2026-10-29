CREATE TABLE "cloud_connectors" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"provider" text NOT NULL,
	"name" text NOT NULL,
	"credentials" text NOT NULL,
	"credential_hint" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"next_sync_at" timestamp with time zone DEFAULT now() NOT NULL,
	"sync_locked_at" timestamp with time zone,
	"last_sync_at" timestamp with time zone,
	"last_error" text,
	"zone_count" integer,
	"host_count" integer,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "discovered_hosts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"connector_id" uuid NOT NULL,
	"hostname" text NOT NULL,
	"zone" text NOT NULL,
	"record_types" text[] NOT NULL,
	"targets" text[] NOT NULL,
	"internal" boolean DEFAULT false NOT NULL,
	"current" boolean DEFAULT true NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "cloud_connectors" ADD CONSTRAINT "cloud_connectors_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_connectors" ADD CONSTRAINT "cloud_connectors_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "discovered_hosts" ADD CONSTRAINT "discovered_hosts_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "discovered_hosts" ADD CONSTRAINT "discovered_hosts_connector_id_cloud_connectors_id_fk" FOREIGN KEY ("connector_id") REFERENCES "public"."cloud_connectors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "cloud_connectors_org_idx" ON "cloud_connectors" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "cloud_connectors_due_idx" ON "cloud_connectors" USING btree ("next_sync_at") WHERE "cloud_connectors"."enabled";--> statement-breakpoint
CREATE UNIQUE INDEX "discovered_hosts_connector_host_idx" ON "discovered_hosts" USING btree ("connector_id","hostname");--> statement-breakpoint
CREATE INDEX "discovered_hosts_org_idx" ON "discovered_hosts" USING btree ("organization_id","hostname");