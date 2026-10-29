CREATE TABLE "asset_technologies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"asset_id" uuid NOT NULL,
	"category" text NOT NULL,
	"name" text NOT NULL,
	"version" text,
	"evidence" text NOT NULL,
	"current" boolean DEFAULT true NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_assessment_id" uuid
);
--> statement-breakpoint
ALTER TABLE "asset_technologies" ADD CONSTRAINT "asset_technologies_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "asset_technologies" ADD CONSTRAINT "asset_technologies_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "asset_technologies" ADD CONSTRAINT "asset_technologies_last_assessment_id_assessments_id_fk" FOREIGN KEY ("last_assessment_id") REFERENCES "public"."assessments"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "asset_technologies_asset_tech_idx" ON "asset_technologies" USING btree ("asset_id","category","name");--> statement-breakpoint
CREATE INDEX "asset_technologies_org_idx" ON "asset_technologies" USING btree ("organization_id","category","name");