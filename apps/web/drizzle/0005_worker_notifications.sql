CREATE TYPE "public"."assessment_trigger" AS ENUM('manual', 'scheduled');--> statement-breakpoint
CREATE TABLE "notifications" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"title" text NOT NULL,
	"body" text DEFAULT '' NOT NULL,
	"link" text,
	"read_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "assessments" ALTER COLUMN "started_at" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "assessments" ALTER COLUMN "started_at" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "assessments" ADD COLUMN "trigger" "assessment_trigger" DEFAULT 'manual' NOT NULL;--> statement-breakpoint
ALTER TABLE "assessments" ADD COLUMN "requested_by" uuid;--> statement-breakpoint
ALTER TABLE "assessments" ADD COLUMN "attempts" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "assessments" ADD COLUMN "run_after" timestamp with time zone DEFAULT now() NOT NULL;--> statement-breakpoint
ALTER TABLE "assessments" ADD COLUMN "locked_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "assessments" ADD COLUMN "summary" jsonb;--> statement-breakpoint
ALTER TABLE "assessments" ADD COLUMN "created_at" timestamp with time zone DEFAULT now() NOT NULL;--> statement-breakpoint
-- Execuções anteriores à fila: a criação é o próprio início.
UPDATE "assessments" SET "created_at" = "started_at", "attempts" = 1 WHERE "started_at" IS NOT NULL;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "schedule_interval_days" integer;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "next_assessment_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "authorizations" ADD COLUMN "expiry_notified_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "notifications" ADD CONSTRAINT "notifications_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notifications" ADD CONSTRAINT "notifications_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "notifications_user_idx" ON "notifications" USING btree ("organization_id","user_id","created_at");--> statement-breakpoint
ALTER TABLE "assessments" ADD CONSTRAINT "assessments_requested_by_users_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "assessments_org_created_idx" ON "assessments" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "assessments_queue_idx" ON "assessments" USING btree ("run_after") WHERE "assessments"."status" = 'queued';--> statement-breakpoint
CREATE UNIQUE INDEX "assessments_active_asset_idx" ON "assessments" USING btree ("asset_id") WHERE "assessments"."status" in ('queued', 'running');--> statement-breakpoint
CREATE INDEX "assets_next_assessment_idx" ON "assets" USING btree ("next_assessment_at") WHERE "assets"."next_assessment_at" is not null;