CREATE TYPE "public"."authorization_status" AS ENUM('pending', 'approved', 'revoked');--> statement-breakpoint
CREATE TABLE "assessment_findings" (
	"organization_id" uuid NOT NULL,
	"assessment_id" uuid NOT NULL,
	"finding_id" uuid NOT NULL,
	"evidence" text NOT NULL,
	CONSTRAINT "assessment_findings_assessment_id_finding_id_pk" PRIMARY KEY("assessment_id","finding_id")
);
--> statement-breakpoint
CREATE TABLE "finding_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"finding_id" uuid NOT NULL,
	"actor_user_id" uuid,
	"from_status" "finding_status",
	"to_status" "finding_status" NOT NULL,
	"reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "authorizations" ADD COLUMN "excluded_hostnames" text[] DEFAULT '{}'::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "authorizations" ADD COLUMN "status" "authorization_status" DEFAULT 'pending' NOT NULL;--> statement-breakpoint
ALTER TABLE "authorizations" ADD COLUMN "created_by" uuid;--> statement-breakpoint
ALTER TABLE "authorizations" ADD COLUMN "approved_by" uuid;--> statement-breakpoint
ALTER TABLE "authorizations" ADD COLUMN "approved_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "authorizations" ADD COLUMN "revoked_by" uuid;--> statement-breakpoint
ALTER TABLE "authorizations" ADD COLUMN "revoked_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "authorizations" ADD COLUMN "revoke_reason" text;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "fingerprint" text;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "status_reason" text;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "status_changed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "status_changed_by" uuid;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "accepted_until" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "last_seen_at" timestamp with time zone DEFAULT now() NOT NULL;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "last_assessment_id" uuid;--> statement-breakpoint
ALTER TABLE "assessment_findings" ADD CONSTRAINT "assessment_findings_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_findings" ADD CONSTRAINT "assessment_findings_assessment_id_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."assessments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_findings" ADD CONSTRAINT "assessment_findings_finding_id_findings_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."findings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_events" ADD CONSTRAINT "finding_events_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_events" ADD CONSTRAINT "finding_events_finding_id_findings_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."findings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_events" ADD CONSTRAINT "finding_events_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "assessment_findings_finding_idx" ON "assessment_findings" USING btree ("finding_id");--> statement-breakpoint
CREATE INDEX "finding_events_finding_idx" ON "finding_events" USING btree ("finding_id","created_at");--> statement-breakpoint
ALTER TABLE "authorizations" ADD CONSTRAINT "authorizations_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authorizations" ADD CONSTRAINT "authorizations_approved_by_users_id_fk" FOREIGN KEY ("approved_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authorizations" ADD CONSTRAINT "authorizations_revoked_by_users_id_fk" FOREIGN KEY ("revoked_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_status_changed_by_users_id_fk" FOREIGN KEY ("status_changed_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_last_assessment_id_assessments_id_fk" FOREIGN KEY ("last_assessment_id") REFERENCES "public"."assessments"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
-- Dados existentes: cada execução gravava achados próprios. Calcula a impressão digital, registra as observações
-- por execução e consolida duplicatas no achado mais recente de cada (ativo, impressão digital).
UPDATE "findings" SET "fingerprint" = lower("category") || '|' || lower("title"), "last_seen_at" = "discovered_at", "last_assessment_id" = "assessment_id";--> statement-breakpoint
INSERT INTO "assessment_findings" ("organization_id", "assessment_id", "finding_id", "evidence")
  SELECT "organization_id", "assessment_id", "id", "evidence" FROM "findings" WHERE "assessment_id" IS NOT NULL;--> statement-breakpoint
CREATE TEMP TABLE "finding_keep" AS
  SELECT "id", first_value("id") OVER w AS "keep", min("discovered_at") OVER w AS "first_seen", max("discovered_at") OVER w AS "last_seen"
  FROM "findings" WINDOW w AS (PARTITION BY "organization_id", "asset_id", "fingerprint" ORDER BY "discovered_at" DESC, "id" ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING);--> statement-breakpoint
DELETE FROM "assessment_findings" af USING "finding_keep" k
  WHERE af."finding_id" = k."id" AND k."id" <> k."keep"
  AND EXISTS (SELECT 1 FROM "assessment_findings" x WHERE x."assessment_id" = af."assessment_id" AND x."finding_id" = k."keep");--> statement-breakpoint
UPDATE "assessment_findings" af SET "finding_id" = k."keep" FROM "finding_keep" k WHERE af."finding_id" = k."id" AND k."id" <> k."keep";--> statement-breakpoint
UPDATE "findings" f SET "discovered_at" = k."first_seen", "last_seen_at" = k."last_seen" FROM "finding_keep" k WHERE f."id" = k."id" AND k."id" = k."keep";--> statement-breakpoint
DELETE FROM "findings" f USING "finding_keep" k WHERE f."id" = k."id" AND k."id" <> k."keep";--> statement-breakpoint
DROP TABLE "finding_keep";--> statement-breakpoint
ALTER TABLE "findings" ALTER COLUMN "fingerprint" SET NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "findings_asset_fingerprint_idx" ON "findings" USING btree ("organization_id","asset_id","fingerprint");--> statement-breakpoint
ALTER TABLE "assets" DROP COLUMN "approved";