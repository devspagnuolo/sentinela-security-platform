ALTER TABLE "findings" DROP CONSTRAINT "findings_assessment_id_assessments_id_fk";
--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "audit_retention_days" integer DEFAULT 730 NOT NULL;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "assessment_retention_days" integer;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "closed_finding_retention_days" integer;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "scope_contact_retention_days" integer DEFAULT 180 NOT NULL;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_assessment_id_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."assessments"("id") ON DELETE set null ON UPDATE no action;