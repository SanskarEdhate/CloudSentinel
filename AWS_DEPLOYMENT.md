# AWS deployment plan

This is a preparation guide only. No AWS resources have been created. Obtain explicit approval before provisioning billable resources. Exact costs depend on region, instance class, usage, storage, logs, and data transfer; use the AWS Pricing Calculator before deployment.

## 1. Account and region

- Use an organization-controlled AWS account with MFA, billing alerts, and a named administrative break-glass process.
- Choose one region near users and organizational data residency requirements. Record the region and resource owners.
- Configure AWS Budgets and Cost Anomaly Detection before provisioning. Tag resources with project, environment, owner, and expiry.

## 2. Network design

- Use a dedicated VPC spanning at least two Availability Zones for production availability.
- Place the internet-facing Application Load Balancer in public subnets; place EC2 application instances and RDS in private subnets.
- Use private route tables and controlled egress (NAT gateway or VPC endpoints as appropriate). Do not assign public addresses to RDS.
- Keep administration behind Systems Manager Session Manager or a restricted VPN/bastion workflow; avoid public SSH.

## 3. EC2 application

- Build a reproducible deployment artifact and install a supported Python runtime plus pinned dependencies on a patched Linux EC2 instance.
- Run the app as an unprivileged service account. Use a systemd service and health check; do not enable Flask debug mode.
- Initially deploy one instance for a controlled demonstration. For production availability, deploy across private subnets in an Auto Scaling group behind an ALB.
- Keep application code and evidence outside world-readable directories; use deployment automation and a documented rollback artifact.

## 4. Amazon RDS for MySQL

- Create a private RDS MySQL instance/subnet group in private subnets; disable public accessibility.
- Set backups, retention, maintenance windows, deletion protection, encryption at rest, and storage autoscaling according to recovery requirements.
- Store database credentials in Secrets Manager or Parameter Store SecureString, rotate them, and use a dedicated application user with only required table-level `SELECT`, `INSERT`, `UPDATE`, and `DELETE` privileges.
- Validate schema migration and restore procedures with a nonproduction database before production.

## 5. Security groups

- ALB ingress: HTTPS (443) from approved client CIDRs; redirect HTTP (80) to HTTPS if needed.
- EC2 ingress: application port only from the ALB security group. No unrestricted internet ingress to the app instances.
- RDS ingress: MySQL (3306) only from the EC2 application security group.
- Restrict egress to required services/endpoints. Never expose RDS or evidence storage publicly.

## 6. IAM for EC2

- Attach an instance profile with least-privilege access to the exact secret parameters, S3 evidence bucket/prefix, and CloudWatch log groups required by the application.
- Prefer short-lived role credentials. Do not put access keys in source code, `.env`, AMIs, or deployment scripts.
- Separate deployment permissions from runtime permissions and review CloudTrail activity.

## 7. Private S3 evidence storage

- Implement the storage adapter matching the existing `save`, `open`, and `delete` interface and configure it through the application factory; keep incident routes storage-provider agnostic.
- Use a dedicated private bucket with Block Public Access, bucket-owner-enforced object ownership, least-privilege bucket policy, TLS-only access, and server-side encryption (prefer SSE-KMS where required).
- Grant the EC2 role access only to the evidence prefix. Downloads should be authorized by the application (or short-lived signed URLs after a separate security review); never make objects public.
- Add lifecycle/retention and deletion policies that match legal requirements. Versioning/Object Lock require an explicit retention design.
- Before production, scan uploads for malware, enforce content and size checks, encrypt in transit/at rest, audit access, and define retention, legal hold, backup, and secure deletion rules.

## 8. Secrets

- Store Flask secret key and database password in AWS Secrets Manager or Systems Manager Parameter Store SecureString, encrypted with KMS and readable only by the application role.
- Inject secrets at service startup through a protected mechanism; avoid writing them to logs, user data, AMIs, or command history.
- Rotate secrets and define an operational recovery procedure. Use a different secret per environment.

## 9. HTTPS with ALB and ACM

- Validate control of the application domain and provision an ACM certificate in the ALB's region.
- Configure an HTTPS listener with a current TLS policy; redirect HTTP to HTTPS.
- Set secure cookies only after TLS termination is confirmed (`SESSION_COOKIE_SECURE=1`) and configure proxy handling carefully for trusted ALB headers.
- Add WAF/rate-limiting controls where appropriate and test forwarded-header behavior before exposing the service.

## 10. WSGI server and application operations

- On Linux EC2, serve the Flask factory with Gunicorn (for example, `gunicorn --workers 3 --bind 127.0.0.1:8000 'app:create_app()'`) behind a local reverse proxy or ALB-connected web server as designed.
- Set worker count/timeouts for the selected instance and workload, and run the process under systemd.
- On Windows local development, use the documented `python app.py` Flask server only on loopback. Gunicorn is not supported as the local Windows server.
- Apply database migrations/schema changes as controlled deployment steps, not at app import/startup.

## 11. CloudWatch

- Send structured application logs to a dedicated CloudWatch log group with retention limits and access restrictions; exclude passwords, cookies, tokens, and secret values.
- Monitor ALB 4xx/5xx, target health, EC2 CPU/memory/disk, RDS CPU/connections/storage, backup status, and application error rates.
- Create alarms and notifications for availability, saturation, backup failure, and unexpected spend. Avoid logging evidence contents or unnecessary sensitive incident details.

## 12. Backups and recovery

- Enable automated RDS backups and point-in-time recovery with an approved retention period; periodically test restores into an isolated environment.
- Define RPO/RTO, incident response owners, and a recovery runbook. Consider cross-region backup copies only after residency and cost review.
- Define S3 versioning/lifecycle/replication based on evidence retention and recovery needs; test restoration and deletion behavior.

## 13. Deployment validation and rollback

1. Deploy first to a nonproduction account/environment and verify schema, secrets, network restrictions, and health checks.
2. Exercise login/roles, incident CRUD, audit entries, evidence scanning/storage/download authorization, log redaction, and backup restore.
3. Verify that public internet cannot reach EC2 admin ports, RDS, or S3 objects; test HTTPS and session cookie flags.
4. Promote an immutable artifact through a controlled release. Monitor alarms and logs during rollout.
5. Roll back to the previous known-good application artifact if health checks fail; keep database changes backward-compatible and restore from backup only through an approved recovery procedure.

## 14. Cost and cleanup

Use AWS Pricing Calculator for EC2, ALB, NAT gateways, RDS class/storage/backup, S3/KMS requests and storage, CloudWatch ingestion/retention, data transfer, and optional WAF. A continuously running NAT gateway, ALB, and RDS can dominate a student-project budget even at low traffic. Choose small nonproduction resources, set budget alerts, and schedule shutdown where safe.

After an approved demonstration, inventory resources and retain only approved backups/evidence. Remove the ALB, EC2/Auto Scaling resources, NAT gateways, RDS, S3 objects/bucket, log groups, secrets, and security-group rules in a controlled order. Confirm retention and backup obligations before deletion; no cleanup is performed by this project automatically.
