# CloudSentinel project status

## Completed

- Rebuilt the active application at the canonical root, `D:\CloudSentinel`, preserving the previously inspected nested starter files and existing virtual environment.
- Added Flask login/logout with Werkzeug password hashes, CSRF protection, session security defaults, server-side roles, admin/analyst user management, account activation controls, and last-active-admin protections.
- Added database-backed dashboard statistics, incident CRUD/search/filter/assignment, resolution details, restricted evidence upload/download, and administrator-only audit history.
- Added normalized MySQL schema, environment-based settings, safe initial administrator setup, local evidence storage interface, responsive dashboard templates, and ignored local data/secrets.
- Added isolated SQLite-backed automated tests, Windows setup instructions, and an AWS deployment plan. No AWS services or billable resources were created.
- Initialized a Git repository in the canonical project root. No files were staged or committed.

## Main project files

- `app.py`, `templates\`, `static\`: Flask application and responsive interface.
- `schema.sql`, `seed_admin.py`, `requirements.txt`: MySQL schema, initial admin setup, and compatible dependencies.
- `.env.example`, `.gitignore`: safe configuration template and local-data exclusions.
- `tests\test_app.py`: isolated application behavior and security tests.
- `README.md`, `AWS_DEPLOYMENT.md`: local setup and AWS deployment guidance.

## Validation performed

- Installed requirements into the existing `.venv` using Python 3.14.3; Windows correctly skipped the Linux-only Gunicorn dependency.
- `python -m unittest discover -s tests -v`: **13 tests passed**, including authentication, permissions, CSRF, incident CRUD/filtering, evidence validation/size/access, audit, and user-management checks.
- `python -m compileall -q app.py seed_admin.py tests`: passed.
- `python -m pip check`: no broken requirements.
- Verified application import and route registration, and confirmed database-unavailable sign-in returns HTTP 503 with setup guidance.
- MySQL Server, MySQL Workbench, and the MySQL client were not detected in PATH, common installation directories, or installed-program registrations. The existing root has no `.env`; only `.env.example` files were found. No secret values were read.

## Remaining limitations and setup

- MySQL is not installed or running on this computer, so `schema.sql` has not been applied, `seed_admin.py` has not created an account, and a live authenticated MySQL workflow is not yet verified. The isolated tests use temporary SQLite databases and do not substitute for MySQL integration testing.
- Install/start MySQL Server, execute `schema.sql` in MySQL Workbench or a MySQL client, create the dedicated least-privilege account, configure a local `.env`, then run `seed_admin.py`. Detailed PowerShell and SQL steps are in `README.md`.
- The evidence backend currently uses private local files. S3 is a documented future storage adapter, not an implemented or configured AWS integration. Malware scanning, production IAM/secrets, HTTPS, WSGI hosting, CloudWatch, and deployment validation remain AWS deployment work.
- The older starter directory `D:\CloudSentinel\CloudSentinel` was left intact to avoid deleting or overwriting existing source files. Run the project only from the canonical root.

## Local start

After local MySQL schema/account setup and administrator creation:

```powershell
Set-Location D:\CloudSentinel
.\.venv\Scripts\python.exe app.py
```

Then open **http://127.0.0.1:5000**.
