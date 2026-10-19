# Honeypot notes

For each service: what it simulates, which events it emits, what it never does.

## HTTP
- catch-all handler with trap paths (/wp-login.php, /phpmyadmin, /.env, /.git/config ...)
- event_type: http_request. `details.trap_hit` and `details.scanner_ua` are the main flags
- the login form logs username and password (clear text in the lab, hash otherwise)
- never serves real files and never executes anything

## SSH
- asyncssh server with a fake shell and filesystem; first two logins refused, third accepted
- events: connect, auth_attempt, command, file_download_attempt, disconnect
- downloads (wget/curl) are never performed, only the URL is logged

## API
- fake internal REST API with a honeytoken; see docs/api-honeypot.md
- events: api_request, api_auth_attempt, honeytoken_used