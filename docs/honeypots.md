# Honeypot notes

For each service: what it simulates, which events it emits, what it never does.

## HTTP
- catch-all handler, trap paths (/wp-login.php, /phpmyadmin, /.env ...)
- event_type: http_request (details.trap_hit tells if a trap path was requested)

## SSH
- to do

## API
- to do