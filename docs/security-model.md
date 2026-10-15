# Security model of the honeypots

- Decoys never execute received commands and never serve real files.
- Honeypot containers run on an internal Docker network with no Internet access.
- Ports are published only on 127.0.0.1, and only with docker-compose.dev.yml.
- No real credentials, keys or personal data in the repository.
- Captured passwords: stored in clear only in the isolated lab (HP_CAPTURE_PASSWORDS=true),
  otherwise only a short hash.
- Isolation checks done so far: (to fill in)