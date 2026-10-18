# projet-cyber

Adaptive honeypot and threat intelligence platform (university project, team of 3).

## Structure

- honeypots/   decoy services (SSH, HTTP, API ...) and the shared event model
- scenarios/   reproducible attack-simulation scripts (lab use only)
- backend/     event processing and API
- threat_intel/ detection rules, MITRE ATT&CK mapping, IOCs
- docs/        event schema, security model, honeypot notes

## Quick start (Windows, PowerShell)

    py -3 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    python -m pytest
    python -m honeypots.http_hp.server

## Safety

Honeypots run only in a local or isolated lab network. Never expose them to the Internet.
Commands received by the fake services are never executed.


## Documentation

- [Documentation du backend](docs/backend.md)
- [Schéma des événements](docs/event-schema.md)
- [Modèle de sécurité](docs/security-model.md)