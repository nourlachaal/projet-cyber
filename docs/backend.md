# Backend — API et bus d'événements

## Objectif

Le backend reçoit les événements générés par les honeypots, valide leur structure et les publie dans Redis Streams pour permettre leur traitement ultérieur.

## Architecture actuelle

- **FastAPI** : expose l'API REST.
- **Pydantic** : valide les événements selon le modèle commun `Event`.
- **Redis Streams** : reçoit les événements dans le flux `honeypot:events`.
- **Docker Compose** : lance le backend, Redis et le honeypot HTTP.

## Endpoints

| Méthode | Route | Description |
|---|---|---|
| GET | `/health` | Vérifie l'API et la connexion à Redis |
| POST | `/events` | Valide un événement et le publie dans Redis |

La documentation interactive est disponible sur `http://127.0.0.1:8000/docs` lorsque les services sont démarrés.

## Format des événements

Le backend utilise le modèle partagé défini dans `honeypots/common/events.py`.

Les champs comprennent notamment :

- `event_id` : identifiant unique de l'événement.
- `timestamp` : date et heure UTC.
- `service` : service concerné.
- `event_type` : type d'événement.
- `source_ip` et `source_port` : origine réseau observée.
- `session_id` : identifiant de session.
- `details` : données complémentaires.

Le schéma commun est documenté dans `docs/event-schema.md`.

## Lancement en développement

Depuis la racine du dépôt :

```powershell
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

Vérifier l'état des services :

```powershell
docker compose -f docker-compose.yml -f docker-compose.dev.yml ps
```

Arrêter les services :

```powershell
docker compose -f docker-compose.yml -f docker-compose.dev.yml down
```

## Vérifications

```powershell
python -m ruff check backend honeypots
python -m pytest
```

Pour vérifier les événements enregistrés dans Redis :

```powershell
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec redis redis-cli XRANGE honeypot:events - +
```

## État actuel

### Implémenté et testé

- API FastAPI initiale.
- Validation des événements.
- Endpoint de santé avec vérification de Redis.
- Publication dans Redis Streams.
- Configuration Docker Compose pour le backend, Redis et le honeypot HTTP.

### À réaliser

- Worker de traitement des événements.
- Intégration avec PostgreSQL.
- Diffusion en temps réel via WebSocket.
- Enrichissement et analyse des événements.

Ces éléments sont des tâches prévues et ne sont pas encore implémentés dans cette version.

## Sécurité

- Utiliser uniquement un laboratoire autorisé et isolé.
- Ne pas exposer les honeypots à Internet.
- Ne pas commiter de secrets, de clés privées ou de données capturées.
- Utiliser des données fictives pour les tests.
