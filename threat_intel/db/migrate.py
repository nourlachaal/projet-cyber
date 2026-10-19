"""Apply goose-style SQL migrations in order, once each.

State is tracked in a _migrations table (filename, applied_at).
Files without goose markers are applied as a whole.
"""

import os
from pathlib import Path

import psycopg

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

_UP_MARKER = "-- +goose Up"
_DOWN_MARKER = "-- +goose Down"


def extract_up(sql: str) -> str:
    """Return the Up section of a goose-style migration file."""
    up_idx = sql.find(_UP_MARKER)
    if up_idx == -1:
        return sql.strip()
    body = sql[up_idx + len(_UP_MARKER) :]
    down_idx = body.find(_DOWN_MARKER)
    if down_idx != -1:
        body = body[:down_idx]
    return body.strip()


def load_dsn() -> str:
    """TI_DB_DSN from the environment, with a fallback to the local .env file."""
    dsn = os.getenv("TI_DB_DSN")
    if dsn:
        return dsn
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("TI_DB_DSN="):
                return line.split("=", 1)[1].strip()
    raise SystemExit("TI_DB_DSN is not set (see .env.example)")


def migrate(conn, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
    """Apply 001_*.sql, 002_*.sql... in order, once each.

    Tracks state in table _migrations (filename, applied_at).
    Returns the list of newly applied filenames.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS _migrations (
            filename   TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    conn.commit()

    applied = {row[0] for row in conn.execute("SELECT filename FROM _migrations")}
    done: list[str] = []
    for path in sorted(migrations_dir.glob("*.sql")):
        if path.name in applied:
            continue
        sql = extract_up(path.read_text(encoding="utf-8"))
        with conn.transaction():
            conn.execute(sql)
            conn.execute("INSERT INTO _migrations (filename) VALUES (%s)", [path.name])
        done.append(path.name)
    return done


def main() -> None:
    dsn = load_dsn()
    with psycopg.connect(dsn) as conn:
        applied = migrate(conn)
    if applied:
        print("applied:", ", ".join(applied))
    else:
        print("nothing to apply, schema is up to date")


if __name__ == "__main__":
    main()
