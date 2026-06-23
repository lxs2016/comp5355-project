import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", "relay.db")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username      TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            IK_sig_pub    TEXT NOT NULL,
            IK_dh_pub     TEXT NOT NULL,
            SPK_pub       TEXT NOT NULL,
            SPK_sig       TEXT NOT NULL,
            created_at    INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS handshakes (
            session_id      TEXT PRIMARY KEY,
            initiator       TEXT NOT NULL,
            responder       TEXT NOT NULL,
            EK_pub          TEXT NOT NULL,
            hs_signature    TEXT NOT NULL,
            transcript_hash TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending',
            created_at      INTEGER NOT NULL,
            FOREIGN KEY (initiator) REFERENCES users(username),
            FOREIGN KEY (responder) REFERENCES users(username)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT    NOT NULL,
            sender      TEXT    NOT NULL,
            recipient   TEXT    NOT NULL,
            ciphertext  TEXT    NOT NULL,
            seq         INTEGER NOT NULL,
            ad          TEXT    NOT NULL,
            delivered   INTEGER NOT NULL DEFAULT 0,
            created_at  INTEGER NOT NULL,
            FOREIGN KEY (sender)    REFERENCES users(username),
            FOREIGN KEY (recipient) REFERENCES users(username)
        );

        CREATE INDEX IF NOT EXISTS idx_messages_recipient
            ON messages(recipient, delivered);
        """)
