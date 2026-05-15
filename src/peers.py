"""Persistência de destinos (alias, host, porta) em ~/.two-headed-beast/peers.json."""

from __future__ import annotations

import json
from pathlib import Path

PEERS_DIR = Path.home() / ".two-headed-beast"
PEERS_FILE = PEERS_DIR / "peers.json"


def _ensure_dir() -> None:
    PEERS_DIR.mkdir(parent_ok=True, mode=0o700)


def load_peers() -> list[dict]:
    """Lista de entradas {"alias": str, "host": str, "port": int}."""
    if not PEERS_FILE.is_file():
        return []
    try:
        with open(PEERS_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    return list(data.get("entries", []))


def save_peers(entries: list[dict]) -> None:
    _ensure_dir()
    with open(PEERS_FILE, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "entries": entries}, f, indent=2)


def add_peer(alias: str, host: str, port: int = 9000) -> None:
    peers = load_peers()
    low = alias.lower()
    for p in peers:
        if str(p.get("alias", "")).lower() == low:
            p["host"] = host
            p["port"] = int(port)
            save_peers(peers)
            return
    peers.append({"alias": alias, "host": host, "port": int(port)})
    save_peers(peers)


def remove_peer(alias: str) -> bool:
    peers = load_peers()
    low = alias.lower()
    filtered = [p for p in peers if str(p.get("alias", "")).lower() != low]
    if len(filtered) == len(peers):
        return False
    save_peers(filtered)
    return True


def list_peers() -> list[dict]:
    return load_peers()
