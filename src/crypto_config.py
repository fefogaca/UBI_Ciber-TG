"""Listas fechadas de cifras e funções de hash, com validação."""

from __future__ import annotations

CIPHERS = {
    "AES-128-GCM": {"key_bits": 128, "nonce_bytes": 12, "tag_bytes": 16},
    "AES-256-GCM": {"key_bits": 256, "nonce_bytes": 12, "tag_bytes": 16},
    "CHACHA20-POLY1305": {"key_bits": 256, "nonce_bytes": 12, "tag_bytes": 16},
}

HASHES = ["SHA256", "SHA384", "SHA512"]


def validate_config(cipher: str, hash_name: str, no_encrypt: bool) -> dict:
    """
    Valida combinação cipher/hash/no_encrypt e devolve o dicionário da cifra ou marcador sem cifra.

    :param cipher: Nome canónico da cifra (maiúsculas).
    :param hash_name: SHA256, SHA384 ou SHA512.
    :param no_encrypt: Se True, não se usa cifra (apenas MAC).
    :return: {"no_encrypt": bool, "cipher": str|None, **CIPHERS[cipher]} ou só no_encrypt.
    :raises ValueError: combinação inválida ou nomes desconhecidos.
    """
    h = hash_name.upper()
    if h not in HASHES:
        raise ValueError(
            f"Função de hash inválida: {hash_name!r}. Use uma de: {', '.join(HASHES)}."
        )

    if no_encrypt:
        return {"no_encrypt": True, "cipher": None, "hash": h}

    c = cipher.upper()
    if c not in CIPHERS:
        raise ValueError(
            f"Cifra inválida: {cipher!r}. Use uma de: {', '.join(CIPHERS)}."
        )

    cfg = {"no_encrypt": False, "cipher": c, "hash": h}
    cfg.update(CIPHERS[c])
    return cfg


def hash_digest_size(hash_name: str) -> int:
    """Tamanho do digest em bytes para SHA256/384/512."""
    h = hash_name.upper()
    if h == "SHA256":
        return 32
    if h == "SHA384":
        return 48
    if h == "SHA512":
        return 64
    raise ValueError(f"Hash desconhecido: {hash_name!r}")
