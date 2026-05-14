"""Acordo de chaves X25519 + HKDF."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from thb.protocol import HANDSHAKE_PUBKEY, recv_msg, send_msg


def _hash_from_name(hash_name: str) -> hashes.HashAlgorithm:
    h = hash_name.upper()
    if h == "SHA256":
        return hashes.SHA256()
    if h == "SHA384":
        return hashes.SHA384()
    if h == "SHA512":
        return hashes.SHA512()
    raise ValueError(f"Hash não suportado para HKDF: {hash_name!r}")


def print_fingerprint(peer_public_bytes: bytes) -> None:
    """
    Imprime fingerprint TOFU da chave pública do par (SHA256, 8 primeiros bytes).

    :param peer_public_bytes: Chave pública X25519 em formato raw (32 bytes).
    """
    digest = hashlib.sha256(peer_public_bytes).digest()[:8]
    hx = digest.hex()
    grouped = ":".join(hx[i : i + 4] for i in range(0, len(hx), 4))
    print(f"[KEY FINGERPRINT] {grouped}")


def perform_kex(
    sock,
    is_server: bool,
    hash_name: str,
    cipher_config: dict,
) -> tuple[bytes | None, bytes]:
    """
    Realiza troca X25519 e deriva k_enc (se aplicável) e k_mac (32 bytes).

    :param sock: socket já conectado (com timeout aplicado pelo chamador se desejado).
    :param is_server: True se este lado aceitou a conexão e deve receber primeiro.
    :param hash_name: SHA256 / SHA384 / SHA512.
    :param cipher_config: resultado de validate_config (inclui key_bits ou no_encrypt).
    :return: (k_enc ou None se --no-encrypt, k_mac sempre 32 bytes).
    """
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )

    if is_server:
        msg_type, payload = recv_msg(sock)
        if msg_type != HANDSHAKE_PUBKEY:
            raise ValueError(f"Esperado HANDSHAKE_PUBKEY, recebido 0x{msg_type:02x}")
        peer_raw = payload
        send_msg(sock, HANDSHAKE_PUBKEY, public_bytes)
    else:
        send_msg(sock, HANDSHAKE_PUBKEY, public_bytes)
        msg_type, payload = recv_msg(sock)
        if msg_type != HANDSHAKE_PUBKEY:
            raise ValueError(f"Esperado HANDSHAKE_PUBKEY, recebido 0x{msg_type:02x}")
        peer_raw = payload

    print_fingerprint(peer_raw)

    peer_pub = X25519PublicKey.from_public_bytes(peer_raw)
    shared_secret = private_key.exchange(peer_pub)

    algorithm = _hash_from_name(hash_name)
    salt = b"thb-v1-salt"

    hkdf_mac = HKDF(
        algorithm=algorithm,
        length=32,
        salt=salt,
        info=b"thb-mac-key",
    )
    k_mac = hkdf_mac.derive(shared_secret)

    if cipher_config.get("no_encrypt"):
        return None, k_mac

    key_len = cipher_config["key_bits"] // 8
    hkdf_enc = HKDF(
        algorithm=algorithm,
        length=key_len,
        salt=salt,
        info=b"thb-encryption-key",
    )
    k_enc = hkdf_enc.derive(shared_secret)
    return k_enc, k_mac
