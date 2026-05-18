"""Acordo de chaves X25519 + HKDF."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.crypto_config import hash_to_cryptography
from src import peers as peers_mod
from src.protocol import HANDSHAKE_PUBKEY, recv_msg, send_msg

LAST_SESSION_PEER_FINGERPRINT: str | None = None
LAST_SESSION_TOFU_KEY: tuple[str, int] | None = None


def peer_pubkey_fingerprint(peer_public_bytes: bytes) -> str:
    """Fingerprint TOFU da chave pública do par (primeiros 8 bytes do SHA-256, formato agrupado)."""
    digest = hashlib.sha256(peer_public_bytes).digest()[:8]
    hx = digest.hex()
    return ":".join(hx[i : i + 4] for i in range(0, len(hx), 4))


def print_fingerprint(peer_public_bytes: bytes) -> str:
    """
    Imprime fingerprint TOFU da chave pública do par (SHA256, 8 primeiros bytes).

    :param peer_public_bytes: Chave pública X25519 em formato raw (32 bytes).
    :return: mesma string mostrada após [IMPRESSÃO DIGITAL DA CHAVE].
    """
    grouped = peer_pubkey_fingerprint(peer_public_bytes)
    print(f"[IMPRESSÃO DIGITAL DA CHAVE] {grouped}")
    return grouped


def perform_kex(
    sock,
    is_server: bool,
    hash_name: str,
    cipher_config: dict,
    *,
    tofu_host: str | None = None,
    tofu_port: int | None = None,
) -> tuple[bytes | None, bytes, str]:
    """
    Realiza troca X25519 e deriva k_enc (se aplicável) e k_mac (32 bytes).

    :param sock: socket já conectado (com timeout aplicado pelo chamador se desejado).
    :param is_server: True se este lado aceitou a conexão e deve receber primeiro.
    :param hash_name: SHA256 / SHA384 / SHA512.
    :param cipher_config: resultado de validate_config (inclui key_bits ou no_encrypt).
    :param tofu_host: host lógico para consulta TOFU em peers (opcional).
    :param tofu_port: porta lógica para consulta TOFU em peers (opcional).
    :return: (k_enc ou None se --no-encrypt, k_mac sempre 32 bytes, fingerprint do par).
    """
    global LAST_SESSION_PEER_FINGERPRINT, LAST_SESSION_TOFU_KEY
    LAST_SESSION_PEER_FINGERPRINT = None
    LAST_SESSION_TOFU_KEY = None

    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )

    if is_server:
        msg_type, payload = recv_msg(sock)
        if msg_type != HANDSHAKE_PUBKEY:
            raise ValueError(f"Esperada chave pública do handshake, recebido tipo 0x{msg_type:02x}")
        peer_raw = payload
        send_msg(sock, HANDSHAKE_PUBKEY, public_bytes)
    else:
        send_msg(sock, HANDSHAKE_PUBKEY, public_bytes)
        msg_type, payload = recv_msg(sock)
        if msg_type != HANDSHAKE_PUBKEY:
            raise ValueError(f"Esperada chave pública do handshake, recebido tipo 0x{msg_type:02x}")
        peer_raw = payload

    fp_str = print_fingerprint(peer_raw)
    LAST_SESSION_PEER_FINGERPRINT = fp_str
    if tofu_host is not None and tofu_port is not None:
        LAST_SESSION_TOFU_KEY = (tofu_host, int(tofu_port))
        stored = peers_mod.get_fingerprint(tofu_host, int(tofu_port))
        if stored and stored != fp_str:
            print(
                "[AVISO] A impressão digital TOFU guardada para este anfitrião/porta "
                "não coincide com esta sessão."
            )
    else:
        LAST_SESSION_TOFU_KEY = None

    peer_pub = X25519PublicKey.from_public_bytes(peer_raw)
    shared_secret = private_key.exchange(peer_pub)

    algorithm = hash_to_cryptography(hash_name)
    salt = b"thb-v1-salt"

    hkdf_mac = HKDF(
        algorithm=algorithm,
        length=32,
        salt=salt,
        info=b"thb-mac-key",
    )
    k_mac = hkdf_mac.derive(shared_secret)

    if cipher_config.get("no_encrypt"):
        return None, k_mac, fp_str

    key_len = cipher_config["key_bits"] // 8
    hkdf_enc = HKDF(
        algorithm=algorithm,
        length=key_len,
        salt=salt,
        info=b"thb-encryption-key",
    )
    k_enc = hkdf_enc.derive(shared_secret)
    return k_enc, k_mac, fp_str
