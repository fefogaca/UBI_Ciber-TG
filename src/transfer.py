"""
Pipeline de transferência: compressão, partição, autenticação por bloco, cabeçalho protegido.
"""

from __future__ import annotations

import json
import os
import zlib
from argparse import Namespace
from typing import Any

import hmac as hmac_stdlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from src.crypto_config import hash_digest_size, hash_to_stdlib
from src.protocol import (
    BLOCK_DATA,
    SIGNATURE,
    STATUS_ERROR,
    STATUS_OK,
    TRANSFER_HEADER,
    recv_msg,
    send_msg,
)
from src import signature as sig_mod

LARGE_THRESHOLD = 12 * 1024 * 1024
BLOCK_4MI = 4 * 1024 * 1024
HEADER_NONCE = b"\x00" * 12


def _hmac(key: bytes, data: bytes, hash_name: str) -> bytes:
    hl = __import__("hashlib")
    return hmac_stdlib.new(key, data, getattr(hl, hash_to_stdlib(hash_name))).digest()


def _aead_encrypt(k_enc: bytes, nonce: bytes, plaintext: bytes, cipher: str) -> bytes:
    if cipher in ("AES-128-GCM", "AES-256-GCM"):
        return AESGCM(k_enc).encrypt(nonce, plaintext, None)
    if cipher == "CHACHA20-POLY1305":
        return ChaCha20Poly1305(k_enc).encrypt(nonce, plaintext, None)
    raise ValueError(f"Cifra AEAD desconhecida: {cipher!r}")


def _aead_decrypt(k_enc: bytes, nonce: bytes, ciphertext: bytes, cipher: str) -> bytes:
    if cipher in ("AES-128-GCM", "AES-256-GCM"):
        return AESGCM(k_enc).decrypt(nonce, ciphertext, None)
    if cipher == "CHACHA20-POLY1305":
        return ChaCha20Poly1305(k_enc).decrypt(nonce, ciphertext, None)
    raise ValueError(f"Cifra AEAD desconhecida: {cipher!r}")


def _protect_header(header_json: bytes, encrypted: bool, k_enc: bytes | None, k_mac: bytes, cipher: str, hash_name: str) -> bytes:
    if encrypted:
        assert k_enc is not None
        return _aead_encrypt(k_enc, HEADER_NONCE, header_json, cipher)
    mac = _hmac(k_mac, b"\x00\x00\x00\x00" + header_json, hash_name)
    return header_json + mac


def _unprotect_header(payload: bytes, encrypted: bool, k_enc: bytes | None, k_mac: bytes, cipher: str, hash_name: str) -> bytes:
    if encrypted:
        assert k_enc is not None
        try:
            return _aead_decrypt(k_enc, HEADER_NONCE, payload, cipher)
        except Exception as exc:
            raise ValueError(
                "Falha ao decifrar ou verificar o cabeçalho da transferência — parâmetros "
                "criptográficos provavelmente em desacordo entre emissor e receptor."
            ) from exc
    mac_len = hash_digest_size(hash_name)
    if len(payload) < mac_len:
        raise ValueError("Cabeçalho inválido: payload demasiado curto para MAC.")
    body, mac = payload[:-mac_len], payload[-mac_len:]
    expected = _hmac(k_mac, b"\x00\x00\x00\x00" + body, hash_name)
    if not hmac_stdlib.compare_digest(mac, expected):
        raise ValueError(
            "Falha ao decifrar ou verificar o cabeçalho da transferência — parâmetros "
            "criptográficos provavelmente em desacordo entre emissor e receptor."
        )
    return body


def _send_status(sock, ok: bool, message: str = "") -> None:
    if ok:
        send_msg(sock, STATUS_OK, b"OK" if not message else message.encode("utf-8"))
    else:
        send_msg(sock, STATUS_ERROR, message.encode("utf-8"))


def send_file(sock, filepath: str, k_enc: bytes | None, k_mac: bytes, args: Namespace) -> None:
    """
    Envia um ficheiro conforme o protocolo THB.

    :param sock: socket TCP após KEX.
    :param filepath: caminho do ficheiro a enviar.
    :param k_enc: chave AEAD ou None se --no-encrypt.
    :param k_mac: chave HMAC de 32 bytes.
    :param args: namespace argparse (cipher, hash, compress, no_encrypt, sign_key).
    """
    encrypted = not args.no_encrypt
    cipher = args.cipher

    with open(filepath, "rb") as f:
        original_data = f.read()

    compressed_data = zlib.compress(original_data, level=6) if args.compress else original_data

    clen = len(compressed_data)
    if clen > LARGE_THRESHOLD:
        block_size = BLOCK_4MI
        num_blocks = (clen + block_size - 1) // block_size
    else:
        block_size = clen if clen > 0 else 0
        num_blocks = 1

    header: dict[str, Any] = {
        "filename": os.path.basename(filepath),
        "original_size": len(original_data),
        "compressed": bool(args.compress),
        "compressed_size": clen,
        "encrypted": encrypted,
        "cipher": cipher if encrypted else None,
        "hash": args.hash,
        "block_size": block_size,
        "num_blocks": num_blocks,
        "signed": args.sign_key is not None,
        "sign_algo": None,
    }
    if args.sign_key:
        header["sign_algo"] = sig_mod.fill_sign_algo_from_key_path(args.sign_key)

    header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
    protected = _protect_header(header_json, encrypted, k_enc, k_mac, cipher or "", args.hash)
    send_msg(sock, TRANSFER_HEADER, protected)

    for i in range(num_blocks):
        start = i * block_size
        end = min(start + block_size, clen) if block_size > 0 else 0
        chunk = compressed_data[start:end]
        nonce_int = i + 1
        if encrypted:
            nonce_bytes = nonce_int.to_bytes(12, "big")
            ct = _aead_encrypt(k_enc, nonce_bytes, chunk, cipher)
            payload = nonce_bytes + ct
        else:
            counter = nonce_int.to_bytes(4, "big")
            mac = _hmac(k_mac, counter + chunk, args.hash)
            payload = chunk + mac
        send_msg(sock, BLOCK_DATA, payload)
        print(f"[ENVIO] Bloco {i + 1}/{num_blocks}")

    if args.sign_key:
        sig_bytes, _ = sig_mod.sign_data(args.sign_key, original_data, args.hash)
        try:
            send_msg(sock, SIGNATURE, sig_bytes)
        except (BrokenPipeError, ConnectionResetError) as exc:
            print(f"[ERRO] Ligação fechada pelo receptor antes de concluir o envio: {exc}")
            return

    try:
        msg_type, payload = recv_msg(sock)
    except (BrokenPipeError, ConnectionResetError, ConnectionError) as exc:
        print(f"[ERRO] Ligação perdida ao aguardar o estado final: {exc}")
        return

    if msg_type == STATUS_ERROR:
        print(f"[ERRO REMOTO] {payload.decode('utf-8', errors='replace')}")
    elif msg_type == STATUS_OK:
        print("[OK] Ficheiro enviado com sucesso")
    else:
        print(f"[ERRO] Resposta inesperada do servidor: 0x{msg_type:02x}")


def receive_file(sock, output_dir: str, k_enc: bytes | None, k_mac: bytes, args: Namespace) -> None:
    """
    Recebe um ficheiro conforme o protocolo THB e grava em output_dir.

    :param sock: socket após KEX.
    :param output_dir: diretório de destino.
    :param k_enc: chave AEAD ou None.
    :param k_mac: chave HMAC.
    :param args: namespace argparse (inclui verify_key, no_encrypt, hash, cipher).
    """
    encrypted = not args.no_encrypt
    cipher = args.cipher

    try:
        msg_type, protected = recv_msg(sock)
        if msg_type != TRANSFER_HEADER:
            raise ValueError(f"Esperado cabeçalho de transferência, recebido tipo 0x{msg_type:02x}")

        try:
            header_json = _unprotect_header(protected, encrypted, k_enc, k_mac, cipher or "", args.hash)
        except ValueError as exc:
            print(f"[ERRO] {exc}")
            _send_status(sock, False, str(exc))
            return

        header = json.loads(header_json.decode("utf-8"))
        for key in (
            "filename",
            "original_size",
            "compressed",
            "compressed_size",
            "encrypted",
            "hash",
            "block_size",
            "num_blocks",
            "signed",
        ):
            if key not in header:
                raise KeyError(f"Cabeçalho incompleto: falta {key!r}")

        if header.get("encrypted") != encrypted:
            raise ValueError("Cabeçalho indica modo de cifra diferente do configurado localmente.")

        if encrypted:
            local_c = (cipher or "").upper()
            hdr_cipher = header.get("cipher")
            remote_c = (hdr_cipher or "").upper()
            if remote_c != local_c:
                raise ValueError(
                    f"Incompatibilidade de cifra: o emissor usou {hdr_cipher!r}, o receptor espera {cipher!r} "
                    f"— use a mesma opção --cipher em ambos os lados."
                )

        local_h = args.hash.upper()
        remote_h = str(header["hash"]).upper()
        if remote_h != local_h:
            raise ValueError(
                f"Incompatibilidade de hash: o emissor usou {header['hash']!r}, o receptor espera {args.hash!r} "
                f"— use a mesma opção --hash em ambos os lados."
            )

        hdr_compressed = bool(header["compressed"])
        receiver_compress = bool(args.compress)
        if hdr_compressed != receiver_compress:
            raise ValueError(
                "Incompatibilidade de compressão: o emissor enviou "
                + ("com compressão" if hdr_compressed else "sem compressão")
                + ", o receptor espera "
                + ("com compressão" if receiver_compress else "sem compressão")
                + " — use a mesma opção --compress em ambos os lados."
            )

        if header["signed"] and not args.verify_key:
            msg = (
                "O cabeçalho indica um ficheiro assinado, mas não foi indicada --verify-key. "
                "A abortar."
            )
            print(f"[ERRO] {msg}")
            _send_status(sock, False, msg)
            return

        nblocks = int(header["num_blocks"])
        blocks: list[bytes] = []

        for i in range(nblocks):
            mtype, payload = recv_msg(sock)
            if mtype != BLOCK_DATA:
                raise ValueError(f"Esperado dados de bloco na posição {i + 1}, recebido tipo 0x{mtype:02x}")
            expected_nonce = i + 1
            if encrypted:
                nonce_bytes = payload[:12]
                received_nonce = int.from_bytes(nonce_bytes, "big")
                if received_nonce != expected_nonce:
                    raise ValueError(
                        f"Nonce de sequência inválido no bloco {i + 1}: esperado {expected_nonce}, recebido {received_nonce}."
                    )
                ciphertext = payload[12:]
                try:
                    pt = _aead_decrypt(k_enc, nonce_bytes, ciphertext, header["cipher"])
                except Exception as exc:
                    raise ValueError(f"Falha AEAD no bloco {i + 1}: {exc}") from exc
            else:
                mac_len = hash_digest_size(header["hash"])
                if len(payload) < mac_len:
                    raise ValueError(f"Bloco {i + 1}: payload demasiado curto.")
                chunk, recv_mac = payload[:-mac_len], payload[-mac_len:]
                counter = expected_nonce.to_bytes(4, "big")
                expected_mac = _hmac(k_mac, counter + chunk, header["hash"])
                if not hmac_stdlib.compare_digest(recv_mac, expected_mac):
                    raise ValueError(f"Bloco {i + 1}: verificação HMAC falhou.")
                pt = chunk
            blocks.append(pt)
            print(f"[REC] Bloco {i + 1}/{nblocks} — integridade verificada")

        compressed_data = b"".join(blocks)
        if header["compressed"]:
            try:
                original_data = zlib.decompress(compressed_data)
            except zlib.error as exc:
                raise ValueError(f"Descompressão zlib falhou: {exc}") from exc
        else:
            original_data = compressed_data

        if len(original_data) != int(header["original_size"]):
            raise ValueError(
                f"Tamanho final {len(original_data)} não coincide com original_size {header['original_size']}."
            )

        if header["signed"]:
            stype, sig_payload = recv_msg(sock)
            if stype != SIGNATURE:
                raise ValueError(f"Esperada assinatura após os blocos, recebido tipo 0x{stype:02x}")
            # verify_signature levanta ValueError em caso de falha — capturada pelo except exterior.
            sig_mod.verify_signature(
                args.verify_key,
                original_data,
                sig_payload,
                header["sign_algo"],
                header["hash"],
            )

        os.makedirs(output_dir, exist_ok=True)
        out_path = os.path.join(output_dir, header["filename"])
        with open(out_path, "wb") as out:
            out.write(original_data)

        _send_status(sock, True, "OK")
        print(
            f'[OK] Ficheiro «{header["filename"]}» ({header["original_size"]} bytes) recebido com sucesso'
        )

    except (ConnectionError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        msg = str(exc)
        print(f"[ERRO] {msg}")
        try:
            _send_status(sock, False, msg)
        except OSError:
            pass
