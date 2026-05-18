"""Framing TCP: prefixo de comprimento e tipos de mensagem."""

from __future__ import annotations

HANDSHAKE_PUBKEY = 0x01
TRANSFER_HEADER = 0x02
BLOCK_DATA = 0x03
SIGNATURE = 0x04
STATUS_OK = 0x10
STATUS_ERROR = 0x11


def recv_exact(sock, n: int) -> bytes:
    """
    Lê exatamente n bytes do socket.

    :param sock: socket TCP conectado.
    :param n: número de bytes.
    :return: buffer com n bytes.
    :raises ConnectionError: se a ligação fechar antes de n bytes.
    """
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Ligação fechada antes de concluir a leitura")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_msg(sock, msg_type: int, payload: bytes) -> None:
    """
    Envia uma mensagem: 4 bytes de comprimento + 1 byte tipo + payload.

    :param sock: socket.
    :param msg_type: byte de tipo (0x01..0x11).
    :param payload: corpo da mensagem (pode ser vazio).
    """
    frame = msg_type.to_bytes(1, "big") + payload
    prefix = len(frame).to_bytes(4, "big")
    sock.sendall(prefix + frame)


def recv_msg(sock) -> tuple[int, bytes]:
    """
    Recebe uma mensagem completa.

    :param sock: socket.
    :return: (msg_type, payload).
    :raises ConnectionError: se a ligação fechar antes do fim da mensagem.
    """
    length_bytes = recv_exact(sock, 4)
    length = int.from_bytes(length_bytes, "big")
    if length < 1:
        raise ConnectionError("Trama inválida: trama vazia")
    frame = recv_exact(sock, length)
    msg_type = frame[0]
    payload = frame[1:]
    return msg_type, payload
