"""Interface de linha de comandos — subcomandos serve e send."""

from __future__ import annotations

import argparse
import os
import socket
import sys

from thb.crypto_config import CIPHERS, HASHES, validate_config
from thb.kex import perform_kex
from thb.transfer import receive_file, send_file

def _norm_cipher(value: str) -> str:
    c = value.upper()
    if c not in CIPHERS:
        raise argparse.ArgumentTypeError(
            f"cifra inválida {value!r}; use uma de: {', '.join(CIPHERS)}"
        )
    return c


def _norm_hash(value: str) -> str:
    h = value.upper()
    if h not in HASHES:
        raise argparse.ArgumentTypeError(
            f"hash inválido {value!r}; use um de: {', '.join(HASHES)}"
        )
    return h


EPILOG = """
EXEMPLOS (dois terminais, mesmos parâmetros criptográficos em ambos):

  Terminal 1 (receptor):
    python -m thb serve --host 127.0.0.1 --port 9000 --output-dir ./received

  Terminal 2 (emissor):
    python -m thb send --host 127.0.0.1 --port 9000 --file ./documento.pdf

  Com compressão e ChaCha20-Poly1305:
    python -m thb serve --port 9000 --compress --cipher CHACHA20-POLY1305 --output-dir ./recv
    python -m thb send --port 9000 --file ./grande.bin --compress --cipher CHACHA20-POLY1305

  Sem cifra (apenas HMAC por bloco); não use --cipher:
    python -m thb serve --port 9000 --no-encrypt --output-dir ./recv
    python -m thb send --port 9000 --file ./dados.bin --no-encrypt

Cifras suportadas: """ + ", ".join(CIPHERS) + """
Hashes (HKDF/HMAC/assinatura): """ + ", ".join(HASHES) + """

LIMITAÇÕES CONHECIDAS:
  O servidor e o cliente devem ser executados com os mesmos parâmetros (--cipher, --hash,
  --compress, --no-encrypt). Caso contrário, o header de transferência não será decifrado
  ou verificado corretamente.

  O acordo de chaves X25519 não autentica o par: um atacante na rede (MITM) pode negociar
  chaves distintas com cada lado. Use o fingerprint [KEY FINGERPRINT] impresso após o KEX
  como verificação manual (TOFU) quando o canal não for totalmente confiável.
"""


def _user_specified_cipher(argv: list[str]) -> bool:
    for a in argv:
        if a == "--cipher" or a.startswith("--cipher="):
            return True
    return False


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m thb",
        description=(
            "TWO-HEADED-BEAST: transmissão segura de ficheiros entre dois programas via TCP. "
            "Um processo serve (escuta); outro envia após estabelecer chave de sessão (X25519 + HKDF)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser(
        "serve",
        help="Modo receptor: escuta num endereço e recebe um ficheiro.",
        description="Inicia o servidor TCP, realiza o handshake de chaves e recebe o ficheiro.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    send = sub.add_parser(
        "send",
        help="Modo emissor: liga ao servidor e envia um ficheiro.",
        description="Conecta ao servidor, realiza o handshake de chaves e envia o ficheiro.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    for p in (serve, send):
        p.add_argument("--host", default="127.0.0.1", help="Endereço a ligar/bind (default: %(default)s)")
        p.add_argument("--port", type=int, default=9000, help="Porta TCP (default: %(default)s)")
        p.add_argument(
            "--cipher",
            type=_norm_cipher,
            default=_norm_cipher("AES-256-GCM"),
            help="Cifra AEAD (default: AES-256-GCM). Incompatível com --no-encrypt.",
        )
        p.add_argument(
            "--no-encrypt",
            action="store_true",
            help="Não cifrar; obriga HMAC por bloco com k_mac.",
        )
        p.add_argument(
            "--compress",
            action="store_true",
            help="Comprimir com zlib antes de particionar e cifrar/autenticar.",
        )
        p.add_argument(
            "--hash",
            type=_norm_hash,
            default=_norm_hash("SHA256"),
            help="Hash para HKDF, HMAC e assinatura (default: SHA256)",
        )

    serve.add_argument(
        "--output-dir",
        default="./received",
        help="Diretório onde gravar o ficheiro recebido (default: %(default)s)",
    )
    serve.add_argument(
        "--verify-key",
        metavar="PATH",
        help="PEM da chave pública ou certificado X.509 para validar assinatura (se o envio foi assinado).",
    )

    send.add_argument("--file", required=True, metavar="PATH", help="Ficheiro a enviar")
    send.add_argument(
        "--sign-key",
        metavar="PATH",
        help="PEM da chave privada para assinar o hash do ficheiro original (opcional).",
    )

    return parser


def _validate_parsed(args: argparse.Namespace) -> None:
    if args.no_encrypt and _user_specified_cipher(sys.argv):
        raise SystemExit(
            "erro: --cipher não pode ser combinado com --no-encrypt; omita --cipher no modo apenas MAC."
        )

    if args.no_encrypt:
        args.cipher = None  # type: ignore[assignment]

    if args.command == "send":
        path = args.file
        if not os.path.isfile(path):
            raise SystemExit(f"erro: ficheiro não encontrado: {path}")
        if not os.access(path, os.R_OK):
            raise SystemExit(f"erro: ficheiro sem permissão de leitura: {path}")

    validate_config(
        args.cipher or "AES-256-GCM",
        args.hash,
        args.no_encrypt,
    )


def run_server(args: argparse.Namespace) -> None:
    """
    Escuta num socket, aceita uma sessão, realiza KEX e recebe o ficheiro.

    :param args: argumentos parseados do subcomando ``serve``.
    """
    config = validate_config(
        args.cipher or "AES-256-GCM",
        args.hash,
        args.no_encrypt,
    )
    os.makedirs(args.output_dir, exist_ok=True)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.host, args.port))
    server_sock.listen(1)
    print(f"[INFO] Listening on {args.host}:{args.port}")

    conn, addr = server_sock.accept()
    print(f"[INFO] Connection from {addr}")
    try:
        conn.settimeout(30)
        k_enc, k_mac = perform_kex(
            conn,
            is_server=True,
            hash_name=args.hash,
            cipher_config=config,
        )
        conn.settimeout(300)
        receive_file(conn, args.output_dir, k_enc, k_mac, args)
    finally:
        try:
            conn.close()
        except OSError:
            pass
        server_sock.close()


def run_client(args: argparse.Namespace) -> None:
    """
    Liga ao servidor, realiza KEX e envia o ficheiro.

    :param args: argumentos parseados do subcomando ``send``.
    """
    config = validate_config(
        args.cipher or "AES-256-GCM",
        args.hash,
        args.no_encrypt,
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((args.host, args.port))
    print(f"[INFO] Connected to {args.host}:{args.port}")
    try:
        k_enc, k_mac = perform_kex(
            sock,
            is_server=False,
            hash_name=args.hash,
            cipher_config=config,
        )
        sock.settimeout(300)
        send_file(sock, args.file, k_enc, k_mac, args)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main() -> None:
    """Faz parse dos argumentos, valida e invoca ``serve`` ou ``send``."""
    parser = _build_parser()
    args = parser.parse_args()
    _validate_parsed(args)

    if args.command == "serve":
        run_server(args)
    elif args.command == "send":
        run_client(args)
    else:
        parser.error("subcomando inválido")


if __name__ == "__main__":
    main()
