"""Interface de linha de comandos — subcomandos serve, send e menu."""

from __future__ import annotations

import argparse
import os
import socket
import sys

from src.branding import show_credits, show_splash
from src.crypto_config import CIPHERS, HASHES, validate_config
from src.kex import perform_kex
from src.transfer import receive_file, send_file


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
Modo interativo (menus guiados, destinos guardados):
  python -m src menu

EXEMPLOS (dois terminais, mesmos parâmetros criptográficos em ambos):

  Terminal 1 (receptor):
    python -m src serve --host 127.0.0.1 --port 9000 --output-dir ./received

  Terminal 2 (emissor):
    python -m src send --host 127.0.0.1 --port 9000 --file ./documento.pdf

  Uma só receção e terminar (comportamento antigo):
    python -m src serve --host 0.0.0.0 --port 9000 --once --output-dir ./received

  Com compressão e ChaCha20-Poly1305:
    python -m src serve --port 9000 --compress --cipher CHACHA20-POLY1305 --output-dir ./recv
    python -m src send --port 9000 --file ./grande.bin --compress --cipher CHACHA20-POLY1305

  Sem cifra (apenas HMAC por bloco); não use --cipher:
    python -m src serve --port 9000 --no-encrypt --output-dir ./recv
    python -m src send --port 9000 --file ./dados.bin --no-encrypt

Cifras suportadas: """ + ", ".join(
    CIPHERS
) + """
Hashes (HKDF/HMAC/assinatura): """ + ", ".join(
    HASHES
) + """

LIMITAÇÕES CONHECIDAS:
  O servidor e o cliente devem ser executados com os mesmos parâmetros (--cipher, --hash,
  --compress, --no-encrypt). Caso contrário, o header de transferência não será decifrado
  ou verificado corretamente.

  Por defeito o servidor aceita várias sessões seguidas (novo acordo X25519 por ligação).
  Use --once para terminar após um ficheiro.

  O acordo de chaves X25519 não autentica o par: um atacante na rede (MITM) pode negociar
  chaves distintas com cada lado. Use o fingerprint [KEY FINGERPRINT] impresso após o KEX
  como verificação manual (TOFU) quando o canal não for totalmente confiável.

PROTOCOLO DE DADOS (resumo — ver README.md):
  Ordem no emissor: leitura do ficheiro → compressão zlib opcional (--compress) → partição
  em blocos de 4 MiB quando o payload (já comprimido) é maior que 12 MiB → por bloco: cifra
  AEAD ou HMAC com a chave de sessão; cabeçalho JSON protegido da mesma forma.
  Com --no-encrypt: não há cifra; cabeçalho e cada bloco levam MAC (HMAC) derivado do mesmo
  segredo X25519 via HKDF (k_mac). Os dois lados devem usar os mesmos --cipher/--hash/
  --compress/--no-encrypt.
"""


def _user_specified_cipher(argv: list[str]) -> bool:
    for a in argv:
        if a == "--cipher" or a.startswith("--cipher="):
            return True
    return False


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src",
        description=(
            "TWO-HEADED-BEAST: transmissão segura de ficheiros entre dois programas via TCP. "
            "Um processo serve (escuta); outro envia após estabelecer chave de sessão (X25519 + HKDF)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    sub = parser.add_subparsers(dest="command", required=False)

    sub.add_parser(
        "menu",
        help="Modo interativo com menus (recomendado para quem evita flags longas).",
        description="Menus guiados para enviar/receber e gerir destinos em ~/.two-headed-beast/peers.json.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    serve = sub.add_parser(
        "serve",
        help="Modo receptor: escuta num endereço e recebe ficheiros.",
        description=(
            "Inicia o servidor TCP. Por defeito permanece à escuta para várias ligações "
            "(cada sessão com novo KEX). Use --once para uma só receção."
        ),
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
        p.add_argument(
            "--quiet",
            "-q",
            action="store_true",
            help="Omitir linha de créditos no arranque.",
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
    serve.add_argument(
        "--once",
        action="store_true",
        help="Terminar após uma receção (por defeito o servidor fica à escuta).",
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

    args.crypto_config = validate_config(
        args.cipher or "AES-256-GCM",
        args.hash,
        args.no_encrypt,
    )


def run_server(args: argparse.Namespace) -> None:
    """
    Escuta num socket; por defeito aceita várias sessões consecutivas (``--once`` limita a uma).

    :param args: argumentos parseados do subcomando ``serve``.
    """
    config = args.crypto_config
    os.makedirs(args.output_dir, exist_ok=True)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.host, args.port))
    server_sock.listen(1)

    if not getattr(args, "quiet", False):
        show_credits()

    print(f"[INFO] Listening on {args.host}:{args.port}")
    if not args.once:
        print("[INFO] Servidor à escuta para várias transferências; Ctrl+C para parar.")

    session = 0
    try:
        while True:
            try:
                conn, addr = server_sock.accept()
            except OSError:
                break
            session += 1
            print(f"\n[INFO] -- Sessão {session} -- ligação de {addr}")
            conn.settimeout(30)
            try:
                k_enc, k_mac, _ = perform_kex(
                    conn,
                    is_server=True,
                    hash_name=args.hash,
                    cipher_config=config,
                    tofu_host=addr[0],
                    tofu_port=args.port,
                )
                conn.settimeout(300)
                receive_file(conn, args.output_dir, k_enc, k_mac, args)
            except Exception as e:
                print(f"[ERROR] Sessão {session}: {e}")
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

            if args.once:
                break

            print("[INFO] À espera da próxima ligação...")

    except KeyboardInterrupt:
        print(f"\n[INFO] Servidor parado após {session} sessão(ões).")
    finally:
        try:
            server_sock.close()
        except OSError:
            pass


def run_client(args: argparse.Namespace) -> str | None:
    """
    Liga ao servidor, realiza KEX e envia o ficheiro.

    :param args: argumentos parseados do subcomando ``send``.
    :return: fingerprint TOFU do par ([KEY FINGERPRINT]) ou None se a ligação falhar antes do KEX.
    """
    if not getattr(args, "quiet", False):
        show_credits()

    config = args.crypto_config
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((args.host, args.port))
    print(f"[INFO] Connected to {args.host}:{args.port}")
    fp: str | None = None
    try:
        k_enc, k_mac, fp = perform_kex(
            sock,
            is_server=False,
            hash_name=args.hash,
            cipher_config=config,
            tofu_host=args.host,
            tofu_port=args.port,
        )
        sock.settimeout(300)
        send_file(sock, args.file, k_enc, k_mac, args)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return fp


def main() -> None:
    """Faz parse dos argumentos, valida e invoca ``serve``, ``send`` ou ``menu``."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        show_splash()
        print()
        print("  Uso: python -m src {serve,send,menu} [opções]")
        print("  Ajuda: python -m src --help")
        print("  Interativo: python -m src menu")
        return

    if args.command == "menu":
        from src.interactive import main_menu

        main_menu()
        return

    _validate_parsed(args)

    if args.command == "serve":
        run_server(args)
    elif args.command == "send":
        run_client(args)
    else:
        parser.error("subcomando inválido")


if __name__ == "__main__":
    main()
