"""
Modo interativo com menus (sem alterar protocolo nem transfer).

Reutiliza :func:`src.cli._validate_parsed`, :func:`src.cli.run_client` e
:func:`src.cli.run_server`.
"""

from __future__ import annotations

import argparse
import os
import sys

from src.branding import Colors, clear_screen, show_header, show_splash
from src.crypto_config import CIPHERS, HASHES
from src import peers as peers_mod


def _strip_wrapping_quotes(path: str) -> str:
    """Remove aspas à volta se o utilizador colar um caminho entre \"...\" ou '...'."""
    p = path.strip()
    if len(p) >= 2 and p[0] == p[-1] and p[0] in ('"', "'"):
        return p[1:-1].strip()
    return p


def _tip(*lines: str) -> None:
    """Imprime dicas em texto discreto (uma ou mais linhas)."""
    for line in lines:
        print(f"  {Colors.DIM}{line}{Colors.RESET}")


def _prompt_yn(prompt: str, default: bool) -> bool:
    """Lê sim/não; Enter aceita o *default*."""
    hint = "[S/n]" if default else "[s/N]"
    raw = input(f"{Colors.PROMPT}>{Colors.RESET} {prompt} {hint}: ").strip().lower()
    if not raw:
        return default
    return raw in ("s", "sim", "y", "yes")


def _prompt_line(prompt: str, default: str = "", *, parens: str | None = None) -> str:
    """
    Lê uma linha; Enter aceita *default*.

    :param parens: dica entre parêntesis (ex. valor típico). Se for igual ao *default*,
        não se repete também em ``[default]`` — mostra-se só uma vez.
    """
    label = f"{prompt} ({parens})" if parens else prompt
    show_bracket = bool(default) and (parens is None or str(parens) != str(default))
    suf = f" [{default}]" if show_bracket else ""
    raw = input(f"{Colors.PROMPT}>{Colors.RESET} {label}{suf}: ").strip()
    return raw if raw else default


def _print_main_menu_options() -> None:
    """Imprime só as opções e a dica (sem limpar ecrã nem cabeçalho compacto)."""
    print(f"  {Colors.ACCENT}1{Colors.RESET}) {Colors.BOLD}Enviar ficheiro{Colors.RESET}")
    print(f"  {Colors.ACCENT}2{Colors.RESET}) {Colors.BOLD}Receber ficheiro{Colors.RESET}")
    print(f"  {Colors.PROMPT}3{Colors.RESET}) Gerir destinos guardados")
    print(f"  {Colors.PROMPT}4{Colors.RESET}) Sobre")
    print(f"  {Colors.PROMPT}0{Colors.RESET}) Sair")
    print()
    _tip(
        "Enviar (1) e Receber (2) abrem assistentes passo a passo - mesmo estilo de perguntas.",
    )


def _draw_main_menu() -> None:
    clear_screen()
    show_header()
    print()
    _print_main_menu_options()


def _about() -> None:
    show_splash()
    input(f"\n{Colors.DIM}Enter para voltar...{Colors.RESET}")


def _manage_peers() -> None:
    while True:
        clear_screen()
        show_header()
        print(f"\n{Colors.BOLD}-- Destinos guardados --{Colors.RESET}\n")
        plist = peers_mod.list_peers()
        if not plist:
            print(f"  {Colors.DIM}(nenhum destino guardado){Colors.RESET}")
        else:
            for i, p in enumerate(plist, 1):
                print(
                    f"  {Colors.PROMPT}{i}{Colors.RESET}) {p['alias']}  ->  "
                    f"{p['host']}:{p['port']}"
                )
        print(f"\n  {Colors.OK}[A]{Colors.RESET} Adicionar   "
              f"{Colors.WARN}[R]{Colors.RESET} Remover   "
              f"{Colors.DIM}[V]{Colors.RESET} Voltar")
        choice = input(f"\n{Colors.PROMPT}>{Colors.RESET} Escolha: ").strip().upper()
        if choice == "V" or choice == "":
            return
        if choice == "A":
            alias = input(f"{Colors.PROMPT}>{Colors.RESET} Alias: ").strip()
            _tip(
                "IP = endereço IPv4 do outro PC (ex.: 192.168.1.50). "
                "No mesmo computador a receber localmente: 127.0.0.1",
            )
            host = input(f"{Colors.PROMPT}>{Colors.RESET} IP (host): ").strip()
            port_s = _prompt_line("Porta", "9000", parens="9000")
            try:
                port = int(port_s)
            except ValueError:
                print(f"{Colors.ERR}Porta inválida.{Colors.RESET}")
                input(f"{Colors.DIM}Enter...{Colors.RESET}")
                continue
            if alias and host:
                peers_mod.add_peer(alias, host, port)
                print(f"{Colors.OK}Guardado.{Colors.RESET}")
            else:
                print(f"{Colors.ERR}Alias e host obrigatórios.{Colors.RESET}")
            input(f"{Colors.DIM}Enter...{Colors.RESET}")
        elif choice == "R":
            if not plist:
                input(f"{Colors.DIM}Enter...{Colors.RESET}")
                continue
            idx_s = input(f"{Colors.PROMPT}>{Colors.RESET} Número a remover: ").strip()
            try:
                idx = int(idx_s)
                if 1 <= idx <= len(plist):
                    alias = plist[idx - 1]["alias"]
                    if peers_mod.remove_peer(alias):
                        print(f"{Colors.OK}Removido.{Colors.RESET}")
                    else:
                        print(f"{Colors.ERR}Falha.{Colors.RESET}")
                else:
                    print(f"{Colors.ERR}Número inválido.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.ERR}Número inválido.{Colors.RESET}")
            input(f"{Colors.DIM}Enter...{Colors.RESET}")


def _choose_cipher_interactive() -> str:
    print(f"\n{Colors.DIM}Cifras: {', '.join(CIPHERS)}{Colors.RESET}")
    c = _prompt_line("Cifra", "AES-256-GCM", parens="AES-256-GCM").upper()
    if c not in CIPHERS:
        print(f"{Colors.ERR}Cifra desconhecida; uso AES-256-GCM.{Colors.RESET}")
        return "AES-256-GCM"
    return c


def _choose_hash_interactive() -> str:
    print(f"\n{Colors.DIM}Hashes: {', '.join(HASHES)}{Colors.RESET}")
    h = _prompt_line("Hash", "SHA256", parens="SHA256").upper()
    if h not in HASHES:
        print(f"{Colors.ERR}Hash desconhecido; uso SHA256.{Colors.RESET}")
        return "SHA256"
    return h


def _flow_send() -> None:
    from src.cli import _validate_parsed, run_client

    clear_screen()
    show_header()
    print(f"\n{Colors.BOLD}-- Destino --{Colors.RESET}\n")
    plist = peers_mod.list_peers()
    host: str
    port: int
    picked_new = False

    if not plist:
        print(f"  {Colors.DIM}Sem destinos guardados.{Colors.RESET}\n")
        _tip(
            "IP do computador que está a receber o ficheiro.",
            "- Mesmo computador (teste local): 127.0.0.1",
            "- Outro PC na rede Wi-Fi: IPv4 desse PC (ex.: 192.168.1.x).",
        )
        host = input(f"{Colors.PROMPT}>{Colors.RESET} IP (host): ").strip()
        port_s = _prompt_line("Porta", "9000", parens="9000")
        try:
            port = int(port_s)
        except ValueError:
            port = 9000
        picked_new = True
    else:
        for i, p in enumerate(plist, 1):
            print(
                f"  {Colors.PROMPT}{i}{Colors.RESET}) {p['alias']}  ->  "
                f"{p['host']}:{p['port']}"
            )
        print(f"  {Colors.PROMPT}{len(plist) + 1}{Colors.RESET}) Novo endereço...")
        raw = input(f"\n{Colors.PROMPT}>{Colors.RESET} Escolha [1-{len(plist) + 1}]: ").strip()
        try:
            n = int(raw)
        except ValueError:
            print(f"{Colors.ERR}Opção inválida.{Colors.RESET}")
            input(f"{Colors.DIM}Enter...{Colors.RESET}")
            return
        if 1 <= n <= len(plist):
            host = plist[n - 1]["host"]
            port = int(plist[n - 1]["port"])
            picked_new = False
        elif n == len(plist) + 1:
            _tip(
                "IP do computador que está a receber o ficheiro.",
                "- Mesmo computador: 127.0.0.1  |  Outro na rede: ex. 192.168.1.x",
            )
            host = input(f"{Colors.PROMPT}>{Colors.RESET} IP (host): ").strip()
            port_s = _prompt_line("Porta", "9000", parens="9000")
            try:
                port = int(port_s)
            except ValueError:
                port = 9000
            picked_new = True
        else:
            print(f"{Colors.ERR}Opção inválida.{Colors.RESET}")
            input(f"{Colors.DIM}Enter...{Colors.RESET}")
            return

    if not host:
        print(f"{Colors.ERR}Host obrigatório.{Colors.RESET}")
        input(f"{Colors.DIM}Enter...{Colors.RESET}")
        return

    clear_screen()
    show_header()
    print(f"\n{Colors.BOLD}-- Ficheiro --{Colors.RESET}\n")
    _tip(
        "Se o caminho tiver espaços ou caracteres especiais, use aspas duplas ou simples:",
        '  ex. "/Users/nome/Pasta/meus ficheiros/foto.png"',
        '  ex. \'C:\\Users\\nome\\Desktop\\doc.pdf\'   (Windows - barra dupla também funciona)',
        "No Terminal macOS pode arrastar o ficheiro para a janela para colar o caminho completo.",
    )
    print()
    filepath = ""
    while True:
        raw_path = input(
            f"{Colors.PROMPT}>{Colors.RESET} Caminho do ficheiro (pode ir entre aspas): "
        ).strip()
        filepath = _strip_wrapping_quotes(raw_path)
        if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
            break
        print(f"{Colors.ERR}Ficheiro inexistente ou sem leitura. Repita.{Colors.RESET}")

    clear_screen()
    show_header()
    print(f"\n{Colors.BOLD}-- Opções de segurança --{Colors.RESET}\n")
    encrypt = _prompt_yn("Cifrar conteúdo?", True)
    cipher = None
    if encrypt:
        cipher = _choose_cipher_interactive()
    else:
        cipher = None  # _validate_parsed define None com no_encrypt

    compress = _prompt_yn("Comprimir com zlib?", False)
    hash_name = _choose_hash_interactive()
    _tip("Caminho PEM opcional. Aspas se tiver espaços, ex.: \"/Users/nome/chave.pem\"")
    sign_path = input(
        f"{Colors.PROMPT}>{Colors.RESET} Chave privada para assinar (Enter omitir): "
    ).strip()
    sign_key = _strip_wrapping_quotes(sign_path) if sign_path else None

    args = argparse.Namespace(
        command="send",
        host=host,
        port=port,
        file=filepath,
        cipher=cipher,
        no_encrypt=not encrypt,
        compress=compress,
        hash=hash_name,
        sign_key=sign_key,
        verify_key=None,
        quiet=True,
    )

    try:
        _validate_parsed(args)
    except SystemExit as e:
        print(f"{Colors.ERR}{e}{Colors.RESET}")
        input(f"{Colors.DIM}Enter...{Colors.RESET}")
        return

    clear_screen()
    show_header()
    print()

    fp: str | None = None
    try:
        fp = run_client(args)
    except Exception as e:
        print(f"{Colors.ERR}[ERRO] {e}{Colors.RESET}")
        input(f"{Colors.DIM}Enter para voltar ao menu...{Colors.RESET}")
        return

    if picked_new and _prompt_yn("Guardar este destino?", False):
        alias = input(f"{Colors.PROMPT}>{Colors.RESET} Alias (ex.: pc-casa): ").strip()
        if alias:
            peers_mod.add_peer(alias, host, port)
            print(f"{Colors.OK}Destino guardado.{Colors.RESET}")
        input(f"{Colors.DIM}Enter...{Colors.RESET}")

    if fp and _prompt_yn(
        "Guardar o [KEY FINGERPRINT] deste par em peers.json (TOFU) para alertas futuros?",
        False,
    ):
        peers_mod.save_fingerprint(host, port, fp)
        print(f"{Colors.OK}Fingerprint guardado para {host}:{port}.{Colors.RESET}")


def _flow_receive() -> None:
    from src import kex
    from src.cli import _validate_parsed, run_server

    clear_screen()
    show_header()
    print(f"\n{Colors.BOLD}-- Servidor --{Colors.RESET}\n")
    _tip(
        "Início rápido: na pergunta abaixo, Enter = escuta em 0.0.0.0 porta 9000",
        "(rede local + neste PC). Só responda «sim» se precisar de outro IP ou porta.",
    )
    manual_net = _prompt_yn("Definir IP ou porta manualmente?", False)
    if manual_net:
        _tip(
            "0.0.0.0 = todas as interfaces (rede e 127.0.0.1). 127.0.0.1 = só este computador.",
        )
        host = _prompt_line("IP / host de escuta", "0.0.0.0", parens="0.0.0.0")
        port_s = _prompt_line("Porta", "9000", parens="9000")
        try:
            port = int(port_s)
        except ValueError:
            print(f"{Colors.ERR}Porta inválida; uso 9000.{Colors.RESET}")
            port = 9000
    else:
        host = "0.0.0.0"
        port = 9000
    _tip(
        "Pasta de gravação (relativa ou absoluta). Aspas se o caminho tiver espaços.",
    )
    out_dir = _strip_wrapping_quotes(
        _prompt_line("Pasta de destino", "./received", parens="./received")
    )
    continuous = _prompt_yn(
        "Modo contínuo (ficar à escuta para vários ficheiros)?", True
    )

    clear_screen()
    show_header()
    print(f"\n{Colors.BOLD}-- Opções de segurança --{Colors.RESET}\n")
    encrypt = _prompt_yn("Esperas receção cifrada (par usa cifra)?", True)
    cipher = _choose_cipher_interactive() if encrypt else None
    compress = _prompt_yn("O par envia comprimido (usar --compress no envio)?", False)
    hash_name = _choose_hash_interactive()
    _tip("PEM de chave pública ou certificado X.509 (opcional). Use aspas se o caminho tiver espaços.")
    verify_path = input(
        f"{Colors.PROMPT}>{Colors.RESET} Chave/Cert para verificar assinatura (Enter omitir): "
    ).strip()
    verify_key = _strip_wrapping_quotes(verify_path) if verify_path else None

    args = argparse.Namespace(
        command="serve",
        host=host,
        port=port,
        output_dir=out_dir,
        cipher=cipher,
        no_encrypt=not encrypt,
        compress=compress,
        hash=hash_name,
        verify_key=verify_key,
        sign_key=None,
        quiet=True,
        once=not continuous,
    )

    try:
        _validate_parsed(args)
    except SystemExit as e:
        print(f"{Colors.ERR}{e}{Colors.RESET}")
        input(f"{Colors.DIM}Enter...{Colors.RESET}")
        return

    clear_screen()
    show_header()
    print()

    try:
        run_server(args)
    except KeyboardInterrupt:
        print(f"\n{Colors.DIM}Interrompido.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.ERR}[ERRO] {e}{Colors.RESET}")

    if kex.LAST_SESSION_PEER_FINGERPRINT and kex.LAST_SESSION_TOFU_KEY:
        th, tp = kex.LAST_SESSION_TOFU_KEY
        if not args.once:
            _tip(
                "Servidor em modo contínuo: o fingerprint abaixo é só o da última sessão "
                "antes de parar (Ctrl+C).",
            )
        if _prompt_yn(
            "Guardar o último [KEY FINGERPRINT] do par em peers.json (TOFU)?",
            False,
        ):
            peers_mod.save_fingerprint(th, tp, kex.LAST_SESSION_PEER_FINGERPRINT)
            print(f"{Colors.OK}Fingerprint guardado para {th}:{tp}.{Colors.RESET}")

    input(f"{Colors.DIM}Enter para voltar ao menu...{Colors.RESET}")


def main_menu() -> None:
    """Loop principal do modo interactivo."""
    # Uma só limpeza + splash; opções logo a seguir (evita segundo «clear» que deixa o
    # bloco curto no meio de um ecrã full-screen cheio de linhas vazias).
    show_splash()
    first_draw = True
    try:
        while True:
            if first_draw:
                first_draw = False
                print()
                _print_main_menu_options()
            else:
                _draw_main_menu()
            choice = input(f"{Colors.PROMPT}>{Colors.RESET} Opção: ").strip()
            if choice == "1":
                _flow_send()
            elif choice == "2":
                _flow_receive()
            elif choice == "3":
                _manage_peers()
            elif choice == "4":
                _about()
            elif choice == "0":
                print(f"\n{Colors.DIM}Até logo.{Colors.RESET}")
                return
            else:
                print(f"{Colors.ERR}Opção inválida.{Colors.RESET}")
                input(f"{Colors.DIM}Enter...{Colors.RESET}")
    except KeyboardInterrupt:
        print(f"\n{Colors.DIM}Saindo...{Colors.RESET}")
        sys.exit(0)
