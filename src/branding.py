"""Identidade visual UBI e utilitarios de terminal (ANSI, limpar ecra).

Interface só com texto e linhas ASCII. Paleta inspirada em CLIs modernas (violeta/azul,
sem verde de terminal clássico): foco em legibilidade e tom amigável.
"""

from __future__ import annotations

import os
import sys

__all__ = [
    "Colors",
    "clear_screen",
    "supports_ansi",
    "show_splash",
    "show_header",
    "show_credits",
]


def clear_screen() -> None:
    """
    Limpa o ecrã visível e coloca o cursor no canto superior esquerdo.

    Não usamos o executável ``clear`` no Unix: em terminais integrados (IDE) ou com
    ``TERM`` marginais ele costuma *imprimir dezenas de newlines* para «empurrar» o
    conteúdo, o que deixa um bloco enorme de linhas em branco entre o splash e o
    menu seguinte.
    """
    if not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
        return
    if os.name == "nt":
        os.system("cls")
    else:
        print("\033[2J\033[H", end="", flush=True)


def supports_ansi() -> bool:
    """Indica se o terminal provavelmente suporta escapes ANSI (cores)."""
    if os.name == "nt":
        try:
            os.system("")
            return True
        except OSError:
            return False
    return bool(hasattr(sys.stdout, "isatty") and sys.stdout.isatty())


class Colors:
    """Cores semânticas (256 cores). Usar disable() se o terminal não as suportar."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    # BRAND: violeta pedra (estrutura, barras) — eco de UIs “agent/code” em lilás
    BRAND = "\033[38;5;141m"
    # ACCENT: lilás claro (marca e destaques, sem o verde clássico de shell)
    ACCENT = "\033[38;5;183m"
    # PROMPT: azul ardosia (números de menu, prefixo >)
    PROMPT = "\033[38;5;111m"
    # OK: ciano-lavanda (sucesso — não usa verde)
    OK = "\033[38;5;153m"
    # WARN: âmbar suave (ações que pedem atenção)
    WARN = "\033[38;5;215m"
    # ERR: coral suave (menos agressivo que vermelho puro)
    ERR = "\033[38;5;210m"

    @classmethod
    def disable(cls) -> None:
        for attr in (
            "RESET",
            "BOLD",
            "DIM",
            "BRAND",
            "ACCENT",
            "PROMPT",
            "OK",
            "WARN",
            "ERR",
        ):
            setattr(cls, attr, "")


if not supports_ansi():
    Colors.disable()


def show_splash(*, clear: bool = True) -> None:
    """Ecrã «Sobre» / arranque: título UBI + autores (sem logo ASCII).

    :param clear: Se True, limpa o ecrã primeiro (opção 4 / arranque do menu).
    """
    if clear:
        clear_screen()
    bar = "=" * 62

    print(f"{Colors.BRAND}{bar}{Colors.RESET}")
    print(
        f"{Colors.BOLD}{Colors.ACCENT}  TWO-HEADED-BEAST{Colors.RESET}  "
        f"{Colors.DIM}|  Universidade da Beira Interior (UBI){Colors.RESET}"
    )
    print(
        f"{Colors.DIM}  Informática Web, Móvel e na Nuvem  |  "
        f"Cibersegurança 2025/2026{Colors.RESET}"
    )
    print(f"{Colors.BRAND}{bar}{Colors.RESET}")
    print(f"{Colors.ACCENT}  Projeto académico - TWO-HEADED-BEAST{Colors.RESET}")
    print(
        f"{Colors.DIM}  Afonso Esteves 55047 | Felipe Dourado 53394 | "
        f"João Vitor Silva 53396{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}  Rui Machado 53867 | Tiago Pereira 55019{Colors.RESET}"
    )
    print(f"{Colors.BRAND}{bar}{Colors.RESET}")


def show_header() -> None:
    """Cabeçalho compacto (3 linhas), apenas = e texto."""
    w = 60
    bar = "=" * w
    print(f"{Colors.BRAND}{bar}{Colors.RESET}")
    print(
        f"{Colors.BOLD}{Colors.ACCENT}  TWO-HEADED-BEAST{Colors.RESET}  "
        f"{Colors.DIM}|  UBI - Cibersegurança 2025/2026{Colors.RESET}"
    )
    print(f"{Colors.BRAND}{bar}{Colors.RESET}")


def show_credits() -> None:
    """Uma linha para arranque de serve/send sem --quiet."""
    print(
        f"{Colors.PROMPT}src{Colors.RESET}{Colors.DIM} · TWO-HEADED-BEAST · "
        f"UBI Cibersegurança · 2025/2026{Colors.RESET}"
    )
