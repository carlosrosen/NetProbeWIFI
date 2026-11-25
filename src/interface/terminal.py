"""Menu do NetProbe Wi-Fi. Execute com python -m src.interface.terminal."""

from __future__ import annotations

import math
import os
import sys
from dataclasses import dataclass, replace
from datetime import datetime
from ipaddress import IPv4Network
from pathlib import Path
from typing import TYPE_CHECKING

try:
    from rich import box
    from rich.console import Console
    from rich.prompt import IntPrompt, Prompt
    from rich.table import Table
    from rich.text import Text
except ModuleNotFoundError as erro:
    if erro.name != "rich":
        raise
    raise SystemExit("O Rich não está instalado neste Python. Inicie pelo abrir-netprobe.cmd ou execute python3 main.py.") from None

# Ao rodar o arquivo pelo editor, o Python só inclui src/interface na busca.
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

if TYPE_CHECKING:
    from src.models.device import Device
    from src.network.discovery import ResultadoDescoberta


def _limpar_tela(console: Console) -> None:
    """Limpa a tela do terminal, usando cls no Windows."""
    if os.name == "nt":
        if sys.stdout.isatty() or console.is_terminal:
            os.system("cls")
    elif console.is_terminal:
        console.clear()


@dataclass(frozen=True)
class Opcoes:
    interface: str | None = None
    rede: IPv4Network | None = None
    timeout_icmp: float = 1.0
    quantidade_pings: int = 2
    intervalo_icmp: float = 0.05
    concorrencia_icmp: int = 50
    timeout_arp: float = 3.0
    tentativas_arp: int = 3
    intervalo_arp: float = 0.01
    timeout_tcp: float = 0.3
    portas: tuple[int, int] | None = (1, 100)
    concorrencia_tcp: int = 100
    portas_excluidas: tuple[int, ...] = ()


def _automatico(valor: str) -> str | None:
    valor = valor.strip()
    return None if valor.casefold() in {"", "auto", "automática", "automatica"} else valor


def _pedir_rede(console: Console, atual: IPv4Network | None) -> IPv4Network | None:
    while True:
        entrada = Prompt.ask("Rede IPv4/CIDR (ou auto)", default=str(atual) if atual else "auto", console=console)
        valor = _automatico(entrada)
        if valor is None:
            return None
        try:
            return IPv4Network(valor if "/" in valor else f"{valor}/24", strict=False)
        except ValueError:
            console.print("Informe uma rede IPv4 como 192.168.1.0/24.", style="yellow")


def _pedir_segundos(console: Console, rotulo: str, atual: float, *, aceita_zero: bool = False) -> float:
    while True:
        valor = Prompt.ask(f"{rotulo} (s)", default=str(atual).replace(".", ","), console=console)
        try:
            segundos = float(valor.replace(",", "."))
            if math.isfinite(segundos) and (segundos > 0 or aceita_zero and segundos == 0):
                return segundos
        except ValueError:
            pass
        limite = "maior ou igual a zero" if aceita_zero else "maior que zero"
        console.print(f"Informe um valor em segundos {limite}.", style="yellow")


def _pedir_inteiro(
    console: Console, rotulo: str, atual: int, *, minimo: int = 1, maximo: int | None = None,
) -> int:
    while True:
        valor = IntPrompt.ask(rotulo, default=atual, console=console)
        if valor >= minimo and (maximo is None or valor <= maximo):
            return valor
        limite = f"entre {minimo} e {maximo}" if maximo is not None else f"maior ou igual a {minimo}"
        console.print(f"Informe um inteiro {limite}.", style="yellow")


def _pedir_exclusoes(console: Console, atuais: tuple[int, ...], inicio: int, fim: int) -> tuple[int, ...]:
    padrao = ", ".join(str(porta) for porta in atuais if inicio <= porta <= fim) or "nenhuma"
    while True:
        entrada = Prompt.ask("Portas excluídas (separe por vírgulas ou digite nenhuma)", default=padrao, console=console)
        if entrada.strip().casefold() == "nenhuma":
            return ()
        try:
            portas = sorted({int(porta) for porta in entrada.split(",")})
            if all(inicio <= porta <= fim for porta in portas):
                return tuple(portas)
        except ValueError:
            pass
        console.print(f"Informe portas inteiras entre {inicio} e {fim}, separadas por vírgulas.", style="yellow")


def _personalizar_tcp(console: Console, opcoes: Opcoes) -> Opcoes:
    verificar = Prompt.ask(
        "Verificar portas TCP?", choices=["s", "n"], default="s" if opcoes.portas else "n", console=console,
    )
    if verificar == "n":
        return replace(opcoes, portas=None)

    inicial, final = opcoes.portas or (1, 100)
    inicio = _pedir_inteiro(console, "Porta inicial", inicial, maximo=65535)
    fim = _pedir_inteiro(console, "Porta final", max(inicio, final), minimo=inicio, maximo=65535)
    return replace(
        opcoes,
        portas=(inicio, fim),
        timeout_tcp=_pedir_segundos(console, "Timeout TCP", opcoes.timeout_tcp),
        concorrencia_tcp=_pedir_inteiro(console, "Conexões TCP simultâneas", opcoes.concorrencia_tcp),
        portas_excluidas=_pedir_exclusoes(console, opcoes.portas_excluidas, inicio, fim),
    )


def _texto_intervalo(portas: tuple[int, int] | None) -> str:
    return f"{portas[0]} a {portas[1]}" if portas else "desativada"


def _personalizar(console: Console, opcoes: Opcoes) -> Opcoes:
    while True:
        _limpar_tela(console)
        console.print("[bold]Personalizar varredura[/bold]")
        console.print("1. Interface e rede\n2. ICMP (ping)\n3. Portas TCP\n4. ARP\n0. Voltar")
        escolha = Prompt.ask("Opção", choices=["1", "2", "3", "4", "0"], console=console)

        if escolha == "0":
            return opcoes

        _limpar_tela(console)
        if escolha == "1":
            interface = Prompt.ask("Interface (nome ou auto)", default=opcoes.interface or "auto", console=console)
            opcoes = replace(opcoes, interface=_automatico(interface), rede=_pedir_rede(console, opcoes.rede))
        elif escolha == "2":
            opcoes = replace(
                opcoes,
                timeout_icmp=_pedir_segundos(console, "Timeout ICMP", opcoes.timeout_icmp),
                quantidade_pings=_pedir_inteiro(console, "Pings por IP", opcoes.quantidade_pings),
                intervalo_icmp=_pedir_segundos(console, "Intervalo entre pings", opcoes.intervalo_icmp, aceita_zero=True),
                concorrencia_icmp=_pedir_inteiro(console, "Tarefas ICMP simultâneas", opcoes.concorrencia_icmp),
            )
        elif escolha == "3":
            opcoes = _personalizar_tcp(console, opcoes)
        else:
            opcoes = replace(
                opcoes,
                timeout_arp=_pedir_segundos(console, "Timeout ARP", opcoes.timeout_arp),
                tentativas_arp=_pedir_inteiro(console, "Reenvios ARP", opcoes.tentativas_arp, minimo=0),
                intervalo_arp=_pedir_segundos(console, "Intervalo entre pacotes ARP", opcoes.intervalo_arp, aceita_zero=True),
            )


def _ultima_visualizacao(valor: str | None) -> str:
    if not valor:
        return "-"
    try:
        return datetime.fromisoformat(valor).strftime("%d/%m/%Y\n%H:%M:%S")
    except ValueError:
        return valor


def _tabela(dispositivos: list[Device], largura: int) -> Table:
    tabela = Table(box=box.ASCII, padding=(0, 0))
    tabela.add_column("IP", no_wrap=True)
    tabela.add_column("Status", min_width=7)
    tabela.add_column("MAC(s)", no_wrap=True)
    tabela.add_column("Via", min_width=9, no_wrap=True)
    bloqueio = "bloqueado" if largura >= 83 else "bloq."
    tabela.add_column(f"ICMP\n{bloqueio}", justify="center", min_width=len(bloqueio))
    tabela.add_column("Conflito", min_width=8)
    tabela.add_column("Última\nvez visto", overflow="fold", min_width=10)

    for item in dispositivos:
        estado = {"online": "Online", "offline": "Offline", "unknown": "Desconhecido"}[item.status]
        protocolos = [
            nome for nome, respondeu in (("ARP", item.arp_ativo), ("ICMP", item.icmp_ativo)) if respondeu
        ]
        tabela.add_row(
            item.ip,
            Text(estado, style="green" if item.status == "online" else "dim"),
            Text("\n".join(item.macs) or "-"),
            ", ".join(protocolos) or "-",
            Text("Sim", style="yellow") if item.icmp_bloqueado else "Não",
            Text("Sim", style="yellow") if item.arp_ativo and item.conflito else "Não",
            Text(_ultima_visualizacao(item.ultima_vez_visto)),
        )
    return tabela


def _tabela_varredura(opcoes: Opcoes, resultado: ResultadoDescoberta) -> Table:
    tabela = Table(
        title="Dados da varredura", title_style="bold", title_justify="left",
        box=box.ASCII, show_header=False, show_lines=True, padding=(0, 2),
    )
    tabela.add_column(style="bold cyan", no_wrap=True)
    tabela.add_column()

    dados = resultado.dados_rede
    mascara = dados.mascara or IPv4Network(dados.rede).netmask
    rede = [
        f"Interface: {dados.interface}  |  IPv4 local: {dados.ip_local}",
        f"Rede da interface: {dados.rede}  |  Máscara: {mascara}",
    ]
    alvo = resultado.rede_varrida
    if alvo is not None and str(alvo) != dados.rede:
        rede.append(f"Faixa analisada: {alvo}  |  Máscara da faixa: {alvo.netmask}")
    tabela.add_row("Rede", Text("\n".join(rede)))

    tabela.add_row(
        "ICMP", f"Pings por IP: {opcoes.quantidade_pings}  |  Timeout ICMP: {opcoes.timeout_icmp:g} s\n"
        f"Intervalo ICMP: {opcoes.intervalo_icmp:g} s  |  Tarefas ICMP simultâneas: {opcoes.concorrencia_icmp}",
    )
    tabela.add_row(
        "ARP", f"Timeout ARP: {opcoes.timeout_arp:g} s  |  Reenvios ARP: {opcoes.tentativas_arp}\n"
        f"Intervalo ARP: {opcoes.intervalo_arp:g} s",
    )
    if opcoes.portas:
        excluidas = ", ".join(map(str, opcoes.portas_excluidas)) or "nenhuma"
        tabela.add_row(
            "TCP", f"Portas TCP: {_texto_intervalo(opcoes.portas)}  |  Timeout TCP: {opcoes.timeout_tcp:g} s\n"
            f"Conexões TCP simultâneas: {opcoes.concorrencia_tcp}\nPortas TCP excluídas: {excluidas}",
        )
    else:
        tabela.add_row("TCP", "Verificação TCP: desativada")

    conflitos = sum(item.arp_ativo and item.conflito for item in resultado.dispositivos)
    bloqueados = sum(item.icmp_bloqueado for item in resultado.dispositivos)
    tabela.add_row(
        "Resumo", f"Online: {len(resultado.online)}  |  Offline: {len(resultado.offline)}\n"
        f"ICMP bloqueado: {bloqueados}  |  Conflitos de IP: {conflitos}",
    )
    return tabela


def _varrer(console: Console, opcoes: Opcoes) -> None:
    from src.network.discovery import descobrir_dispositivos

    with console.status("Varredura: em andamento", spinner="line"):
        resultado = descobrir_dispositivos(
            interface=opcoes.interface, rede=str(opcoes.rede) if opcoes.rede else None,
            limitar_rede_local=True, quantidade_portas=None, intervalo_portas=opcoes.portas,
            portas_excluidas=opcoes.portas_excluidas, concorrencia_portas=opcoes.concorrencia_tcp,
            tempo_limite_porta=opcoes.timeout_tcp, tempo_limite_icmp=opcoes.timeout_icmp,
            quantidade_pings=opcoes.quantidade_pings, intervalo_icmp=opcoes.intervalo_icmp,
            tarefas_concorrentes_icmp=opcoes.concorrencia_icmp, tempo_limite_arp=opcoes.timeout_arp,
            tentativas_arp=opcoes.tentativas_arp, intervalo_arp=opcoes.intervalo_arp,
        )

    console.print(_tabela_varredura(opcoes, resultado))
    dispositivos = resultado.dispositivos
    if dispositivos:
        console.print()
        console.print(_tabela(dispositivos, console.width))
    else:
        console.print("Dispositivos: nenhum encontrado")
    console.print("Inventário: dados/inventario.json")

    if resultado.portas_verificadas:
        console.print(f"\n[bold]Portas TCP abertas[/bold] ({_texto_intervalo(opcoes.portas)})")
        for ip, portas in resultado.portas_verificadas.items():
            texto = "Falha" if portas is None else ", ".join(map(str, portas)) or "Nenhuma"
            console.print(Text.assemble((f"{ip:<15}", "green"), "  ", texto))


def main() -> None:
    console = Console()
    opcoes = Opcoes()
    primeira_vez = True

    try:
        while True:
            if not primeira_vez:
                _limpar_tela(console)
            primeira_vez = False

            console.print("[bold cyan]NetProbe Wi-Fi[/bold cyan]")
            interface = opcoes.interface or "automática"
            rede = opcoes.rede or "automática"
            console.print(f"\nInterface: {interface} | Rede: {rede} | Verificação TCP: {_texto_intervalo(opcoes.portas)}", markup=False)
            console.print("1. Iniciar varredura\n2. Personalizar\n0. Sair")
            escolha = Prompt.ask("Opção", choices=["1", "2", "0"], console=console)
            if escolha == "0":
                return
            if escolha == "2":
                opcoes = _personalizar(console, opcoes)
            else:
                _limpar_tela(console)
                try:
                    _varrer(console, opcoes)
                except (ImportError, OSError, RuntimeError, ValueError) as erro:
                    console.print(f"Falha na varredura. {erro}", style="red", markup=False)
                Prompt.ask(
                    "\nPressione Enter para voltar ao menu",
                    default="",
                    show_default=False,
                    console=console,
                )
    except EOFError:
        return
    except KeyboardInterrupt:
        console.print("\nOperação interrompida.")


if __name__ == "__main__":
    main()
