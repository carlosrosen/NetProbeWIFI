"""Integracao dos scanners de rede com o inventario de dispositivos."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Iterable

from src.models.device import (Device, atualizar_inventario, carregar_inventario, salvar_inventario)
from src.network.interfaces import DadosRede, obter_dados_rede
from src.scanner.arp import varrer_rede_arp
from src.scanner.icmp import varrer_rede_icmp
from src.scanner.ports import scan_ports

__all__ = [
    "ResultadoDescoberta",
    "descobrir_dispositivos",
]

@dataclass(frozen=True)
class ResultadoDescoberta:
    """Dados da rede e dispositivos prontos para a exibicao."""

    dados_rede: DadosRede
    dispositivos: list[Device]
    rede_varrida: IPv4Network | None = None
    portas_verificadas: dict[str, list[int] | None] | None = None

    @property
    def online(self) -> list[Device]:
        """Dispositivos encontrados na varredura atual."""
        return [
            dispositivo
            for dispositivo in self.dispositivos
            if dispositivo.status == "online"
        ]

    @property
    def offline(self) -> list[Device]:
        """Dispositivos conhecidos que nao responderam agora."""
        return [
            dispositivo
            for dispositivo in self.dispositivos
            if dispositivo.status == "offline"
        ]


def descobrir_dispositivos(
    interface: str | None = None,
    rede: str | None = None,
    quantidade_portas: int | None = 100,
    *,
    tempo_limite_icmp: float = 2.0,
    quantidade_pings: int = 2,
    tarefas_concorrentes_icmp: int = 50,
    intervalo_icmp: float | None = None,
    tempo_limite_arp: float = 3.0,
    tentativas_arp: int = 3,
    intervalo_arp: float = 0.01,
    tempo_limite_porta: float = 0.5,
    salvar: bool = True,
    intervalo_portas: tuple[int, int] | None = None,
    portas_excluidas: tuple[int, ...] = (),
    concorrencia_portas: int | None = None,
    limitar_rede_local: bool = False,
) -> ResultadoDescoberta:
    """Descobre dispositivos. Um intervalo explícito tem prioridade sobre quantidade_portas."""

    _validar_quantidade_portas(quantidade_portas)
    if intervalo_portas is not None:
        inicio, fim = intervalo_portas
        if not 1 <= inicio <= fim <= 65535:
            raise ValueError("O intervalo de portas deve estar entre 1 e 65535.")
    elif quantidade_portas is not None:
        intervalo_portas = (1, quantidade_portas)

    dados_rede = obter_dados_rede(interface)
    rede_varrida = _rede_local(dados_rede, rede) if limitar_rede_local else None
    rede_alvo = str(rede_varrida) if rede_varrida is not None else rede or dados_rede.rede

    icmp_args = {
        "rede": rede_alvo,
        "interface": dados_rede.interface,
        "tempo_limite": tempo_limite_icmp,
        "quantidade_pings": quantidade_pings,
        "tarefas_concorrentes": tarefas_concorrentes_icmp,
    }
    if intervalo_icmp is not None:
        icmp_args["intervalo"] = intervalo_icmp

    arp_args = {
        "rede": rede_alvo,
        "interface": dados_rede.interface,
        "tempo_limite": tempo_limite_arp,
        "tentativas": tentativas_arp,
        "intervalo": intervalo_arp,
    }

    with ThreadPoolExecutor(max_workers=2) as executor:
        futuro_icmp = executor.submit(varrer_rede_icmp, **icmp_args)
        futuro_arp = executor.submit(varrer_rede_arp, **arp_args)
        hosts_icmp = futuro_icmp.result()
        resultados_arp = futuro_arp.result()

    faixa = None
    if rede_varrida is not None:
        faixa = {str(ip) for ip in rede_varrida.hosts()}
        resultados_arp = {ip: macs for ip, macs in resultados_arp.items() if ip in faixa}
        hosts_icmp = [host for host in hosts_icmp if host.address in faixa]

    verificadas = portas_por_ip = None
    if intervalo_portas is not None:
        ips = sorted(
            set(resultados_arp) | {
                host.address
                for host in hosts_icmp
                if getattr(host, "is_alive", False)
            },
            key=IPv4Address,
        )
        verificadas = _escanear_portas(
            ips, intervalo_portas, tempo_limite_porta, portas_excluidas, concorrencia_portas,
        )
        portas_por_ip = {ip: portas for ip, portas in verificadas.items() if portas is not None}

    anterior = carregar_inventario()
    historico = anterior if faixa is None else {ip: dados for ip, dados in anterior.items() if ip in faixa}
    inventario = atualizar_inventario(historico, resultados_arp, hosts_icmp, portas_por_ip)

    if salvar:
        salvar_inventario(inventario if faixa is None else {**anterior, **inventario})

    return ResultadoDescoberta(
        dados_rede=dados_rede,
        dispositivos=[Device.from_dict(ip, dados) for ip, dados in inventario.items()],
        rede_varrida=rede_varrida,
        portas_verificadas=verificadas,
    )


def _rede_local(dados: DadosRede, rede: str | None) -> IPv4Network:
    rede_local = IPv4Network(dados.rede)
    alvo = IPv4Network(rede or f"{dados.ip_local}/{max(24, rede_local.prefixlen)}", strict=False)
    if not alvo.subnet_of(rede_local):
        raise ValueError(f"A rede {alvo} está fora da sub-rede da interface ({rede_local}).")
    return alvo


def _escanear_portas(
    ips: Iterable[str], intervalo: tuple[int, int], timeout: float,
    excluidas: tuple[int, ...], concorrencia: int | None,
) -> dict[str, list[int] | None]:
    inicio, fim = intervalo
    argumentos = {"timeout": timeout}
    if excluidas:
        argumentos["ignorar"] = list(excluidas)
    if concorrencia is not None:
        argumentos["max_workers"] = concorrencia
    if excluidas and sum(inicio <= porta <= fim for porta in set(excluidas)) == fim - inicio + 1:
        return {ip: [] for ip in ips}

    resultado: dict[str, list[int] | None] = {}

    for ip in ips:
        quantidade_abertas, encontradas = scan_ports(ip, inicio, fim, **argumentos)
        resultado[ip] = encontradas if quantidade_abertas >= 0 else None

    return resultado


def _validar_quantidade_portas(quantidade: int | None) -> None:
    """Valida a quantidade de portas antes de iniciar a varredura."""

    if quantidade is None:
        return
    if not isinstance(quantidade, int) or isinstance(quantidade, bool):
        raise TypeError("A quantidade de portas deve ser um numero inteiro.")
    if not 1 <= quantidade <= 65535:
        raise ValueError("A quantidade de portas deve estar entre 1 e 65535.")
