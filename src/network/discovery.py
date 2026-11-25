"""Integracao dos scanners de rede com o inventario de dispositivos."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from ipaddress import IPv4Address
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
    tempo_limite_arp: float = 3.0,
    tentativas_arp: int = 3,
    intervalo_arp: float = 0.01,
    tempo_limite_porta: float = 0.5,
    salvar: bool = True,
) -> ResultadoDescoberta:
    """Executa a descoberta real e prepara os dados para a exibicao."""

    _validar_quantidade_portas(quantidade_portas)

    dados_rede = obter_dados_rede(interface)
    rede_alvo = rede or dados_rede.rede

    icmp_args = {
        "rede": rede_alvo,
        "interface": dados_rede.interface,
        "tempo_limite": tempo_limite_icmp,
        "quantidade_pings": quantidade_pings,
        "tarefas_concorrentes": tarefas_concorrentes_icmp,
    }

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

    portas_por_ip = None
    if quantidade_portas is not None:
        ips = sorted(
            set(resultados_arp) | {
                host.address
                for host in hosts_icmp
                if getattr(host, "is_alive", False)
            },
            key=IPv4Address,
        )
        portas_por_ip = _escanear_portas(ips, quantidade_portas, tempo_limite_porta)

    inventario = atualizar_inventario(carregar_inventario(), resultados_arp, hosts_icmp, portas_por_ip)

    if salvar:
        salvar_inventario(inventario)

    return ResultadoDescoberta(
        dados_rede=dados_rede,
        dispositivos=[Device.from_dict(ip, dados) for ip, dados in inventario.items()],
    )


def _escanear_portas(ips: Iterable[str], quantidade: int, timeout: float) -> dict[str, list[int]]:
    """Varre as portas de 1 ate a quantidade informada."""

    resultado: dict[str, list[int]] = {}

    for ip in ips:
        quantidade_abertas, encontradas = scan_ports(ip, 1, quantidade, timeout=timeout)
        if quantidade_abertas >= 0:
            resultado[ip] = encontradas

    return resultado


def _validar_quantidade_portas(quantidade: int | None) -> None:
    """Valida a quantidade de portas antes de iniciar a varredura."""

    if quantidade is None:
        return
    if not isinstance(quantidade, int) or isinstance(quantidade, bool):
        raise TypeError("A quantidade de portas deve ser um numero inteiro.")
    if not 1 <= quantidade <= 65535:
        raise ValueError("A quantidade de portas deve estar entre 1 e 65535.")
