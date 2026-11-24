"""Descoberta de interface, IP e rede IPv4 local."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from scapy.all import conf, get_if_addr, resolve_iface

try:
    import psutil
except ImportError:  # pragma: no cover - psutil está no requirements.txt
    psutil = None

NomeInterface = str
FAMILIA_IPV4 = socket.AF_INET

@dataclass(frozen=True)
class DadosRede:
    """Dados de rede de uma interface local."""
    interface: NomeInterface
    ip_local: str
    rede: str
    mascara: str | None = None

__all__ = [
    "DadosRede",
    "FAMILIA_IPV4",
    "NomeInterface",
    "obter_dados_rede",
]

def obter_dados_rede(interface: NomeInterface | None = None) -> DadosRede:
    """Retorna interface, IP local, rede e máscara."""

    interface = _resolver_interface(interface)
    dados = _obter_dados_do_sistema(interface)

    if dados is not None:
        return dados

    ip_local = _obter_ip_validado(interface)

    rede_alternativa = IPv4Network(
        f"{ip_local}/24",
        strict=False,
    )
    return DadosRede(
        interface=interface,
        ip_local=ip_local,
        rede=str(rede_alternativa),
    )

def _resolver_interface(interface: NomeInterface | None) -> NomeInterface:
    """Retorna uma interface concreta, com o nome amigável quando possível."""

    if not interface:
        interface = conf.route.route("0.0.0.0")[0]

    try:
        nome_amigavel = resolve_iface(interface).name
    except Exception:
        return interface

    return nome_amigavel or interface

def _validar_ip_local(ip_local: str) -> str:
    """Valida o IP local e rejeita endereços inadequados para varredura."""

    try:
        objeto_ip = IPv4Address(ip_local)
    except ValueError as erro:
        raise OSError(f"Endereço IP local inválido: {ip_local!r}.") from erro

    if (objeto_ip.is_loopback or objeto_ip.is_link_local or objeto_ip.is_unspecified):
        raise OSError(f"Endereço IP local inadequado para varredura: {ip_local}. Verifique se a máquina possui um IP de rede local válido.")

    return str(objeto_ip)

def _obter_ip_validado(interface: NomeInterface) -> str:
    """Obtém e valida o IPv4 de uma interface."""

    ip_local = get_if_addr(interface)

    if not ip_local or ip_local == "0.0.0.0":
        raise RuntimeError(f"Não foi possível descobrir o IPv4 da interface {interface!r}.")

    try:
        return _validar_ip_local(ip_local)
    except OSError as erro:
        raise RuntimeError(f"Não foi possível obter um IP local válido: {erro}") from erro

def _obter_dados_do_sistema(interface: NomeInterface) -> DadosRede | None:
    """Tenta obter IP, máscara e rede da interface via psutil."""

    if psutil is None:
        return None

    enderecos_da_interface = psutil.net_if_addrs()
    for nome_da_interface in _candidatos_de_nome_da_interface(interface):
        for endereco in enderecos_da_interface.get(nome_da_interface, []):
            if endereco.family != FAMILIA_IPV4 or not endereco.netmask:
                continue

            rede_ipv4 = IPv4Network(
                f"{endereco.address}/{endereco.netmask}",
                strict=False,
            )

            return DadosRede(
                interface=interface,
                ip_local=str(endereco.address),
                rede=str(rede_ipv4),
                mascara=str(endereco.netmask),
            )
    return None

def _candidatos_de_nome_da_interface(interface: NomeInterface) -> list[str]:
    """Retorna os nomes possíveis da interface para consultar o psutil."""

    candidatos = [interface]

    try:
        nome_amigavel = resolve_iface(interface).name
        if nome_amigavel and nome_amigavel != interface:
            candidatos.insert(0, nome_amigavel)
    except Exception:
        pass

    return candidatos
