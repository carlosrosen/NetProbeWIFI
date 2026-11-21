"""
Módulo de escaneamento de rede via ICMP utilizando a biblioteca icmplib.
"""

import ipaddress
import socket
from typing import Optional, Set, Union

from icmplib import multiping


def get_local_ip() -> str:
    """
    Obtém o endereço IP local da máquina na interface de rede ativa.

    :return: Endereço IPv4 local como string (ex: '192.168.1.10').
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def scan_icmp_network(
    network: Optional[Union[str, ipaddress.IPv4Network]] = None,
    cidr: int = 24,
    timeout: float = 2.0,
    count: int = 2,
    interval: float = 0.05,
    concurrent_tasks: int = 50,
    privileged: bool = False,
) -> Set[str]:
    """
    Realiza um multiping ICMP para a faixa de endereços disponíveis para os hosts
    na rede e retorna o conjunto de IPs ativos.

    Caso nenhuma rede seja informada, obtém o IP da máquina automaticamente e
    calcula a rede utilizando o CIDR padrão (/24).

    :param network: Rede alvo no formato CIDR (ex: '192.168.1.0/24'), IP base
                    ou objeto IPv4Network. Se None, usa o IP local da máquina.
    :param cidr: Prefixo CIDR padrão caso apenas um IP seja usado ou na detecção
                 automática (padrão: 24).
    :param timeout: Tempo limite (em segundos) de espera por resposta de cada pacote.
    :param count: Número de pacotes ICMP enviados para cada host.
    :param interval: Intervalo (em segundos) entre o envio de cada pacote.
    :param concurrent_tasks: Número máximo de tarefas concorrentes para envio de pings.
    :param privileged: Define se o socket usará modo privilegiado (root/admin).
    :return: Conjunto (set) contendo os endereços IP (strings) dos hosts ativos.
    """
    if network is None:
        local_ip = get_local_ip()
        net_obj = ipaddress.ip_network(f"{local_ip}/{cidr}", strict=False)
    elif isinstance(network, ipaddress.IPv4Network):
        net_obj = network
    elif isinstance(network, str):
        net_str = network.strip()
        if "/" not in net_str:
            net_str = f"{net_str}/{cidr}"
        net_obj = ipaddress.ip_network(net_str, strict=False)
    else:
        raise TypeError("O parâmetro 'network' deve ser uma string CIDR, IPv4Network ou None.")

    # Obtém apenas a faixa de endereços disponíveis para hosts (exclui rede e broadcast em /24)
    target_hosts = [str(ip) for ip in net_obj.hosts()]
    if not target_hosts:
        return set()

    responses = multiping(
        addresses=target_hosts,
        count=count,
        interval=interval,
        timeout=timeout,
        concurrent_tasks=concurrent_tasks,
        privileged=privileged,
    )
    

    active_ips = {host for host in responses if host.is_alive}
    return active_ips
