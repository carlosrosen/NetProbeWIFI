"""
Módulo de escaneamento de rede via ICMP utilizando a biblioteca icmplib.
"""

import ipaddress
import math
import socket
from typing import Optional, Set, Union

from icmplib import (
    Host,
    ICMPLibError,
    ICMPSocketError,
    NameLookupError,
    SocketAddressError,
    SocketPermissionError,
    multiping,
)

# limite de segurança para evitar listas gigantes (ex: /0, /8)
MAX_HOSTS_PADRAO = 65536

def _validar_ip_local(local_ip: str) -> str:
    """Valida o IP local e rejeita endereços inadequados para varredura."""
    try:
        ip_obj = ipaddress.IPv4Address(local_ip)
    except ipaddress.AddressValueError as e:
        raise OSError(f"Endereço IP local inválido: {local_ip!r}.") from e

    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified:
        raise OSError(
            f"Endereço IP local inadequado para varredura: {local_ip}. "
            "Verifique se a máquina possui um IP de rede local válido."
        )

    return str(ip_obj)

def get_local_ip() -> str:
    """
    Obtém o endereço IP local da máquina na interface de rede ativa.

    Rejeita endereços loopback, link-local e 0.0.0.0.

    :return: Endereço IPv4 local como string (ex: '192.168.1.10').
    :raises RuntimeError: Caso não seja possível determinar o endereço IP local.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return _validar_ip_local(s.getsockname()[0])
    except OSError:
        pass

    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        return _validar_ip_local(local_ip)
    except OSError as e:
        raise RuntimeError(
            "Não foi possível obter um endereço IP local válido para a varredura. "
            "Verifique se há uma conexão de rede ativa e se o IP não é "
            "loopback ou link-local."
        ) from e

def scan_icmp_network(
    network: Optional[Union[str, ipaddress.IPv4Network]] = None,
    cidr: int = 24,
    timeout: float = 2.0,
    count: int = 2,
    interval: float = 0.05,
    concurrent_tasks: int = 50,
    privileged: bool = False,
) -> Set[Host]:
    """
    Realiza um multiping ICMP para a faixa de endereços disponíveis para os hosts
    na rede e retorna o conjunto de hosts ativos.

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
                       No Linux, ``privileged=False`` pode exigir a configuração
                       ``net.ipv4.ping_group_range``. No Windows, é ignorado.
    :return: Conjunto (set) contendo os objetos Host (icmplib.Host) dos hosts ativos.
    :raises TypeError: Se os tipos dos parâmetros forem inválidos.
    :raises ValueError: Se os valores de rede, CIDR ou parâmetros de ping forem
                        inválidos, ou se a rede exceder MAX_HOSTS_PADRAO.
    :raises PermissionError: Se não houver permissão para abrir o socket ICMP.
    :raises MemoryError: Se a rede especificada gerar uma lista excessiva de hosts.
    :raises RuntimeError: Se ocorrer erro de rede ou socket durante o escaneamento.
    """
    if not isinstance(cidr, int) or isinstance(cidr, bool) or not (0 <= cidr <= 32):
        raise ValueError("O parâmetro 'cidr' deve ser um número inteiro entre 0 e 32.")

    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("O parâmetro 'timeout' deve ser um número finito maior que zero.")

    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        raise ValueError("O parâmetro 'count' deve ser um número inteiro maior que zero.")

    if (
        not isinstance(interval, (int, float))
        or isinstance(interval, bool)
        or not math.isfinite(interval)
        or interval < 0
    ):
        raise ValueError(
            "O parâmetro 'interval' deve ser um número finito maior ou igual a zero."
        )

    if (
        not isinstance(concurrent_tasks, int)
        or isinstance(concurrent_tasks, bool)
        or concurrent_tasks <= 0
    ):
        raise ValueError(
            "O parâmetro 'concurrent_tasks' deve ser um número inteiro maior que zero."
        )

    if not isinstance(privileged, bool):
        raise TypeError("O parâmetro 'privileged' deve ser um valor booleano.")

    try:
        if network is None:
            local_ip = get_local_ip()
            net_obj = ipaddress.IPv4Network(f"{local_ip}/{cidr}", strict=False)
        elif isinstance(network, ipaddress.IPv4Network):
            net_obj = network
        elif isinstance(network, str):
            net_str = network.strip()
            if not net_str:
                raise ValueError("A string de endereço de rede não pode ser vazia.")
            if "/" not in net_str:
                net_str = f"{net_str}/{cidr}"
            net_obj = ipaddress.IPv4Network(net_str, strict=False)
        else:
            raise TypeError(
                "O parâmetro 'network' deve ser uma string CIDR, IPv4Network ou None."
            )
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
        raise ValueError(
            f"Endereço de rede ou máscara CIDR inválida ('{network}'): {e}"
        ) from e

    if net_obj.num_addresses > MAX_HOSTS_PADRAO:
        raise ValueError(
            f"A rede '{net_obj}' possui {net_obj.num_addresses} endereços, "
            f"acima do limite de {MAX_HOSTS_PADRAO}. Use uma rede menor."
        )

    # obtem apenas a faixa de endereços disponíveis para hosts (exclui rede e broadcast em /24)
    try:
        target_hosts = [str(ip) for ip in net_obj.hosts()]
    except MemoryError as e:
        raise MemoryError(
            f"A rede '{net_obj}' é muito grande para ser escaneada de uma só vez. "
            "Utilize um prefixo CIDR maior (ex: /24)."
        ) from e

    if not target_hosts:
        return set()

    try:
        responses = multiping(
            addresses=target_hosts,
            count=count,
            interval=interval,
            timeout=timeout,
            concurrent_tasks=concurrent_tasks,
            privileged=privileged,
        )
    except (SocketPermissionError, PermissionError) as e:
        raise PermissionError(
            "Permissão insuficiente para criar o socket ICMP. "
            "No Linux, execute como root com 'privileged=True' ou configure "
            "'net.ipv4.ping_group_range'. No Windows, execute como administrador."
        ) from e
    except SocketAddressError as e:
        raise RuntimeError(
            f"Não foi possível vincular o endereço de origem ao socket ICMP: {e}"
        ) from e
    except NameLookupError as e:
        raise ValueError(
            f"Não foi possível resolver um ou mais endereços da rede '{net_obj}': {e}"
        ) from e
    except (ICMPSocketError, ICMPLibError) as e:
        raise RuntimeError(
            f"Erro no socket ICMP durante o escaneamento da rede '{net_obj}': {e}"
        ) from e
    except OSError as e:
        raise RuntimeError(
            f"Erro de sistema ou rede ao executar o multiping na rede '{net_obj}': {e}"
        ) from e

    active_hosts = {host for host in responses if host.is_alive}
    return active_hosts
