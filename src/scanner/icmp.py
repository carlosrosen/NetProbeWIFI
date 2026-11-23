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
MAXIMO_HOSTS_PADRAO = 65536

def _validar_ip_local(ip_local: str) -> str:
    """Valida o IP local e rejeita endereços inadequados para varredura."""
    try:
        objeto_ip = ipaddress.IPv4Address(ip_local)
    except ipaddress.AddressValueError as erro:
        raise OSError(f"Endereço IP local inválido: {ip_local!r}.") from erro

    if (
        objeto_ip.is_loopback
        or objeto_ip.is_link_local
        or objeto_ip.is_unspecified
    ):
        raise OSError(
            f"Endereço IP local inadequado para varredura: {ip_local}. "
            "Verifique se a máquina possui um IP de rede local válido."
        )

    return str(objeto_ip)


def obter_ip_local() -> str:
    """
    Obtém o endereço IP local da máquina na interface de rede ativa.

    Rejeita endereços loopback, link-local e 0.0.0.0.

    :return: Endereço IPv4 local como string (ex: '192.168.1.10').
    :raises RuntimeError: Caso não seja possível determinar o endereço IP local.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as soquete:
            soquete.connect(("8.8.8.8", 80))
            return _validar_ip_local(soquete.getsockname()[0])
    except OSError:
        pass

    try:
        ip_local = socket.gethostbyname(socket.gethostname())
        return _validar_ip_local(ip_local)
    except OSError as erro:
        raise RuntimeError(
            "Não foi possível obter um endereço IP local válido para a varredura. "
            "Verifique se há uma conexão de rede ativa e se o IP não é "
            "loopback ou link-local."
        ) from erro


def varrer_rede_icmp(
    rede: Optional[Union[str, ipaddress.IPv4Network]] = None,
    cidr: int = 24,
    tempo_limite: float = 2.0,
    quantidade_pings: int = 2,
    intervalo: float = 0.05,
    tarefas_concorrentes: int = 50,
    privilegiado: bool = False,
) -> Set[Host]:
    """
    Realiza um multiping ICMP para a faixa de endereços disponíveis para os hosts
    na rede e retorna o conjunto de hosts ativos.

    Caso nenhuma rede seja informada, obtém o IP da máquina automaticamente e
    calcula a rede utilizando o CIDR padrão (/24).

    :param rede: Rede alvo no formato CIDR (ex: '192.168.1.0/24'), IP base
                 ou objeto IPv4Network. Se None, usa o IP local da máquina.
    :param cidr: Prefixo CIDR padrão caso apenas um IP seja usado ou na detecção
                 automática (padrão: 24).
    :param tempo_limite: Tempo limite (em segundos) de espera por resposta de
                         cada pacote.
    :param quantidade_pings: Número de pacotes ICMP enviados para cada host.
    :param intervalo: Intervalo (em segundos) entre o envio de cada pacote.
    :param tarefas_concorrentes: Número máximo de tarefas concorrentes para
                                 envio de pings.
    :param privilegiado: Define se o socket usará modo privilegiado (root/admin).
                         No Linux, ``privilegiado=False`` pode exigir a configuração
                         ``net.ipv4.ping_group_range``. No Windows, é ignorado.
    :return: Conjunto (set) contendo os objetos Host (icmplib.Host) dos hosts ativos.
    :raises TypeError: Se os tipos dos parâmetros forem inválidos.
    :raises ValueError: Se os valores de rede, CIDR ou parâmetros de ping forem
                        inválidos, ou se a rede exceder MAXIMO_HOSTS_PADRAO.
    :raises PermissionError: Se não houver permissão para abrir o socket ICMP.
    :raises MemoryError: Se a rede especificada gerar uma lista excessiva de hosts.
    :raises RuntimeError: Se ocorrer erro de rede ou socket durante o escaneamento.
    """
    if (
        not isinstance(cidr, int)
        or isinstance(cidr, bool)
        or not (0 <= cidr <= 32)
    ):
        raise ValueError("O parâmetro 'cidr' deve ser um número inteiro entre 0 e 32.")

    if (
        not isinstance(tempo_limite, (int, float))
        or isinstance(tempo_limite, bool)
        or not math.isfinite(tempo_limite)
        or tempo_limite <= 0
    ):
        raise ValueError(
            "O parâmetro 'tempo_limite' deve ser um número finito maior que zero."
        )

    if (
        not isinstance(quantidade_pings, int)
        or isinstance(quantidade_pings, bool)
        or quantidade_pings <= 0
    ):
        raise ValueError(
            "O parâmetro 'quantidade_pings' deve ser um número inteiro "
            "maior que zero."
        )

    if (
        not isinstance(intervalo, (int, float))
        or isinstance(intervalo, bool)
        or not math.isfinite(intervalo)
        or intervalo < 0
    ):
        raise ValueError(
            "O parâmetro 'intervalo' deve ser um número finito maior ou igual a zero."
        )

    if (
        not isinstance(tarefas_concorrentes, int)
        or isinstance(tarefas_concorrentes, bool)
        or tarefas_concorrentes <= 0
    ):
        raise ValueError(
            "O parâmetro 'tarefas_concorrentes' deve ser um número inteiro "
            "maior que zero."
        )

    if not isinstance(privilegiado, bool):
        raise TypeError("O parâmetro 'privilegiado' deve ser um valor booleano.")

    try:
        if rede is None:
            ip_local = obter_ip_local()
            objeto_rede = ipaddress.IPv4Network(
                f"{ip_local}/{cidr}",
                strict=False,
            )
        elif isinstance(rede, ipaddress.IPv4Network):
            objeto_rede = rede
        elif isinstance(rede, str):
            texto_rede = rede.strip()
            if not texto_rede:
                raise ValueError("A string de endereço de rede não pode ser vazia.")
            if "/" not in texto_rede:
                texto_rede = f"{texto_rede}/{cidr}"
            objeto_rede = ipaddress.IPv4Network(texto_rede, strict=False)
        else:
            raise TypeError(
                "O parâmetro 'rede' deve ser uma string CIDR, IPv4Network ou None."
            )
    except (
        ipaddress.AddressValueError,
        ipaddress.NetmaskValueError,
        ValueError,
    ) as erro:
        raise ValueError(
            f"Endereço de rede ou máscara CIDR inválida ('{rede}'): {erro}"
        ) from erro

    if objeto_rede.num_addresses > MAXIMO_HOSTS_PADRAO:
        raise ValueError(
            f"A rede '{objeto_rede}' possui {objeto_rede.num_addresses} endereços, "
            f"acima do limite de {MAXIMO_HOSTS_PADRAO}. Use uma rede menor."
        )

    # obtém apenas a faixa de endereços disponíveis para hosts (exclui endereço de rede e broadcast em /24)
    try:
        enderecos_alvo = [
            str(endereco_ip) for endereco_ip in objeto_rede.hosts()
        ]
    except MemoryError as erro:
        raise MemoryError(
            f"A rede '{objeto_rede}' é muito grande para ser escaneada de uma só vez. "
            "Utilize um prefixo CIDR maior (ex: /24)."
        ) from erro

    if not enderecos_alvo:
        return set()

    try:
        respostas = multiping(
            addresses=enderecos_alvo,
            count=quantidade_pings,
            interval=intervalo,
            timeout=tempo_limite,
            concurrent_tasks=tarefas_concorrentes,
            privileged=privilegiado,
        )
    except (SocketPermissionError, PermissionError) as erro:
        raise PermissionError(
            "Permissão insuficiente para criar o socket ICMP. "
            "No Linux, execute como root com 'privilegiado=True' ou configure "
            "'net.ipv4.ping_group_range'. No Windows, execute como administrador."
        ) from erro
    except SocketAddressError as erro:
        raise RuntimeError(
            f"Não foi possível vincular o endereço de origem ao socket ICMP: {erro}"
        ) from erro
    except NameLookupError as erro:
        raise ValueError(
            f"Não foi possível resolver um ou mais endereços da rede "
            f"'{objeto_rede}': {erro}"
        ) from erro
    except (ICMPSocketError, ICMPLibError) as erro:
        raise RuntimeError(
            f"Erro no socket ICMP durante o escaneamento da rede "
            f"'{objeto_rede}': {erro}"
        ) from erro
    except OSError as erro:
        raise RuntimeError(
            f"Erro de sistema ou rede ao executar o multiping na rede "
            f"'{objeto_rede}': {erro}"
        ) from erro

    hosts_ativos = {
        host_ativo for host_ativo in respostas if host_ativo.is_alive
    }
    return hosts_ativos
