"""Módulo de escaneamento de rede via ICMP utilizando a biblioteca icmplib."""

import ipaddress
import math
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

from src.network.interfaces import (NomeInterface, obter_dados_rede)

# Limite de segurança para evitar redes gigantes (ex: /0, /8)
MAXIMO_HOSTS_PADRAO = 65536

def varrer_rede_icmp(
    rede: Optional[Union[str, ipaddress.IPv4Network]] = None,
    cidr: int = 24,
    tempo_limite: float = 2.0,
    quantidade_pings: int = 2,
    intervalo: float = 0.05,
    tarefas_concorrentes: int = 50,
    privilegiado: bool = False,
    interface: NomeInterface | None = None,
) -> Set[Host]:
    """Realiza um ping sweep ICMP e retorna os hosts ativos."""
    
    _validar_parametros_da_varredura(cidr, tempo_limite, quantidade_pings, intervalo, tarefas_concorrentes, privilegiado)

    dados = obter_dados_rede(interface)
    interface = dados.interface

    if rede is None:
        rede = dados.rede

    try:
        if isinstance(rede, ipaddress.IPv4Network):
            objeto_rede = rede
        elif isinstance(rede, str):
            texto_rede = rede.strip()
            if not texto_rede:
                raise ValueError("A string de endereço de rede não pode ser vazia.")
            if "/" not in texto_rede:
                texto_rede = f"{texto_rede}/{cidr}"
            objeto_rede = ipaddress.IPv4Network(texto_rede, strict=False)
        else:
            raise TypeError("O parâmetro 'rede' deve ser uma string CIDR, IPv4Network ou None.")
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as erro:
        raise ValueError(f"Endereço de rede ou máscara CIDR inválida ('{rede}'): {erro}") from erro

    if objeto_rede.num_addresses > MAXIMO_HOSTS_PADRAO:
        raise ValueError(f"A rede '{objeto_rede}' possui {objeto_rede.num_addresses} endereços, acima do limite de {MAXIMO_HOSTS_PADRAO}. Use uma rede menor.")

    try:
        enderecos_alvo = [str(endereco_ip) for endereco_ip in objeto_rede.hosts()]
    except MemoryError as erro:
        raise MemoryError(f"A rede '{objeto_rede}' é muito grande para ser escaneada de uma só vez. Utilize um prefixo CIDR maior (ex: /24).") from erro

    if not enderecos_alvo:
        return set()

    try:
        respostas = multiping(
            addresses=enderecos_alvo,
            count=quantidade_pings,
            interval=intervalo,
            timeout=tempo_limite,
            concurrent_tasks=tarefas_concorrentes,
            source=dados.ip_local,
            privileged=privilegiado,
        )
    except (SocketPermissionError, PermissionError) as erro:
        raise PermissionError(
            "Permissão insuficiente para criar o socket ICMP. "
            "No Linux, execute como root com 'privilegiado=True' ou configure "
            "'net.ipv4.ping_group_range'. No Windows, execute como administrador."
        ) from erro
    except SocketAddressError as erro:
        raise RuntimeError(f"Não foi possível vincular o endereço de origem ao socket ICMP: {erro}") from erro
    except NameLookupError as erro:
        raise ValueError(f"Não foi possível resolver um ou mais endereços da rede '{objeto_rede}': {erro}") from erro
    except (ICMPSocketError, ICMPLibError) as erro:
        raise RuntimeError(f"Erro no socket ICMP durante o escaneamento da rede '{objeto_rede}': {erro}") from erro
    except OSError as erro:
        raise RuntimeError(f"Erro de sistema ou rede ao executar o multiping na rede '{objeto_rede}': {erro}") from erro

    hosts_ativos = {host_ativo for host_ativo in respostas if host_ativo.is_alive}

    return hosts_ativos

def _validar_parametros_da_varredura(cidr: int, tempo_limite: float, quantidade_pings: int, intervalo: float, tarefas_concorrentes: int, privilegiado: bool) -> None:
    """Valida os parâmetros de entrada do ping sweep."""
    if (not isinstance(cidr, int)or isinstance(cidr, bool) or not (0 <= cidr <= 32)):
        raise ValueError("O parâmetro 'cidr' deve ser um número inteiro entre 0 e 32.")

    if (not isinstance(tempo_limite, (int, float)) or isinstance(tempo_limite, bool) or not math.isfinite(tempo_limite) or tempo_limite <= 0):
        raise ValueError("O parâmetro 'tempo_limite' deve ser um número finito maior que zero.")

    if (not isinstance(quantidade_pings, int) or isinstance(quantidade_pings, bool) or quantidade_pings <= 0):
        raise ValueError("O parâmetro 'quantidade_pings' deve ser um número inteiro maior que zero.")

    if (not isinstance(intervalo, (int, float)) or isinstance(intervalo, bool) or not math.isfinite(intervalo) or intervalo < 0):
        raise ValueError("O parâmetro 'intervalo' deve ser um número finito maior ou igual a zero.")

    if (not isinstance(tarefas_concorrentes, int) or isinstance(tarefas_concorrentes, bool) or tarefas_concorrentes <= 0):
        raise ValueError("O parâmetro 'tarefas_concorrentes' deve ser um número inteiro maior que zero.")

    if not isinstance(privilegiado, bool):
        raise TypeError("O parâmetro 'privilegiado' deve ser um valor booleano.")
