"""Descoberta ARP e detecção de conflitos IP/MAC"""

from __future__ import annotations

import socket
from collections import defaultdict
from ipaddress import IPv4Address, IPv4Network
from typing import Iterable, Mapping, Sequence

from scapy.all import (
    ARP,
    Ether,
    conf,
    get_if_addr,
    get_if_hwaddr,
    resolve_iface,
    srp,
)
from scapy.packet import Packet

try:
    import psutil
except ImportError:  # pragma: no cover - psutil está no requirements.txt
    psutil = None

__all__ = [
    "ResultadoArp",
    "encontrar_conflitos",
    "encontrar_macs_duplicados",
    "filtrar_bloqueados_icmp",
    "obter_rede_local",
    "varrer_rede_arp",
]

# Tipos e constantes

EnderecoIp = str
EnderecoMac = str
NomeInterface = str
ResultadoArp = dict[EnderecoIp, list[EnderecoMac]]

MAC_BROADCAST: EnderecoMac = "ff:ff:ff:ff:ff:ff"
CODIGO_RESPOSTA_ARP = 2
FAMILIA_IPV4 = socket.AF_INET
SEGUNDOS_TEMPO_LIMITE_PADRAO = 1.0
TENTATIVAS_PADRAO = 2
INTERVALO_PADRAO_ENTRE_PACOTES = 0.0

# Funções principais

def obter_rede_local(interface: NomeInterface | None = None) -> tuple[NomeInterface, str]:
    """Retorna ``(interface, rede)`` da rede IPv4 local.

    Se ``interface`` não for informada, usa a interface da rota padrão.
    """
    interface = _resolver_interface(interface)
    rede_ipv4 = _obter_rede_do_sistema(interface)

    if rede_ipv4 is not None:
        return interface, rede_ipv4

    endereco_ipv4_local = get_if_addr(interface)
    if not endereco_ipv4_local or endereco_ipv4_local == "0.0.0.0":
        raise RuntimeError(
            f"Não foi possível descobrir o IPv4 da interface {interface!r}."
        )

    rede_alternativa = IPv4Network(f"{endereco_ipv4_local}/24", strict=False)
    return interface, str(rede_alternativa)

def varrer_rede_arp(
    alvos: Iterable[EnderecoIp] | EnderecoIp | None = None,
    *,
    rede: str | None = None,
    interface: NomeInterface | None = None,
    tempo_limite: float = SEGUNDOS_TEMPO_LIMITE_PADRAO,
    tentativas: int = TENTATIVAS_PADRAO,
    intervalo: float = INTERVALO_PADRAO_ENTRE_PACOTES,
) -> ResultadoArp:
    
    """Descobre dispositivos IPv4 na rede local usando ARP. Retorna {ip: [macs]}. Vários MACs no mesmo IP indicam conflito."""

    _validar_parametros_da_varredura(tempo_limite, tentativas, intervalo)

    ips_alvo, interface = _resolver_ips_alvo(alvos, rede, interface)

    if not ips_alvo:
        return {}

    respostas_por_ip = _enviar_requisicoes_arp(ips_alvo, interface=interface, tempo_limite=tempo_limite, tentativas=tentativas,intervalo=intervalo)

    return _converter_para_resultado_ordenado(respostas_por_ip)

def filtrar_bloqueados_icmp(
    resultados_arp: Mapping[EnderecoIp, Iterable[EnderecoMac]],
    ips_ativos: Iterable[object],
) -> ResultadoArp:
    """Retorna entradas ARP cujo IP não respondeu ao ICMP.

    Aceita strings, ``IPv4Address`` ou objetos com atributo ``address``,
    como os ``Host`` retornados pelo ``icmplib``.
    """
    ips_ativos_normalizados = {
        _normalizar_ip_ativo(item) for item in ips_ativos
    }

    return {
        endereco_ip: _normalizar_macs(enderecos_mac)
        for endereco_ip, enderecos_mac in resultados_arp.items()
        if endereco_ip not in ips_ativos_normalizados
    }

def encontrar_conflitos(resultados_arp: Mapping[EnderecoIp, Iterable[EnderecoMac]]) -> ResultadoArp:
    """Retorna IPs reivindicados por mais de um MAC."""
    conflitos: ResultadoArp = {}

    for endereco_ip, enderecos_mac in resultados_arp.items():
        macs_normalizados = _normalizar_macs(enderecos_mac)
        if len(macs_normalizados) > 1:
            conflitos[endereco_ip] = macs_normalizados

    return conflitos


def encontrar_macs_duplicados(resultados_arp: Mapping[EnderecoIp, Iterable[EnderecoMac]]) -> dict[EnderecoMac, list[EnderecoIp]]:
    """Retorna MACs associados a mais de um IP. Não é necessariamente conflito (proxy ARP, múltiplos IPs etc)"""
    ips_por_mac: dict[EnderecoMac, set[EnderecoIp]] = defaultdict(set)

    for endereco_ip, enderecos_mac in resultados_arp.items():
        for endereco_mac in enderecos_mac:
            ips_por_mac[endereco_mac.lower()].add(endereco_ip)

    return {
        endereco_mac: sorted(enderecos_ip, key=IPv4Address)
        for endereco_mac, enderecos_ip in ips_por_mac.items()
        if len(enderecos_ip) > 1
    }

# Descoberta de interface e rede

def _resolver_interface(interface: NomeInterface | None) -> NomeInterface:
    """Retorna uma interface concreta, usando a rota padrão como alternativa."""
    if interface:
        return interface
    return conf.route.route("0.0.0.0")[0]

def _obter_rede_do_sistema(interface: NomeInterface) -> str | None:
    """Tenta obter a rede IPv4 da interface via psutil."""
    
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
            return str(rede_ipv4)

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

# Resolução dos alvos

def _resolver_ips_alvo(alvos: Iterable[EnderecoIp] | EnderecoIp | None, rede: str | None, interface: NomeInterface | None) -> tuple[list[EnderecoIp], NomeInterface]:
    """Resolve a lista de IPs a sondar e a interface a usar."""
    if alvos is not None:
        return _normalizar_ips_alvo(alvos), _resolver_interface(interface)

    if rede is None:
        interface, rede = obter_rede_local(interface)
    else:
        interface = _resolver_interface(interface)

    return _ips_utilizaveis_da_rede(rede), interface

def _normalizar_ips_alvo(alvos: Iterable[EnderecoIp] | EnderecoIp) -> list[EnderecoIp]:
    """Valida e normaliza os IPs informados pelo usuário."""
    if isinstance(alvos, str):
        alvos = [alvos]

    return [str(IPv4Address(endereco_ip)) for endereco_ip in alvos]

def _ips_utilizaveis_da_rede(rede: str) -> list[EnderecoIp]:
    """Gera todos os IPs utilizáveis de uma rede IPv4."""
    rede_ipv4 = IPv4Network(rede, strict=False)
    return [str(endereco_ip) for endereco_ip in rede_ipv4.hosts()]

def _validar_parametros_da_varredura(tempo_limite: float,tentativas: int,intervalo: float) -> None:
    """Valida os parâmetros de tempo e tentativas da varredura."""
    if tempo_limite <= 0:
        raise ValueError("tempo_limite deve ser maior que zero.")
    if tentativas < 0:
        raise ValueError("tentativas não pode ser negativo.")
    if intervalo < 0:
        raise ValueError("intervalo não pode ser negativo.")

# Construção e envio dos pacotes ARP

def _montar_requisicoes_arp(ips_alvo: Sequence[EnderecoIp], interface: NomeInterface) -> list[Ether]:
    """Monta uma requisição ARP broadcast para cada IP alvo. O MAC e o IP de origem são definidos explicitamente a partir de ``interface``."""
    try:
        mac_origem = get_if_hwaddr(interface)
        ip_origem = get_if_addr(interface)
    except Exception as exc:
        raise RuntimeError(
            f"Não foi possível obter o MAC/IP da interface {interface!r}: {exc}"
        ) from exc

    if not ip_origem or ip_origem == "0.0.0.0":
        raise RuntimeError(
            f"A interface {interface!r} não possui um endereço IPv4 válido."
        )

    return [
        Ether(dst=MAC_BROADCAST, src=mac_origem) / ARP(pdst=ip_alvo, psrc=ip_origem)
        for ip_alvo in ips_alvo
    ]

def _enviar_requisicoes_arp(
    ips_alvo: Sequence[EnderecoIp],
    *,
    interface: NomeInterface,
    tempo_limite: float,
    tentativas: int,
    intervalo: float,
) -> dict[EnderecoIp, set[EnderecoMac]]:
    """Envia as requisições ARP e retorna ``{ip: {macs}}``."""
    requisicoes_arp = _montar_requisicoes_arp(ips_alvo, interface)

    try:
        pacotes_respondidos, _pacotes_sem_resposta = srp(
            requisicoes_arp,
            iface=interface,
            timeout=tempo_limite,
            retry=tentativas,
            inter=intervalo,
            multi=True,
            verbose=False,
        )

    except PermissionError as exc:
        raise RuntimeError(
            "ARP precisa de privilégios de administrador/root. "
            "No Windows, instale o Npcap e execute o terminal como administrador. E no Linux/macOS, execute com sudo."
        ) from exc
    
    except RuntimeError as exc:
        mensagem_erro = str(exc).lower()
        if "winpcap" in mensagem_erro or "layer 2" in mensagem_erro:
            raise RuntimeError(
                "O Scapy não conseguiu abrir a camada 2. No Windows, instale o Npcap e execute o terminal como administrador."
            ) from exc
        raise
    return _agrupar_respostas_por_ip(pacotes_respondidos)

# Análise das respostas

def _agrupar_respostas_por_ip(pacotes_respondidos: Iterable[tuple[Packet, Packet]]) -> dict[EnderecoIp, set[EnderecoMac]]:
    """Agrupa as respostas ARP pelo IP de origem."""
    respostas_por_ip: dict[EnderecoIp, set[EnderecoMac]] = defaultdict(set)

    for _requisicao, resposta in pacotes_respondidos:
        if ARP not in resposta:
            continue

        camada_arp = resposta[ARP]
        if camada_arp.op != CODIGO_RESPOSTA_ARP:
            continue
        if camada_arp.psrc == "0.0.0.0":
            continue

        respostas_por_ip[camada_arp.psrc].add(camada_arp.hwsrc.lower())

    return dict(respostas_por_ip)

def _converter_para_resultado_ordenado(respostas_por_ip: Mapping[EnderecoIp, Iterable[EnderecoMac]]) -> ResultadoArp:
    """Converte o agrupamento interno no resultado público ordenado."""
    return {
        endereco_ip: sorted(respostas_por_ip[endereco_ip])
        for endereco_ip in sorted(respostas_por_ip, key=IPv4Address)
    }

def _normalizar_macs(enderecos_mac: Iterable[EnderecoMac]) -> list[EnderecoMac]:
    """Retorna MACs em minúsculo, sem duplicatas e ordenados."""
    return sorted({endereco_mac.lower() for endereco_mac in enderecos_mac})

def _normalizar_ip_ativo(item: object) -> EnderecoIp:
    """Converte string, IPv4Address ou objeto com address em IP canônico."""
    if isinstance(item, str):
        endereco = item.strip()
    elif isinstance(item, IPv4Address):
        endereco = str(item)
    else:
        endereco = getattr(item, "address", None)
        if isinstance(endereco, IPv4Address):
            endereco = str(endereco)
        elif not isinstance(endereco, str):
            raise TypeError(
                "Cada item de 'ips_ativos' deve ser uma string de IP, "
                "IPv4Address ou um objeto com atributo 'address'."
            )
        endereco = endereco.strip()
    return str(IPv4Address(endereco))

# ---------------------------------------------------------------------------
# Teste manual
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Rode `python -m src.scanner.arp` como administrador/root.
    resultados_arp = varrer_rede_arp()

    if not resultados_arp:
        print("Nenhum dispositivo respondeu ao ARP.")
    else:
        for endereco_ip, enderecos_mac in resultados_arp.items():
            marcador_conflito = (
                "  <-- CONFLITO" if len(enderecos_mac) > 1 else ""
            )
            print(
                f"{endereco_ip:15} {' / '.join(enderecos_mac)}"
                f"{marcador_conflito}"
            )
