# SCRIPT APENAS PARA TESTE, NAO VAI SER A VERSAO DEFINITIVA E NEM A ESTRUTURA DE VISUALIZAÇAO FINAL

"""Validação manual do inventário ARP + ICMP na rede local.

Uso:
    python tests/validar_rede_local.py
    python tests/validar_rede_local.py --interface "Wi-Fi"
    python tests/validar_rede_local.py --rede 192.168.1.0/24
    python tests/validar_rede_local.py --apenas-icmp

O script não solicita elevação. Por padrão, roda com o usuário atual.
Em máquina sem admin/Npcap, use ``--apenas-icmp`` para não tentar ARP.
Ele não é um teste pytest, porque depende da rede real e dos dispositivos
ligados.
"""

from __future__ import annotations

import argparse
import os
import sys
from ipaddress import IPv4Address
from pathlib import Path


# Permite executar o script de qualquer diretório: python tests/validar_rede_local.py
RAIZ_PROJETO = Path(__file__).resolve().parents[1]
if str(RAIZ_PROJETO) not in sys.path:
    sys.path.insert(0, str(RAIZ_PROJETO))


from src.network.interfaces import obter_dados_rede
from src.scanner.arp import (
    encontrar_conflitos,
    encontrar_macs_duplicados,
    filtrar_bloqueados_icmp,
    varrer_rede_arp,
)
from src.scanner.icmp import varrer_rede_icmp


def _esta_com_admin() -> bool:
    """Retorna True se o processo atual estiver elevado."""
    if sys.platform == "win32":
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())

    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def criar_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Valida ICMP + ARP na rede local.",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Interface de rede. Se omitida, usa a rota padrão.",
    )
    parser.add_argument(
        "--rede",
        default=None,
        help="Rede em CIDR. Se omitida, usa a rede real da interface.",
    )
    parser.add_argument(
        "--tempo-limite",
        type=float,
        default=1.0,
        help="Timeout do ICMP por pacote (padrão: 1.0 s).",
    )
    parser.add_argument(
        "--quantidade-pings",
        type=int,
        default=1,
        help="Pacotes ICMP por host (padrão: 1).",
    )
    parser.add_argument(
        "--intervalo",
        type=float,
        default=0.05,
        help="Intervalo entre pacotes ICMP (padrão: 0.05 s).",
    )
    parser.add_argument(
        "--tarefas-concorrentes",
        type=int,
        default=50,
        help="Pings ICMP simultâneos (padrão: 50).",
    )
    parser.add_argument(
        "--privilegiado",
        action="store_true",
        help="Usa socket ICMP privilegiado (root/admin).",
    )
    parser.add_argument(
        "--apenas-icmp",
        "--sem-arp",
        dest="apenas_icmp",
        action="store_true",
        help="Não executa ARP; use em máquina sem admin/Npcap.",
    )
    parser.add_argument(
        "--tempo-limite-arp",
        type=float,
        default=2.0,
        help="Timeout do ARP (padrão: 2.0 s).",
    )
    parser.add_argument(
        "--tentativas",
        type=int,
        default=2,
        help="Tentativas de ARP (padrão: 2).",
    )
    parser.add_argument(
        "--intervalo-arp",
        type=float,
        default=0.01,
        help="Intervalo entre pacotes ARP (padrão: 0.01 s).",
    )
    return parser


def _chave_ip(host) -> IPv4Address:
    return IPv4Address(host.address)


def executar_icmp(args, dados):
    print("\n== ICMP ==")
    try:
        hosts = varrer_rede_icmp(
            rede=dados.rede if args.rede is None else args.rede,
            interface=dados.interface,
            tempo_limite=args.tempo_limite,
            quantidade_pings=args.quantidade_pings,
            intervalo=args.intervalo,
            tarefas_concorrentes=args.tarefas_concorrentes,
            privilegiado=args.privilegiado,
        )
    except Exception as erro:
        print(f"ERRO no ICMP: {type(erro).__name__}: {erro}")
        return None

    if not hosts:
        print("Nenhum host respondeu ao ICMP.")
        return hosts

    for host in sorted(hosts, key=_chave_ip):
        print(
            f"  {host.address:15} "
            f"avg_rtt={host.avg_rtt:.3f} ms "
            f"perda={host.packet_loss * 100:.0f}%"
        )

    return hosts


def executar_arp(args, dados):
    print("\n== ARP ==")
    try:
        resultados = varrer_rede_arp(
            rede=dados.rede if args.rede is None else args.rede,
            interface=dados.interface,
            tempo_limite=args.tempo_limite_arp,
            tentativas=args.tentativas,
            intervalo=args.intervalo_arp,
        )
    except Exception as erro:
        print(f"ERRO no ARP: {type(erro).__name__}: {erro}")
        print(
            "No Windows, verifique o Npcap e execute como administrador. "
            "No Linux, use sudo ou CAP_NET_RAW."
        )
        return None

    if not resultados:
        print("Nenhum dispositivo respondeu ao ARP.")
        return resultados

    for endereco_ip, enderecos_mac in resultados.items():
        print(f"  {endereco_ip:15} {' / '.join(enderecos_mac)}")

    return resultados


def main() -> int:
    args = criar_parser().parse_args()

    print("Use este script apenas em redes que você tem autorização para testar.")
    modo = "administrador" if _esta_com_admin() else "usuário comum"
    print(f"Modo de execução: {modo} (o script não solicita elevação)")

    if args.privilegiado and not _esta_com_admin():
        print(
            "Aviso: '--privilegiado' foi solicitado, mas o processo "
            "não está elevado."
        )

    if args.apenas_icmp:
        print("ARP será ignorado por causa de '--apenas-icmp'.")

    try:
        dados = obter_dados_rede(args.interface)
    except Exception as erro:
        print(f"ERRO ao descobrir a rede local: {type(erro).__name__}: {erro}")
        return 1

    print("\n== Rede local ==")
    print(f"  Interface : {dados.interface}")
    print(f"  IP local  : {dados.ip_local}")
    print(f"  Rede      : {dados.rede}")
    print(f"  Máscara   : {dados.mascara or 'desconhecida'}")

    hosts_icmp = executar_icmp(args, dados)

    if args.apenas_icmp:
        resultados_arp = None
    else:
        resultados_arp = executar_arp(args, dados)

    if resultados_arp is not None:
        print("\n== Conflitos e duplicidades ==")
        conflitos = encontrar_conflitos(resultados_arp)
        macs_duplicados = encontrar_macs_duplicados(resultados_arp)

        print(f"  Conflitos de IP   : {conflitos or 'nenhum'}")
        print(f"  MACs em vários IPs: {macs_duplicados or 'nenhum'}")

    if hosts_icmp is not None and resultados_arp is not None:
        print("\n== Ativos no ARP que não responderam ao ICMP ==")
        bloqueados = filtrar_bloqueados_icmp(resultados_arp, hosts_icmp)

        if not bloqueados:
            print("  Nenhum.")
        else:
            for endereco_ip, enderecos_mac in bloqueados.items():
                print(f"  {endereco_ip:15} {' / '.join(enderecos_mac)}")

    if hosts_icmp is None and resultados_arp is None:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
