"""Validacao manual do discovery com exibicao completa dos dados."""

# Execute a partir da raiz do projeto:
#
#   .\.venv\Scripts\python.exe tests\validar_discovery.py
#
# Exemplos:
#
#   .\.venv\Scripts\python.exe tests\validar_discovery.py --interface Ethernet
#   .\.venv\Scripts\python.exe tests\validar_discovery.py --quantidade-portas 50
#   .\.venv\Scripts\python.exe tests\validar_discovery.py --sem-portas
#   .\.venv\Scripts\python.exe tests\validar_discovery.py --sem-salvar
#
# Com o ambiente virtual ativado:
#
#   python tests\validar_discovery.py

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path


RAIZ_PROJETO = Path(__file__).resolve().parents[1]
if str(RAIZ_PROJETO) not in sys.path:
    sys.path.insert(0, str(RAIZ_PROJETO))


from src.models.device import CAMINHO_INVENTARIO, carregar_inventario
from src.network.discovery import (
    ResultadoDescoberta,
    descobrir_dispositivos,
)


def criar_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Executa o discovery real e exibe todos os dados dos dispositivos."
        ),
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Interface de rede. Se omitida, usa a rota padrao.",
    )
    parser.add_argument(
        "--rede",
        default=None,
        help="Rede no formato CIDR. Se omitida, usa a rede da interface.",
    )
    parser.add_argument(
        "--quantidade-portas",
        type=int,
        default=100,
        help=(
            "Quantidade de portas a escanear, de 1 ate N. "
            "Padrao: 100."
        ),
    )
    parser.add_argument(
        "--sem-portas",
        action="store_true",
        help="Nao executa a varredura de portas.",
    )
    parser.add_argument(
        "--tempo-limite-porta",
        type=float,
        default=0.5,
        help="Timeout de cada porta, em segundos.",
    )
    parser.add_argument(
        "--tarefas-icmp",
        type=int,
        default=50,
        help="Numero de tarefas ICMP simultaneas.",
    )
    parser.add_argument(
        "--tempo-limite-arp",
        type=float,
        default=3.0,
        help="Timeout do ARP, em segundos.",
    )
    parser.add_argument(
        "--tentativas-arp",
        type=int,
        default=3,
        help="Numero de tentativas do ARP.",
    )
    parser.add_argument(
        "--intervalo-arp",
        type=float,
        default=0.01,
        help="Intervalo entre pacotes ARP, em segundos.",
    )
    parser.add_argument(
        "--sem-salvar",
        action="store_true",
        help="Nao grava o inventario em dados/inventario.json.",
    )
    return parser


def exibir_rede(dados_rede) -> None:
    print("\n== Rede ==")
    print(f"  Interface : {dados_rede.interface}")
    print(f"  IP local  : {dados_rede.ip_local}")
    print(f"  Rede      : {dados_rede.rede}")
    print(f"  Mascara   : {dados_rede.mascara or 'desconhecida'}")


def exibir_resumo(resultado: ResultadoDescoberta) -> None:
    print("\n== Resumo ==")
    print(f"  Total   : {len(resultado.dispositivos)}")
    print(f"  Online  : {len(resultado.online)}")
    print(f"  Offline : {len(resultado.offline)}")


def exibir_dispositivos(resultado: ResultadoDescoberta) -> None:
    print("\n== Dispositivos ==")

    if not resultado.dispositivos:
        print("  Nenhum dispositivo encontrado.")
        return

    for indice, dispositivo in enumerate(resultado.dispositivos, start=1):
        print(f"\n[{indice}] {dispositivo.ip}")
        print(f"  MACs               : {dispositivo.macs}")
        print(f"  MAC principal      : {dispositivo.mac or '-'}")
        print(f"  Status             : {dispositivo.status}")
        print(f"  ARP ativo          : {dispositivo.arp_ativo}")
        print(f"  ICMP ativo         : {dispositivo.icmp_ativo}")
        print(f"  ICMP bloqueado     : {dispositivo.icmp_bloqueado}")
        print(f"  Conflito           : {dispositivo.conflito}")
        print(f"  Portas abertas     : {dispositivo.open_ports}")
        print(f"  Primeira vez visto : {dispositivo.primeira_vez_visto or '-'}")
        print(f"  Ultima vez visto   : {dispositivo.ultima_vez_visto or '-'}")


def exibir_persistencia(resultado: ResultadoDescoberta) -> None:
    inventario_em_memoria = {
        dispositivo.ip: dispositivo.to_dict()
        for dispositivo in resultado.dispositivos
    }
    inventario_salvo = carregar_inventario()

    print("\n== Persistencia ==")
    print(f"  Arquivo   : {CAMINHO_INVENTARIO}")
    print(f"  Registros : {len(inventario_salvo)}")
    print(
        "  Round-trip: "
        f"{'OK' if inventario_salvo == inventario_em_memoria else 'FALHOU'}"
    )


def main() -> int:
    args = criar_parser().parse_args()

    print("Use este script apenas em redes que voce tem autorizacao para testar.")

    quantidade_portas = None if args.sem_portas else args.quantidade_portas

    try:
        resultado = descobrir_dispositivos(
            interface=args.interface,
            rede=args.rede,
            quantidade_portas=quantidade_portas,
            tempo_limite_porta=args.tempo_limite_porta,
            tarefas_concorrentes_icmp=args.tarefas_icmp,
            tempo_limite_arp=args.tempo_limite_arp,
            tentativas_arp=args.tentativas_arp,
            intervalo_arp=args.intervalo_arp,
            salvar=not args.sem_salvar,
        )
    except Exception as erro:
        print(f"\nERRO no discovery: {type(erro).__name__}: {erro}")
        traceback.print_exc()
        return 1

    exibir_rede(resultado.dados_rede)
    exibir_resumo(resultado)
    exibir_dispositivos(resultado)

    if not args.sem_salvar:
        exibir_persistencia(resultado)

    print("\nValidacao concluida.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
