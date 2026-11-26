"""Modelo e persistencia dos dispositivos encontrados na rede local."""

from __future__ import annotations

import json
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Iterable, Mapping


CAMINHO_INVENTARIO = Path(__file__).resolve().parents[2] / "dados" / "inventario.json"
STATUS_VALIDOS = {"online", "offline", "unknown"}


class InventarioCorrompidoError(ValueError):
    """Indica que o arquivo de inventario existe, mas nao pode ser lido."""


class Device:
    """Representa um dispositivo encontrado na rede."""

    def __init__(
        self,
        ip: str,
        macs: Iterable[str] | None = None,
        status: str = "unknown",
        arp_ativo: bool = False,
        icmp_ativo: bool = False,
        open_ports: Iterable[int] | None = None,
        primeira_vez_visto: str | None = None,
        ultima_vez_visto: str | None = None,
    ) -> None:
        self.ip = ip

        if status not in STATUS_VALIDOS:
            raise ValueError(
                f"Status invalido: {status!r}. Use online, offline ou unknown."
            )

        self.macs = list(macs) if macs is not None else []
        self.status = status

        self.arp_ativo = bool(arp_ativo)
        self.icmp_ativo = bool(icmp_ativo)

        self.open_ports = list(open_ports) if open_ports is not None else []

        self.primeira_vez_visto = primeira_vez_visto
        self.ultima_vez_visto = ultima_vez_visto

    @property
    def mac(self) -> str | None:
        """Retorna o primeiro MAC conhecido."""
        return self.macs[0] if self.macs else None

    @property
    def icmp_bloqueado(self) -> bool:
        """Indica resposta ao ARP sem resposta ao ping."""
        return self.arp_ativo and not self.icmp_ativo

    @property
    def conflito(self) -> bool:
        """Indica mais de um MAC associado ao mesmo IP."""
        return len(set(self.macs)) > 1

    def to_dict(self) -> dict[str, Any]:
        """Converte o dispositivo para a estrutura do inventario JSON."""
        return {
            "macs": list(self.macs),
            "status": self.status,
            "arp_ativo": self.arp_ativo,
            "icmp_ativo": self.icmp_ativo,
            "open_ports": list(self.open_ports),
            "primeira_vez_visto": self.primeira_vez_visto,
            "ultima_vez_visto": self.ultima_vez_visto,
        }

    @classmethod
    def from_dict(cls, ip: str, dados: Mapping[str, Any]) -> "Device":
        """Cria um dispositivo a partir de uma entrada do inventario."""
        return cls(
            ip=ip,
            macs=dados.get("macs", []),
            status=dados.get("status", "unknown"),
            arp_ativo=dados.get("arp_ativo", False),
            icmp_ativo=dados.get("icmp_ativo", False),
            open_ports=dados.get("open_ports", []),
            primeira_vez_visto=dados.get("primeira_vez_visto"),
            ultima_vez_visto=dados.get("ultima_vez_visto"),
        )


def consolidar_dispositivos(
    resultados_arp: Mapping[str, Iterable[str]],
    hosts_icmp: Iterable[object],
    portas_por_ip: Mapping[str, Iterable[int]] | None = None,
) -> list[Device]:
    """Une resultados de ARP, ICMP e portas em um dispositivo por IP."""
    return _consolidar_dispositivos(
        resultados_arp,
        hosts_icmp,
        portas_por_ip,
        momento=_agora_iso(),
    )


def _validar_inventario(inventario: Mapping[str, Any]) -> None:
    """Valida o formato do inventario antes de usa-lo ou grava-lo."""

    if not isinstance(inventario, Mapping):
        raise ValueError("O inventario JSON deve conter um objeto na raiz.")

    for ip, dados in inventario.items():
        if not isinstance(ip, str):
            raise ValueError(f"A chave do inventario deve ser texto: {ip!r}.")

        try:
            IPv4Address(ip)
        except ValueError as erro:
            raise ValueError(f"Chave de IP invalida no inventario: {ip!r}.") from erro

        if not isinstance(dados, dict):
            raise ValueError(f"Os dados do dispositivo {ip} devem ser um objeto JSON.")

        macs = dados.get("macs", [])
        if not isinstance(macs, list) or not all(isinstance(mac, str) for mac in macs):
            raise ValueError(f"A lista 'macs' do dispositivo {ip} e invalida.")

        portas = dados.get("open_ports", [])
        if not isinstance(portas, list) or not all(
            isinstance(porta, int)
            and not isinstance(porta, bool)
            and 1 <= porta <= 65535
            for porta in portas
        ):
            raise ValueError(f"A lista 'open_ports' do dispositivo {ip} e invalida.")

        for campo in ("primeira_vez_visto", "ultima_vez_visto"):
            valor = dados.get(campo)
            if valor is not None and not isinstance(valor, str):
                raise ValueError(f"O campo {campo!r} do dispositivo {ip} e invalido.")

        Device.from_dict(ip, dados)


def _mover_inventario_corrompido(caminho: Path) -> Path | None:
    """Renomeia o arquivo invalido para nao perder o conteudo original."""

    sufixo = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    destino = caminho.with_name(f"{caminho.name}.corrupt-{sufixo}")

    try:
        caminho.replace(destino)
    except OSError:
        return None

    return destino


def carregar_inventario(caminho: str | Path = CAMINHO_INVENTARIO) -> dict[str, Any]:
    """Carrega e valida o inventario JSON."""
    caminho_arquivo = Path(caminho)

    if not caminho_arquivo.exists():
        return {}

    try:
        with caminho_arquivo.open("r", encoding="utf-8") as arquivo:
            inventario = json.load(arquivo)
    except (json.JSONDecodeError, UnicodeDecodeError) as erro:
        backup = _mover_inventario_corrompido(caminho_arquivo)
        detalhe = f" Backup: {backup}." if backup else ""
        raise InventarioCorrompidoError(f"O inventario JSON esta invalido: {erro}.{detalhe}") from erro

    try:
        _validar_inventario(inventario)
    except (TypeError, ValueError) as erro:
        backup = _mover_inventario_corrompido(caminho_arquivo)
        detalhe = f" Backup: {backup}." if backup else ""
        raise InventarioCorrompidoError(f"O inventario JSON possui dados invalidos: {erro}.{detalhe}") from erro

    return inventario


def salvar_inventario(inventario: Mapping[str, Any], caminho: str | Path = CAMINHO_INVENTARIO) -> None:
    """Salva o inventario em JSON de forma legivel."""

    _validar_inventario(inventario)
    caminho_arquivo = Path(caminho)
    caminho_arquivo.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=caminho_arquivo.parent) as pasta:
        temporario = Path(pasta) / caminho_arquivo.name
        with temporario.open("w", encoding="utf-8") as arquivo:
            json.dump(dict(inventario), arquivo, ensure_ascii=False, indent=2, sort_keys=True)
            arquivo.write("\n")
        temporario.replace(caminho_arquivo)


def atualizar_inventario(
    inventario_anterior: Mapping[str, Mapping[str, Any]],
    resultados_arp: Mapping[str, Iterable[str]],
    hosts_icmp: Iterable[object],
    portas_por_ip: Mapping[str, Iterable[int]] | None = None,
    *,
    marcar_offline: bool = True,
) -> dict[str, dict[str, Any]]:
    """Atualiza o historico sem remover dispositivos vistos anteriormente.

    Quando ``marcar_offline`` e falso, dispositivos nao encontrados passam para
    ``unknown`` em vez de ``offline``. Isso evita falsos negativos quando um dos
    scanners (ICMP ou ARP) falhou.
    """
    momento = _agora_iso()

    inventario_atualizado: dict[str, dict[str, Any]] = {
        ip: Device.from_dict(ip, dados).to_dict()
        for ip, dados in inventario_anterior.items()
    }

    encontrados = _consolidar_dispositivos(
        resultados_arp,
        hosts_icmp,
        portas_por_ip,
        momento=momento,
    )
    ips_encontrados = {dispositivo.ip for dispositivo in encontrados}

    for dispositivo in encontrados:
        dados_anteriores = inventario_atualizado.get(dispositivo.ip)

        if dados_anteriores is None:
            dispositivo.primeira_vez_visto = momento
        else:
            dispositivo.primeira_vez_visto = (
                dados_anteriores.get("primeira_vez_visto") or momento
            )
            if not dispositivo.macs:
                dispositivo.macs = list(dados_anteriores.get("macs", []))
            if portas_por_ip is None or dispositivo.ip not in portas_por_ip:
                dispositivo.open_ports = list(
                    dados_anteriores.get("open_ports", [])
                )

        dispositivo.ultima_vez_visto = momento
        inventario_atualizado[dispositivo.ip] = dispositivo.to_dict()

    for ip, dados in inventario_atualizado.items():
        if ip not in ips_encontrados:
            dados["status"] = "offline" if marcar_offline else "unknown"
            dados["arp_ativo"] = False
            dados["icmp_ativo"] = False

    return dict(
        sorted(inventario_atualizado.items(), key=lambda item: IPv4Address(item[0]))
    )


def _consolidar_dispositivos(
    resultados_arp: Mapping[str, Iterable[str]],
    hosts_icmp: Iterable[object],
    portas_por_ip: Mapping[str, Iterable[int]] | None,
    momento: str,
) -> list[Device]:
    ips_icmp = {
        getattr(host, "address")
        for host in hosts_icmp
        if getattr(host, "is_alive", False)
    }
    portas_por_ip = portas_por_ip if portas_por_ip is not None else {}
    ips_encontrados = set(resultados_arp) | ips_icmp
    return [
        Device(
            ip=ip,
            macs=resultados_arp.get(ip, []),
            status="online",
            arp_ativo=ip in resultados_arp,
            icmp_ativo=ip in ips_icmp,
            open_ports=portas_por_ip.get(ip, []),
            primeira_vez_visto=momento,
            ultima_vez_visto=momento,
        )
        for ip in sorted(ips_encontrados, key=IPv4Address)
    ]


def _agora_iso() -> str:
    """Gera uma data legivel pelo JSON, incluindo o fuso horario local."""
    return datetime.now().astimezone().isoformat(timespec="seconds")
