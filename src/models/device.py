"""Modelo e persistencia dos dispositivos encontrados na rede local."""

from __future__ import annotations

import json
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Iterable, Mapping


CAMINHO_INVENTARIO = Path(__file__).resolve().parents[2] / "dados" / "inventario.json"
STATUS_VALIDOS = {"online", "offline", "unknown"}


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


def carregar_inventario(caminho: str | Path = CAMINHO_INVENTARIO) -> dict[str, Any]:
    """Carrega o inventario JSON; retorna vazio se ele nao existir."""
    caminho_arquivo = Path(caminho)

    if not caminho_arquivo.exists():
        return {}

    with caminho_arquivo.open("r", encoding="utf-8") as arquivo:
        inventario = json.load(arquivo)

    if not isinstance(inventario, dict):
        raise ValueError("O inventario JSON deve conter um objeto na raiz.")
    return inventario


def salvar_inventario(
    inventario: Mapping[str, Any],
    caminho: str | Path = CAMINHO_INVENTARIO,
) -> None:
    """Salva o inventario em JSON de forma legivel."""
    caminho_arquivo = Path(caminho)
    caminho_arquivo.parent.mkdir(parents=True, exist_ok=True)
    with caminho_arquivo.open("w", encoding="utf-8") as arquivo:
        json.dump(
            dict(inventario),
            arquivo,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        arquivo.write("\n")


def atualizar_inventario(
    inventario_anterior: Mapping[str, Mapping[str, Any]],
    resultados_arp: Mapping[str, Iterable[str]],
    hosts_icmp: Iterable[object],
    portas_por_ip: Mapping[str, Iterable[int]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Atualiza o historico sem remover dispositivos vistos anteriormente."""
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
            dados["status"] = "offline"
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
