"""Modelo e persistencia dos dispositivos encontrados na rede local."""

from __future__ import annotations

import json
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Iterable, Mapping


STATUS_VALIDOS = {"online", "offline", "unknown"}


# ---------------------------------------------------------------------------
# 1. Representacao de um dispositivo
# ---------------------------------------------------------------------------
class Device:
    """Representa a ficha de um aparelho encontrado na rede.

    A classe nao procura aparelhos. Ela apenas recebe e organiza informacoes
    que vieram dos scanners de ARP, ICMP e portas.
    """

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
        # Normalizamos o IP para que valores equivalentes tenham sempre o
        # mesmo formato e para rejeitar enderecos IPv4 invalidos.
        self.ip = _normalizar_ip(ip)

        # Somente estes tres estados podem ser gravados no inventario.
        if status not in STATUS_VALIDOS:
            raise ValueError(
                f"Status invalido: {status!r}. Use online, offline ou unknown."
            )

        # "macs or []" cria uma lista vazia quando nenhum MAC foi encontrado.
        # A funcao auxiliar tambem remove repeticoes e converte para minusculas.
        self.macs = _normalizar_macs(macs or [])
        self.status = status

        # Estes indicadores representam apenas a varredura atual.
        self.arp_ativo = bool(arp_ativo)
        self.icmp_ativo = bool(icmp_ativo)

        # As portas sao validadas, ficam sem repeticoes e em ordem crescente.
        self.open_ports = _normalizar_portas(open_ports or [])

        # As datas sao strings no formato ISO para poderem ser salvas em JSON.
        self.primeira_vez_visto = primeira_vez_visto
        self.ultima_vez_visto = ultima_vez_visto

    @property
    def mac(self) -> str | None:
        """Retorna o primeiro MAC conhecido."""
        # O projeto mantem varios MACs para detectar conflitos, mas a interface
        # pode usar esta propriedade quando precisar mostrar somente um.
        return self.macs[0] if self.macs else None

    @property
    def icmp_bloqueado(self) -> bool:
        """Indica resposta ao ARP sem resposta ao ping."""
        # Se respondeu ao ARP, sabemos que esta na rede. Se nao respondeu ao
        # ICMP, provavelmente o aparelho ou firewall esta bloqueando o ping.
        return self.arp_ativo and not self.icmp_ativo

    @property
    def conflito(self) -> bool:
        """Indica mais de um MAC associado ao mesmo IP."""
        # Dois MACs diferentes usando o mesmo IP podem indicar colisao de IP.
        return len(set(self.macs)) > 1

    def to_dict(self) -> dict[str, Any]:
        """Converte o dispositivo para a estrutura do inventario JSON."""
        # O IP nao aparece aqui porque ele sera a chave principal do JSON:
        # {"192.168.0.10": {dados do dispositivo}}.
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
        # E o caminho inverso de to_dict: transforma dados antigos do JSON em
        # um objeto Device. get(..., padrao) aceita inventarios mais antigos
        # que ainda nao possuam todos os campos.
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


# ---------------------------------------------------------------------------
# 2. Uniao dos resultados produzidos pelos scanners
# ---------------------------------------------------------------------------
def consolidar_dispositivos(
    resultados_arp: Mapping[str, Iterable[str]],
    hosts_icmp: Iterable[object],
    portas_por_ip: Mapping[str, Iterable[int]] | None = None,
) -> list[Device]:
    """Une resultados de ARP, ICMP e portas em um dispositivo por IP."""
    # A implementacao real fica na funcao interna para podermos fornecer o
    # mesmo horario a todos os aparelhos processados numa atualizacao.
    return _consolidar_dispositivos(
        resultados_arp,
        hosts_icmp,
        portas_por_ip,
        momento=_agora_iso(),
    )


# ---------------------------------------------------------------------------
# 3. Leitura e gravacao do arquivo inventario.json
# ---------------------------------------------------------------------------
def carregar_inventario(caminho: str | Path = "inventario.json") -> dict[str, Any]:
    """Carrega o inventario JSON; retorna vazio se ele nao existir."""
    caminho_arquivo = Path(caminho)

    # Na primeira execucao ainda nao existe inventario, portanto {} e um
    # resultado normal e nao um erro.
    if not caminho_arquivo.exists():
        return {}

    with caminho_arquivo.open("r", encoding="utf-8") as arquivo:
        inventario = json.load(arquivo)

    # A raiz precisa ser um dicionario porque cada IP sera uma chave.
    if not isinstance(inventario, dict):
        raise ValueError("O inventario JSON deve conter um objeto na raiz.")
    return inventario


def salvar_inventario(
    inventario: Mapping[str, Any],
    caminho: str | Path = "inventario.json",
) -> None:
    """Salva o inventario em JSON de forma legivel."""
    with Path(caminho).open("w", encoding="utf-8") as arquivo:
        # indent deixa o arquivo legivel para uma pessoa. ensure_ascii=False
        # permite caracteres acentuados sem codigos de escape.
        json.dump(
            dict(inventario),
            arquivo,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        arquivo.write("\n")


# ---------------------------------------------------------------------------
# 4. Comparacao da varredura atual com o inventario anterior
# ---------------------------------------------------------------------------
def atualizar_inventario(
    inventario_anterior: Mapping[str, Mapping[str, Any]],
    resultados_arp: Mapping[str, Iterable[str]],
    hosts_icmp: Iterable[object],
    portas_por_ip: Mapping[str, Iterable[int]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Atualiza o historico sem remover dispositivos vistos anteriormente."""
    # Um unico horario e usado em toda a operacao para manter o inventario
    # consistente, mesmo que existam muitos dispositivos.
    momento = _agora_iso()

    # Criamos uma nova estrutura em vez de modificar diretamente o dicionario
    # que foi entregue por quem chamou a funcao.
    inventario_atualizado: dict[str, dict[str, Any]] = {
        _normalizar_ip(ip): Device.from_dict(ip, dados).to_dict()
        for ip, dados in inventario_anterior.items()
    }

    # Transforma os resultados brutos da varredura em objetos Device.
    encontrados = _consolidar_dispositivos(
        resultados_arp,
        hosts_icmp,
        portas_por_ip,
        momento=momento,
    )
    ips_encontrados = {dispositivo.ip for dispositivo in encontrados}

    for dispositivo in encontrados:
        dados_anteriores = inventario_atualizado.get(dispositivo.ip)

        # Se nao existe registro anterior, estamos vendo o aparelho pela
        # primeira vez.
        if dados_anteriores is None:
            dispositivo.primeira_vez_visto = momento
        else:
            # Se ja era conhecido, a primeira data nunca deve ser perdida.
            dispositivo.primeira_vez_visto = (
                dados_anteriores.get("primeira_vez_visto") or momento
            )
            # Uma resposta somente por ICMP nao fornece um MAC novo.
            if not dispositivo.macs:
                dispositivo.macs = list(dados_anteriores.get("macs", []))
            # Ausencia de uma varredura de portas nao significa portas fechadas.
            if portas_por_ip is None or dispositivo.ip not in portas_por_ip:
                dispositivo.open_ports = list(
                    dados_anteriores.get("open_ports", [])
                )

        # Qualquer resposta ARP ou ICMP prova que o aparelho foi visto agora.
        dispositivo.ultima_vez_visto = momento
        inventario_atualizado[dispositivo.ip] = dispositivo.to_dict()

    # O aparelho antigo que nao apareceu nem no ARP nem no ICMP continua no
    # historico, mas passa a ser marcado como offline. A data de ultima vez
    # visto permanece inalterada.
    for ip, dados in inventario_atualizado.items():
        if ip not in ips_encontrados:
            dados["status"] = "offline"
            dados["arp_ativo"] = False
            dados["icmp_ativo"] = False

    # Devolve o inventario em ordem numerica de IP para facilitar a exibicao.
    return dict(
        sorted(inventario_atualizado.items(), key=lambda item: IPv4Address(item[0]))
    )


# ---------------------------------------------------------------------------
# 5. Funcoes internas de apoio
# ---------------------------------------------------------------------------
def _consolidar_dispositivos(
    resultados_arp: Mapping[str, Iterable[str]],
    hosts_icmp: Iterable[object],
    portas_por_ip: Mapping[str, Iterable[int]] | None,
    momento: str,
) -> list[Device]:
    # Primeiro padronizamos os dados. Isso evita que diferencas de letras
    # maiusculas ou de formato criem registros duplicados.
    arp_normalizado = {
        _normalizar_ip(ip): _normalizar_macs(macs)
        for ip, macs in resultados_arp.items()
    }
    # Do Host retornado pelo icmplib usamos somente address e is_alive,
    # conforme o contrato definido para este projeto.
    ips_icmp = {
        _normalizar_ip(getattr(host, "address"))
        for host in hosts_icmp
        if bool(getattr(host, "is_alive", False))
    }
    portas_normalizadas = {
        _normalizar_ip(ip): _normalizar_portas(portas)
        for ip, portas in (portas_por_ip or {}).items()
    }

    # A uniao de conjuntos garante um unico Device por IP, mesmo quando o
    # aparelho apareceu simultaneamente no ARP e no ICMP.
    ips_encontrados = set(arp_normalizado) | ips_icmp
    return [
        Device(
            ip=ip,
            macs=arp_normalizado.get(ip, []),
            status="online",
            arp_ativo=ip in arp_normalizado,
            icmp_ativo=ip in ips_icmp,
            open_ports=portas_normalizadas.get(ip, []),
            primeira_vez_visto=momento,
            ultima_vez_visto=momento,
        )
        for ip in sorted(ips_encontrados, key=IPv4Address)
    ]


def _normalizar_ip(ip: object) -> str:
    """Valida um IPv4 e devolve sua representacao padronizada."""
    if not isinstance(ip, str):
        raise TypeError("O endereco IP deve ser uma string.")
    return str(IPv4Address(ip.strip()))


def _normalizar_macs(macs: Iterable[str]) -> list[str]:
    """Limpa MACs, remove repeticoes e preserva a ordem encontrada."""
    resultado: list[str] = []
    vistos: set[str] = set()
    for mac in macs:
        if not isinstance(mac, str):
            raise TypeError("Cada endereco MAC deve ser uma string.")
        normalizado = mac.strip().lower()
        if normalizado and normalizado not in vistos:
            resultado.append(normalizado)
            vistos.add(normalizado)
    return resultado


def _normalizar_portas(portas: Iterable[int]) -> list[int]:
    """Valida as portas e devolve valores unicos em ordem crescente."""
    resultado: set[int] = set()
    for porta in portas:
        if not isinstance(porta, int) or isinstance(porta, bool):
            raise TypeError("Cada porta deve ser um numero inteiro.")
        if not 1 <= porta <= 65535:
            raise ValueError("Cada porta deve estar entre 1 e 65535.")
        resultado.add(porta)
    return sorted(resultado)


def _agora_iso() -> str:
    """Gera uma data legivel pelo JSON, incluindo o fuso horario local."""
    return datetime.now().astimezone().isoformat(timespec="seconds")
