from __future__ import annotations

import pytest
from scapy.all import ARP, Ether

from src.scanner import arp as arp_module
from src.scanner.arp import (
    encontrar_conflitos,
    encontrar_macs_duplicados,
    filtrar_bloqueados_icmp,
    varrer_rede_arp,
)


def _montar_requisicao_arp(endereco_ip: str):
    return Ether() / ARP(pdst=endereco_ip)


def _montar_resposta_arp(endereco_ip: str, endereco_mac: str):
    return Ether() / ARP(op=2, psrc=endereco_ip, hwsrc=endereco_mac)


def _obter_mac_falso(_interface):
    return "10:20:30:40:50:60"


def _obter_ip_falso(_interface):
    return "192.168.0.50"


def test_agrupa_multiplos_macs_para_o_mesmo_ip():
    pacotes_respondidos = [
        (
            _montar_requisicao_arp("192.168.0.10"),
            _montar_resposta_arp("192.168.0.10", "AA:BB:CC:DD:EE:01"),
        ),
        (
            _montar_requisicao_arp("192.168.0.10"),
            _montar_resposta_arp("192.168.0.10", "AA:BB:CC:DD:EE:02"),
        ),
        (
            _montar_requisicao_arp("192.168.0.11"),
            _montar_resposta_arp("192.168.0.11", "AA:BB:CC:DD:EE:03"),
        ),
    ]

    resultado = arp_module._agrupar_respostas_por_ip(pacotes_respondidos)

    assert resultado == {
        "192.168.0.10": {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"},
        "192.168.0.11": {"aa:bb:cc:dd:ee:03"},
    }


def test_ignora_pacotes_que_nao_sao_respostas():
    requisicao_arp = Ether() / ARP(
        op=1,
        psrc="192.168.0.10",
        hwsrc="aa:bb:cc:dd:ee:01",
    )

    resultado = arp_module._agrupar_respostas_por_ip(
        [(_montar_requisicao_arp("192.168.0.10"), requisicao_arp)]
    )

    assert resultado == {}


def test_resolve_ips_alvo_a_partir_da_rede():
    ips_alvo, interface = arp_module._resolver_ips_alvo(
        None,
        "192.168.0.0/30",
        "fake0",
    )

    assert ips_alvo == ["192.168.0.1", "192.168.0.2"]
    assert interface == "fake0"


def test_filtra_apenas_ips_sem_resposta_icmp():
    resultados_arp = {
        "192.168.0.1": ["aa:bb:cc:dd:ee:01"],
        "192.168.0.10": ["aa:bb:cc:dd:ee:02"],
        "192.168.0.11": ["aa:bb:cc:dd:ee:03"],
    }

    resultado = filtrar_bloqueados_icmp(
        resultados_arp,
        {"192.168.0.1", "192.168.0.11"},
    )

    assert resultado == {"192.168.0.10": ["aa:bb:cc:dd:ee:02"]}


def test_encontra_apenas_ips_com_multiplos_macs():
    resultados_arp = {
        "192.168.0.1": ["aa:bb:cc:dd:ee:01"],
        "192.168.0.10": ["aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"],
    }

    assert encontrar_conflitos(resultados_arp) == {
        "192.168.0.10": ["aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"],
    }


def test_encontra_macs_com_multiplos_ips():
    resultados_arp = {
        "192.168.0.1": ["aa:bb:cc:dd:ee:01"],
        "192.168.0.10": ["aa:bb:cc:dd:ee:01"],
    }

    assert encontrar_macs_duplicados(resultados_arp) == {
        "aa:bb:cc:dd:ee:01": ["192.168.0.1", "192.168.0.10"],
    }


def test_varredura_arp_agrupa_respostas_e_passa_opcoes_do_scapy(monkeypatch):
    chamada_srp = {}

    def srp_falso(requisicoes_arp, **opcoes):
        chamada_srp["requisicoes_arp"] = requisicoes_arp
        chamada_srp["opcoes"] = opcoes
        return [
            (
                requisicoes_arp[0],
                _montar_resposta_arp("192.168.0.10", "AA:BB:CC:DD:EE:01"),
            ),
            (
                requisicoes_arp[0],
                _montar_resposta_arp("192.168.0.10", "AA:BB:CC:DD:EE:02"),
            ),
        ], []

    monkeypatch.setattr(
        arp_module,
        "get_if_hwaddr",
        _obter_mac_falso,
    )
    monkeypatch.setattr(
        arp_module,
        "get_if_addr",
        _obter_ip_falso,
    )
    monkeypatch.setattr(arp_module, "srp", srp_falso)

    resultado = varrer_rede_arp(alvos=["192.168.0.10"], interface="fake0")

    assert resultado == {
        "192.168.0.10": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
    }
    assert chamada_srp["opcoes"]["multi"] is True
    assert chamada_srp["opcoes"]["iface"] == "fake0"
    assert chamada_srp["opcoes"]["timeout"] == 1.0
    assert chamada_srp["opcoes"]["retry"] == 2


def test_varredura_arp_rejeita_tempo_limite_invalido():
    with pytest.raises(ValueError, match="tempo_limite"):
        varrer_rede_arp(alvos=["192.168.0.10"], tempo_limite=0)
