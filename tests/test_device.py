"""Testes unitarios do modelo e do inventario, sem acesso a rede real."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from src.models.device import (
    Device,
    atualizar_inventario,
    carregar_inventario,
    consolidar_dispositivos,
    salvar_inventario,
)


def host(ip: str, ativo: bool = True) -> SimpleNamespace:
    return SimpleNamespace(address=ip, is_alive=ativo)


class TestDevice(unittest.TestCase):
    def test_propriedades_calculadas(self):
        dispositivo = Device(
            "192.168.0.10",
            macs=["AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:02"],
            arp_ativo=True,
            icmp_ativo=False,
        )
        self.assertEqual(dispositivo.mac, "aa:bb:cc:dd:ee:01")
        self.assertTrue(dispositivo.icmp_bloqueado)
        self.assertTrue(dispositivo.conflito)

    def test_listas_nao_sao_compartilhadas_entre_instancias(self):
        primeiro = Device("192.168.0.1")
        segundo = Device("192.168.0.2")
        primeiro.macs.append("aa:bb:cc:dd:ee:ff")
        primeiro.open_ports.append(80)
        self.assertEqual(segundo.macs, [])
        self.assertEqual(segundo.open_ports, [])


class TestConsolidacao(unittest.TestCase):
    def test_consolida_arp_icmp_e_portas_sem_duplicar_ip(self):
        dispositivos = consolidar_dispositivos(
            {"192.168.0.10": ["AA:BB:CC:DD:EE:FF"]},
            [host("192.168.0.10")],
            {"192.168.0.10": [443, 80, 80]},
        )
        self.assertEqual(len(dispositivos), 1)
        self.assertEqual(dispositivos[0].macs, ["aa:bb:cc:dd:ee:ff"])
        self.assertTrue(dispositivos[0].arp_ativo)
        self.assertTrue(dispositivos[0].icmp_ativo)
        self.assertEqual(dispositivos[0].open_ports, [80, 443])

    def test_arp_sem_icmp_indica_icmp_bloqueado(self):
        dispositivo = consolidar_dispositivos(
            {"192.168.0.10": ["aa:bb:cc:dd:ee:ff"]}, []
        )[0]
        self.assertEqual(dispositivo.status, "online")
        self.assertTrue(dispositivo.icmp_bloqueado)

    def test_icmp_sem_arp_cria_dispositivo_sem_mac(self):
        dispositivo = consolidar_dispositivos({}, [host("192.168.0.10")])[0]
        self.assertEqual(dispositivo.macs, [])
        self.assertFalse(dispositivo.arp_ativo)
        self.assertTrue(dispositivo.icmp_ativo)

    def test_ignora_host_icmp_inativo(self):
        self.assertEqual(
            consolidar_dispositivos({}, [host("192.168.0.10", False)]), []
        )

    def test_ordena_ips_numericamente(self):
        dispositivos = consolidar_dispositivos(
            {
                "192.168.0.100": [],
                "192.168.0.2": [],
                "192.168.0.20": [],
            },
            [],
        )
        self.assertEqual(
            [dispositivo.ip for dispositivo in dispositivos],
            ["192.168.0.2", "192.168.0.20", "192.168.0.100"],
        )


class TestInventario(unittest.TestCase):
    DADOS_ANTERIORES = {
        "macs": ["aa:bb:cc:dd:ee:ff"],
        "status": "online",
        "arp_ativo": True,
        "icmp_ativo": True,
        "open_ports": [80],
        "primeira_vez_visto": "2026-01-01T10:00:00-03:00",
        "ultima_vez_visto": "2026-01-01T11:00:00-03:00",
    }

    def test_adiciona_dispositivo_novo(self):
        inventario = atualizar_inventario(
            {}, {"192.168.0.10": ["aa:bb:cc:dd:ee:ff"]}, []
        )
        dados = inventario["192.168.0.10"]
        self.assertEqual(dados["status"], "online")
        self.assertIsNotNone(dados["primeira_vez_visto"])
        self.assertEqual(dados["primeira_vez_visto"], dados["ultima_vez_visto"])

    def test_marca_dispositivo_conhecido_como_offline(self):
        anterior = {"192.168.0.10": dict(self.DADOS_ANTERIORES)}
        inventario = atualizar_inventario(anterior, {}, [])
        dados = inventario["192.168.0.10"]
        self.assertEqual(dados["status"], "offline")
        self.assertFalse(dados["arp_ativo"])
        self.assertFalse(dados["icmp_ativo"])
        self.assertEqual(
            dados["ultima_vez_visto"], "2026-01-01T11:00:00-03:00"
        )

    def test_preserva_historico_mac_e_portas_quando_so_icmp_responde(self):
        anterior = {"192.168.0.10": dict(self.DADOS_ANTERIORES)}
        inventario = atualizar_inventario(
            anterior, {}, [host("192.168.0.10")]
        )
        dados = inventario["192.168.0.10"]
        self.assertEqual(dados["macs"], ["aa:bb:cc:dd:ee:ff"])
        self.assertEqual(dados["open_ports"], [80])
        self.assertEqual(
            dados["primeira_vez_visto"], "2026-01-01T10:00:00-03:00"
        )
        self.assertNotEqual(
            dados["ultima_vez_visto"], "2026-01-01T11:00:00-03:00"
        )

    def test_carrega_arquivo_inexistente(self):
        with tempfile.TemporaryDirectory() as diretorio:
            caminho = Path(diretorio) / "nao-existe.json"
            self.assertEqual(carregar_inventario(caminho), {})

    def test_salva_e_carrega_json(self):
        inventario = {
            "192.168.0.10": Device(
                "192.168.0.10",
                macs=["aa:bb:cc:dd:ee:ff"],
                status="online",
                arp_ativo=True,
                open_ports=[80, 443],
            ).to_dict()
        }
        with tempfile.TemporaryDirectory() as diretorio:
            caminho = Path(diretorio) / "inventario.json"
            salvar_inventario(inventario, caminho)
            self.assertEqual(carregar_inventario(caminho), inventario)


if __name__ == "__main__":
    unittest.main()
