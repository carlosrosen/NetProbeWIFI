"""Testes da integracao de descoberta, sem acesso a rede real."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from src.models.device import Device
from src.network.discovery import ResultadoDescoberta, descobrir_dispositivos
from src.network.interfaces import DadosRede


DADOS_REDE = DadosRede(
    interface="Ethernet",
    ip_local="192.168.0.73",
    rede="192.168.0.0/24",
    mascara="255.255.255.0",
)


def host(ip: str, ativo: bool = True) -> SimpleNamespace:
    return SimpleNamespace(address=ip, is_alive=ativo)


def inventario(*ips: str) -> dict:
    return {
        ip: {
            "macs": ["aa:bb:cc:dd:ee:ff"],
            "status": "online",
            "arp_ativo": True,
            "icmp_ativo": True,
            "open_ports": [443],
            "primeira_vez_visto": "2026-01-01T10:00:00-03:00",
            "ultima_vez_visto": "2026-01-01T11:00:00-03:00",
        }
        for ip in ips
    }


class TestDescoberta(unittest.TestCase):
    def test_prepara_dispositivos_online_e_offline(self):
        with (
            patch(
                "src.network.discovery.obter_dados_rede",
                return_value=DADOS_REDE,
            ),
            patch(
                "src.network.discovery.varrer_rede_icmp",
                return_value=[host("192.168.0.73")],
            ) as icmp,
            patch(
                "src.network.discovery.varrer_rede_arp",
                return_value={"192.168.0.1": ["84:01:12:bd:16:2f"]},
            ) as arp,
            patch(
                "src.network.discovery.scan_ports",
                return_value=(1, [80]),
            ) as scan,
            patch(
                "src.network.discovery.carregar_inventario",
                return_value=inventario("192.168.0.99"),
            ),
            patch(
                "src.network.discovery.salvar_inventario",
            ) as salvar,
        ):
            resultado = descobrir_dispositivos(quantidade_portas=100)

        self.assertIsInstance(resultado, ResultadoDescoberta)
        self.assertEqual(resultado.dados_rede, DADOS_REDE)
        self.assertEqual(
            [dispositivo.ip for dispositivo in resultado.dispositivos],
            ["192.168.0.1", "192.168.0.73", "192.168.0.99"],
        )

        encontrado_arp = resultado.dispositivos[0]
        self.assertTrue(encontrado_arp.arp_ativo)
        self.assertFalse(encontrado_arp.icmp_ativo)
        self.assertTrue(encontrado_arp.icmp_bloqueado)
        self.assertEqual(encontrado_arp.open_ports, [80])

        encontrado_icmp = resultado.dispositivos[1]
        self.assertFalse(encontrado_icmp.arp_ativo)
        self.assertTrue(encontrado_icmp.icmp_ativo)
        self.assertEqual(encontrado_icmp.open_ports, [80])

        offline = resultado.dispositivos[2]
        self.assertEqual(offline.status, "offline")
        self.assertEqual(offline.macs, ["aa:bb:cc:dd:ee:ff"])
        self.assertEqual(offline.open_ports, [443])

        self.assertEqual(len(resultado.online), 2)
        self.assertEqual(len(resultado.offline), 1)
        icmp.assert_called_once_with(
            rede=DADOS_REDE.rede,
            interface=DADOS_REDE.interface,
            tempo_limite=2.0,
            quantidade_pings=2,
            tarefas_concorrentes=50,
        )
        arp.assert_called_once_with(
            rede=DADOS_REDE.rede,
            interface=DADOS_REDE.interface,
            tempo_limite=3.0,
            tentativas=3,
            intervalo=0.01,
        )
        self.assertEqual(scan.call_count, 2)
        scan.assert_any_call("192.168.0.1", 1, 100, timeout=0.5)
        salvar.assert_called_once()

    def test_sem_portas_nao_executa_varredura_de_portas(self):
        with (
            patch(
                "src.network.discovery.obter_dados_rede",
                return_value=DADOS_REDE,
            ),
            patch(
                "src.network.discovery.varrer_rede_icmp",
                return_value=set(),
            ),
            patch(
                "src.network.discovery.varrer_rede_arp",
                return_value={"192.168.0.1": ["aa:bb:cc:dd:ee:ff"]},
            ),
            patch("src.network.discovery.scan_ports") as scan,
            patch(
                "src.network.discovery.carregar_inventario",
                return_value=inventario("192.168.0.1"),
            ),
            patch(
                "src.network.discovery.salvar_inventario",
            ) as salvar,
        ):
            resultado = descobrir_dispositivos(
                quantidade_portas=None,
                salvar=False,
            )

        scan.assert_not_called()
        salvar.assert_not_called()

        dispositivo = resultado.dispositivos[0]
        self.assertEqual(dispositivo.ip, "192.168.0.1")
        self.assertEqual(dispositivo.open_ports, [443])
        self.assertTrue(dispositivo.arp_ativo)
        self.assertFalse(dispositivo.icmp_ativo)

    def test_falha_nas_portas_preserva_portas_anteriores(self):
        with (
            patch(
                "src.network.discovery.obter_dados_rede",
                return_value=DADOS_REDE,
            ),
            patch(
                "src.network.discovery.varrer_rede_icmp",
                return_value=set(),
            ),
            patch(
                "src.network.discovery.varrer_rede_arp",
                return_value={"192.168.0.1": ["aa:bb:cc:dd:ee:ff"]},
            ),
            patch(
                "src.network.discovery.scan_ports",
                return_value=(-1, []),
            ),
            patch(
                "src.network.discovery.carregar_inventario",
                return_value=inventario("192.168.0.1"),
            ),
            patch(
                "src.network.discovery.salvar_inventario",
            ),
        ):
            resultado = descobrir_dispositivos(quantidade_portas=100)

        self.assertEqual(resultado.dispositivos[0].open_ports, [443])

    def test_quantidade_padrao_varre_de_1_a_100(self):
        with (
            patch(
                "src.network.discovery.obter_dados_rede",
                return_value=DADOS_REDE,
            ),
            patch(
                "src.network.discovery.varrer_rede_icmp",
                return_value=[],
            ),
            patch(
                "src.network.discovery.varrer_rede_arp",
                return_value={"192.168.0.1": ["aa:bb:cc:dd:ee:ff"]},
            ),
            patch(
                "src.network.discovery.scan_ports",
                return_value=(0, []),
            ) as scan,
            patch(
                "src.network.discovery.carregar_inventario",
                return_value={},
            ),
            patch(
                "src.network.discovery.salvar_inventario",
            ),
        ):
            descobrir_dispositivos()

        scan.assert_called_once_with(
            "192.168.0.1",
            1,
            100,
            timeout=0.5,
        )

    def test_quantidade_de_portas_personalizada(self):
        with (
            patch(
                "src.network.discovery.obter_dados_rede",
                return_value=DADOS_REDE,
            ),
            patch(
                "src.network.discovery.varrer_rede_icmp",
                return_value=[],
            ),
            patch(
                "src.network.discovery.varrer_rede_arp",
                return_value={"192.168.0.1": ["aa:bb:cc:dd:ee:ff"]},
            ),
            patch(
                "src.network.discovery.scan_ports",
                return_value=(0, []),
            ) as scan,
            patch(
                "src.network.discovery.carregar_inventario",
                return_value={},
            ),
            patch(
                "src.network.discovery.salvar_inventario",
            ),
        ):
            descobrir_dispositivos(quantidade_portas=50)

        scan.assert_called_once_with(
            "192.168.0.1",
            1,
            50,
            timeout=0.5,
        )

    def test_quantidade_de_portas_invalida(self):
        with self.assertRaises(ValueError):
            descobrir_dispositivos(quantidade_portas=0)

        with self.assertRaises(ValueError):
            descobrir_dispositivos(quantidade_portas=65536)

        with self.assertRaises(TypeError):
            descobrir_dispositivos(quantidade_portas="100")

        with self.assertRaises(TypeError):
            descobrir_dispositivos(quantidade_portas=True)


if __name__ == "__main__":
    unittest.main()
