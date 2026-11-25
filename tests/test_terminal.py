"""Integração do menu com a descoberta e o inventário, sem tráfego de rede."""

from io import StringIO
from ipaddress import IPv4Network
from socket import gaierror
from types import SimpleNamespace
from unittest.mock import Mock

from rich.console import Console

from src.interface import terminal
from src.models.device import Device, carregar_inventario, salvar_inventario
from src.network import discovery
from src.network.interfaces import DadosRede
from src.scanner import ports


def test_menu_valida_intervalos_e_portas_excluidas(monkeypatch):
    linhas = [
        "2", "1,5", "0", "3", "-1", "0", "14",  # ICMP
        "3", "s", "8000", "8010", "0,4", "7", "7999", "8005, 8003, 8005",  # TCP
        "4", "2,1", "0", "0,02",  # ARP
        "0",
    ]
    entrada = StringIO("\n".join(linhas) + "\n")
    saida = StringIO()
    monkeypatch.setattr("sys.stdin", entrada)

    opcoes = terminal._personalizar(Console(file=saida, width=100), terminal.Opcoes())

    assert (opcoes.timeout_icmp, opcoes.quantidade_pings, opcoes.intervalo_icmp, opcoes.concorrencia_icmp) == (1.5, 3, 0, 14)
    assert (opcoes.portas, opcoes.timeout_tcp, opcoes.concorrencia_tcp) == ((8000, 8010), 0.4, 7)
    assert opcoes.portas_excluidas == (8003, 8005)
    assert (opcoes.timeout_arp, opcoes.tentativas_arp, opcoes.intervalo_arp) == (2.1, 0, 0.02)
    assert "entre 8000 e 8010" in saida.getvalue()


def test_varredura_respeita_exclusoes_e_preserva_historico(monkeypatch, tmp_path):
    caminho = tmp_path / "inventario.json"
    ip, fora = "192.168.100.253", "192.168.100.10"
    anterior = "2026-01-01T10:00:00-03:00"
    instante_da_varredura = "2026-11-25T09:03:04-03:00"
    registro_ip = Device(ip, status="online", primeira_vez_visto=anterior).to_dict()
    registro_fora = Device(fora, status="online", icmp_ativo=True, open_ports=[443]).to_dict()
    salvar_inventario({ip: registro_ip, fora: registro_fora}, caminho)
    monkeypatch.setattr(discovery, "carregar_inventario", lambda: carregar_inventario(caminho))
    monkeypatch.setattr(discovery, "salvar_inventario", lambda inventario: salvar_inventario(inventario, caminho))
    monkeypatch.setattr("src.models.device._agora_iso", lambda: instante_da_varredura)

    dados = DadosRede("Wi-Fi", "192.168.100.254", "192.168.100.0/24")
    obter_rede = Mock(return_value=dados)
    monkeypatch.setattr(discovery, "obter_dados_rede", obter_rede)
    icmp = Mock(return_value=[SimpleNamespace(address=dados.ip_local, is_alive=True)])
    arp = Mock(return_value={ip: ["00:11:22:33:44:55", "00:11:22:33:44:66"]})
    monkeypatch.setattr(discovery, "varrer_rede_icmp", icmp)
    monkeypatch.setattr(discovery, "varrer_rede_arp", arp)
    conectar = Mock(side_effect=lambda endereco, porta, _: porta if endereco == ip else None)
    monkeypatch.setattr(ports, "_verificar_porta", conectar)
    obter_tcp = Mock(wraps=ports.scan_ports)
    monkeypatch.setattr(discovery, "scan_ports", obter_tcp)

    opcoes = terminal.Opcoes(
        rede=IPv4Network("192.168.100.128/25"), timeout_icmp=1.5, quantidade_pings=3,
        intervalo_icmp=0.2, concorrencia_icmp=14, timeout_arp=2.1, tentativas_arp=1,
        intervalo_arp=0.02, portas=(8000, 8002), portas_excluidas=(8001,),
        timeout_tcp=0.4, concorrencia_tcp=7,
    )
    saida = StringIO()
    console = Console(file=saida, width=110)
    terminal._varrer(console, opcoes)

    obter_rede.assert_called_once_with(None)
    icmp.assert_called_once_with(
        rede="192.168.100.128/25", interface="Wi-Fi", tempo_limite=1.5,
        quantidade_pings=3, intervalo=0.2, tarefas_concorrentes=14,
    )
    arp.assert_called_once_with(
        rede="192.168.100.128/25", interface="Wi-Fi", tempo_limite=2.1, tentativas=1, intervalo=0.02,
    )
    obter_tcp.assert_any_call(ip, 8000, 8002, ignorar=[8001], timeout=0.4, max_workers=7)
    assert {chamada.args[1] for chamada in conectar.call_args_list} == {8000, 8002}

    texto = saida.getvalue()
    assert texto.index("Dados da varredura") < texto.index("MAC(s)")
    assert any("Resumo" in linha and "Online: 2" in linha for linha in texto.splitlines())
    assert "Interface: Wi-Fi" in texto and "IPv4 local: 192.168.100.254" in texto
    assert "Máscara: 255.255.255.0" in texto and "Máscara da faixa: 255.255.255.128" in texto
    assert "Portas TCP excluídas: 8001" in texto
    assert "ICMP bloqueado: 1" in texto and "Conflitos de IP: 1" in texto
    tabela, lista = texto.split("Portas TCP abertas (8000 a 8002)\n")
    assert "8000, 8002" not in tabela and "00:11:22:33:44:66" in tabela
    assert lista.splitlines()[:2] == [f"{ip}  8000, 8002", f"{dados.ip_local}  Nenhuma"]
    salvo = carregar_inventario(caminho)
    assert salvo[fora] == registro_fora
    assert salvo[ip]["open_ports"] == [8000, 8002]
    assert salvo[ip]["primeira_vez_visto"] == anterior
    assert salvo[ip]["ultima_vez_visto"] == instante_da_varredura

    icmp.return_value = []
    arp.return_value = {}
    obter_tcp.reset_mock()
    saida.truncate(0)
    saida.seek(0)
    terminal._varrer(console, opcoes)

    obter_tcp.assert_not_called()
    assert "Offline: 2" in saida.getvalue()
    salvo_novamente = carregar_inventario(caminho)
    assert salvo_novamente[fora] == registro_fora
    assert salvo_novamente[ip]["status"] == "offline"
    assert salvo_novamente[ip]["ultima_vez_visto"] == salvo[ip]["ultima_vez_visto"]


def test_tabela_compacta_mostra_dados_completos():
    ip = "192.168.100.254"
    item = Device(
        ip, ["00:11:22:33:44:55"], "online", arp_ativo=True, icmp_ativo=True,
        ultima_vez_visto="2026-11-25T09:03:04-03:00",
    )
    offline = Device("192.168.100.253", status="offline")
    saida = StringIO()
    console = Console(file=saida, width=80)
    console.print(terminal._tabela([item, offline], console.width))

    texto = saida.getvalue()
    assert all(valor in texto for valor in (ip, "Offline", "Conflito", "25/11/2026", "09:03:04"))
    assert any(ip in linha and "ARP, ICMP" in linha for linha in texto.splitlines())
    assert all(len(linha) <= 80 for linha in texto.splitlines())


def test_tcp_trata_host_sem_resolucao_e_todas_portas_excluidas(monkeypatch):
    resolver = Mock(side_effect=gaierror("Host não resolvido"))
    conectar = Mock()
    monkeypatch.setattr(ports.socket, "gethostbyname", resolver)
    monkeypatch.setattr(ports, "_verificar_porta", conectar)
    item = Device("192.168.100.253", status="online", open_ports=[443])
    dados = DadosRede("Wi-Fi", "192.168.100.254", "192.168.100.0/24")
    monkeypatch.setattr(discovery, "obter_dados_rede", lambda _: dados)
    monkeypatch.setattr(discovery, "varrer_rede_icmp", lambda **_: [])
    monkeypatch.setattr(discovery, "varrer_rede_arp", lambda **_: {item.ip: ["00:11:22:33:44:55"]})
    monkeypatch.setattr(discovery, "carregar_inventario", lambda: {item.ip: item.to_dict()})

    falha = discovery.descobrir_dispositivos(intervalo_portas=(443, 443), salvar=False)
    assert falha.portas_verificadas == {item.ip: None}
    assert falha.online[0].open_ports == [443]
    resolver.assert_called_once_with(item.ip)

    excluidas = discovery.descobrir_dispositivos(intervalo_portas=(443, 443), portas_excluidas=(443,), salvar=False)
    assert excluidas.portas_verificadas == {item.ip: []}
    assert excluidas.online[0].open_ports == []
    assert resolver.call_count == 1
    conectar.assert_not_called()
