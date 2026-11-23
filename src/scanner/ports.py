"""
Módulo de varredura de portas TCP.
"""

import math
import socket


def _validar_parametros(ip: str, inicio: int, fim: int, ignorar: list[int] | None, timeout: float) -> None:
    """Valida os parâmetros da varredura de portas."""
    if not isinstance(ip, str) or not ip.strip():
        raise ValueError("O IP/hostname não pode ser vazio.")

    if not isinstance(inicio, int) or isinstance(inicio, bool):
        raise TypeError("A porta inicial deve ser um número inteiro.")

    if not isinstance(fim, int) or isinstance(fim, bool):
        raise TypeError("A porta final deve ser um número inteiro.")

    if ignorar is not None:
        if not isinstance(ignorar, list):
             raise TypeError("O parâmetro 'ignorar' deve ser uma lista de inteiros ou None.")

        for porta in ignorar:
            if not isinstance(porta, int) or isinstance(porta, bool):
                raise TypeError("Todas as portas em 'ignorar' devem ser números inteiros.")
            if not (1 <= porta <= 65535):
                    raise ValueError("Todas as portas em 'ignorar' devem estar entre 1 e 65535.")

    if not (1 <= inicio <= fim <= 65535):
        raise ValueError(
            "O intervalo de portas deve estar entre 1 e 65535, "
            "com a porta inicial menor ou igual à final."
        )

    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("O timeout deve ser um número finito maior que zero.")


def scan_ports(ip: str, inicio: int, fim: int, ignorar: list[int] | None = None, timeout: float = 1.0) -> tuple[int, list[int]]:
    """
    Realiza uma varredura de portas TCP em um endereço IPv4.

    Entradas:
        ip (str): Endereço IPv4 ou hostname do alvo.
        inicio (int): Número da porta inicial da varredura.
        fim (int): Número da porta final da varredura.
        ignorar (list[int]): Lista com os números das portas que devem ser ignoradas.
        timeout (float): Tempo máximo de espera por porta, em segundos.

    Funcionamento:
        Resolve o endereço informado para IPv4 e percorre o intervalo
        de portas especificado, tentando estabelecer uma conexão TCP
        com cada porta. As portas que aceitarem a conexão são
        armazenadas em uma lista.

    Saídas:
        tuple: Retorna dois valores:
            - quantidade (int): Número de portas abertas encontradas.
            - abertas (list): Lista com os números das portas abertas.

        Em caso de erro de resolução do endereço ou de execução,
        retorna (-1, []).

    Exceções:
        ValueError: Se o IP, o intervalo de portas ou o timeout forem inválidos.
        TypeError: Se as portas não forem números inteiros.
    """
    _validar_parametros(ip, inicio, fim, ignorar, timeout)
    ignorar_set = set(ignorar or [])

    try:
        endereco = socket.gethostbyname(ip.strip())
        abertas = []

        for porta in range(inicio, fim + 1):
            if porta not in ignorar_set:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(timeout)

                        if sock.connect_ex((endereco, porta)) == 0:
                            abertas.append(porta)

                except OSError:
                    continue

        return len(abertas), abertas

    except (socket.gaierror, OSError):
        return -1, []
