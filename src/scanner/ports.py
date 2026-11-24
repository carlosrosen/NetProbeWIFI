"""
Módulo de varredura de portas TCP.
"""

import math
import socket
from concurrent.futures import ThreadPoolExecutor


def _validar_parametros(
    ip: str,
    inicio: int,
    fim: int,
    ignorar: list[int] | None,
    timeout: float
) -> None: 
    """Valida os parâmetros da varredura de portas."""
    if not isinstance(ip, str) or not ip.strip():
        raise ValueError("O IP/hostname não pode ser vazio.")

    if not isinstance(inicio, int) or isinstance(inicio, bool):
        raise TypeError("A porta inicial deve ser um número inteiro.")

    if not isinstance(fim, int) or isinstance(fim, bool):
        raise TypeError("A porta final deve ser um número inteiro.")

    if ignorar is not None:
        if not isinstance(ignorar, list):
            raise TypeError(
                "O parâmetro 'ignorar' deve ser uma lista de "
                "inteiros ou None."
            )

        for porta in ignorar:
            if not isinstance(porta, int) or isinstance(porta, bool):
                raise TypeError(
                    "Todas as portas em 'ignorar' devem ser "
                    "números inteiros."
                )

            if not (1 <= porta <= 65535):
                raise ValueError(
                    "Todas as portas em 'ignorar' devem estar "
                    "entre 1 e 65535."
                )

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


def _verificar_porta(endereco: str, porta: int, timeout:float) -> int | None: 
    """Verifica se uma porta está aberta no endereço informado."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
    
            if sock.connect_ex((endereco, porta)) == 0:
                return porta
    
    except OSError:
        pass
    
    return None


def scan_ports(
    ip: str,
    inicio: int,
    fim: int,
    ignorar: list[int] | None = None,
    timeout: float = 1.0,
    max_workers: int = 100
) -> tuple[int, list[int]]: 
    """
    Realiza uma varredura de portas TCP em um endereço IPv4.

    Parâmetros:
        ip (str): Endereço IPv4 ou hostname do alvo.
        inicio (int): Número da porta inicial da varredura.
        fim (int): Número da porta final da varredura.
        ignorar (list[int] | None): Lista com os números das portas
            que devem ser ignoradas.
        timeout (float): Tempo máximo de espera por conexão, em
            segundos.
        max_workers (int): Número máximo de threads utilizadas
            simultaneamente na varredura. 

    Funcionamento:
        Resolve o endereço informado para IPv4 e percorre o intervalo
            de portas especificado, tentando estabelecer uma conexão
            TCP com cada porta. As portas que aceitarem a conexão são
            armazenadas em uma lista.

    Retorno:
        tuple[int, list[int]]: Retorna dois valores:
            - quantidade (int): Número de portas abertas encontradas.
            - abertas (list[int]): Lista com os números das portas
                abertas.

        Em caso de erro de resolução do endereço ou de execução,
            retorna (-1, []).

    Exceções:
        ValueError: Se o IP, o intervalo de portas ou o timeout forem
            inválidos.
        TypeError: Se as portas não forem números inteiros.
    """
    _validar_parametros(ip, inicio, fim, ignorar, timeout)
    ignorar_set = set(ignorar or [])

    try:
        endereco = socket.gethostbyname(ip.strip())

        portas_alvo = [
            porta
            for porta in range(inicio, fim + 1)
            if porta not in ignorar_set
        ]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            resultados = executor.map(
                lambda porta: _verificar_porta(endereco, porta, timeout),
                portas_alvo
            )

        abertas = sorted(
            porta
            for porta in resultados
            if porta is not None
        )

        return len(abertas), abertas

    except (socket.gaierror, OSError):
        return -1, []
