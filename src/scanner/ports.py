import socket

def scan_ports(ip, inicio, fim):
    """
    Realiza uma varredura de portas TCP em um endereço IPv4.

    Entradas:
        ip (str): Endereço IPv4 ou hostname do alvo.
        inicio (int): Número da porta inicial da varredura.
        fim (int): Número da porta final da varredura.

    Funcionamento:
        Resolve o endereço informado para IPv4 e percorre o intervalo
        de portas especificado, tentando estabelecer uma conexão TCP
        com cada porta. As portas que aceitarem a conexão são
        armazenadas em uma lista.

    Saídas:
        tuple: Retorna dois valores:
            - quantidade (int): Número de portas abertas encontradas.
            - abertas (list): Lista com os números das portas abertas.

        Em caso de erro na resolução do endereço ou na execução
        da função, retorna (-1, []).
    """
    try:
        endereco = socket.gethostbyname(ip)
        abertas = []

        for porta in range(inicio, fim + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)

                    if sock.connect_ex((endereco, porta)) == 0:
                        abertas.append(porta)

            except OSError:
                continue

        return len(abertas), abertas

    except (socket.gaierror, OSError):
        return -1, []
