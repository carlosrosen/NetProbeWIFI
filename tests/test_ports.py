from src.scanner.ports import scan_ports

if __name__ == "__main__":
    ip = input("Digite o IPv4: ").strip()

    try:
        inicio = int(input("Porta inicial: "))
        fim = int(input("Porta final: "))

        if not (1 <= inicio <= fim <= 65535):
            raise ValueError("Intervalo de portas inválido.")

        quantidade, portas = scan_ports(ip, inicio, fim)

        print(quantidade)
        print(portas)

    except ValueError as erro:
        print(-1)
