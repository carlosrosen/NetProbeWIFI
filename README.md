# NetProbeWIFI
Ferramenta de inventário para redes domésticas capaz de mapear dispositivos ativos, contornando bloqueios de ICMP via técnicas de sondagem de IP/ARP.

## Como executar

O NetProbe usa Python 3.10 ou superior e precisa de acesso à internet na primeira instalação das dependências. O arquivo `main.py` cria a `.venv` dentro da cópia do projeto, instala os pacotes do `requirements.txt` e abre o menu. As próximas execuções reaproveitam o ambiente.

No Windows, abra o PowerShell ou o Git Bash na pasta clonada e execute:

```text
./abrir-netprobe.cmd
```

O atalho procura o Python instalado. Se encontrar apenas o `uv`, ele usa o `uv` para preparar o Python na pasta do projeto.

No Linux ou macOS, execute:

```sh
python3 main.py
```

Em distribuições Linux que fornecem `venv` separadamente, instale o pacote `python3-venv` ou o equivalente da distribuição.

Para usar a varredura ARP no Windows, instale o [Npcap](https://npcap.com/#download). A varredura também depende de uma interface com IPv4 local e de permissão para abrir os sockets de ICMP e ARP. Se o sistema exigir privilégios, prepare o ambiente antes de reabrir o programa em um terminal com as permissões necessárias. Veja como configurar a captura e os sockets na documentação abaixo.

## Documentação

- [Mecanismo de Colisão / ARP](docs/arp.md)
- [Ping Sweep com ICMP](docs/icmp.md)
