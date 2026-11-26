# Ping Sweep com ICMP

Documentação detalhada do módulo [`src/scanner/icmp.py`](../src/scanner/icmp.py).

Este módulo implementa a varredura de hosts via ICMP usando a biblioteca
`icmplib`. Ele descobre quais IPs respondem a ping e retorna objetos `Host`
com estatísticas de latência e perda de pacotes.

O módulo é independente do ARP e da UI: ele não importa `arp.py` e não imprime
nada. A integração com o inventário e com o ARP é feita pela camada de
orquestração.

---

## 1. Visão geral

O fluxo do `varrer_rede_icmp` é:

1. Validar os parâmetros.
2. Resolver a interface e a rede (`rede`, `cidr` ou interface).
3. Obter o IP de origem da interface.
4. Verificar o limite de tamanho da rede.
5. Gerar a lista de IPs utilizáveis.
6. Executar o `multiping` do `icmplib`.
7. Filtrar apenas os hosts com `is_alive == True`.
8. Retornar um `Set[Host]`.

### Por que ICMP não basta

Alguns dispositivos bloqueiam ou ignoram ping. O ICMP não os encontra, mas o
ARP pode encontrar. Por isso o projeto combina:

- **ICMP:** descoberta rápida de hosts que respondem a ping;
- **ARP:** descoberta de hosts que bloqueiam ICMP;
- **`filtrar_bloqueados_icmp`:** cruza os dois resultados.

### Formato do retorno

```python
{
    Host("192.168.0.1", packets_sent=2, rtts=[1.2, 0.9]),
    Host("192.168.0.73", packets_sent=2, rtts=[0.3, 0.2]),
}
```

O retorno é um `Set[Host]`, não um `Set[str]`.

### Objeto `Host`

Cada `Host` do `icmplib` expõe:

| Atributo | Significado |
|---|---|
| `address` | IP do host |
| `is_alive` | Se o host respondeu |
| `min_rtt` | Menor RTT, em ms |
| `avg_rtt` | RTT médio, em ms |
| `max_rtt` | Maior RTT, em ms |
| `rtts` | Lista de RTTs |
| `packets_sent` | Pacotes enviados |
| `packets_received` | Pacotes recebidos |
| `packet_loss` | Perda de pacotes entre 0 e 1 |
| `jitter` | Jitter, em ms |

Para pegar só os IPs:

```python
ips = {host.address for host in hosts}
```

---

## 2. Referência das funções

### 2.1 `_validar_ip_local(ip_local) -> str`

**Local:** [`src/network/interfaces.py`](../src/network/interfaces.py).

**Objetivo:** validar o IP local antes de usá-lo para montar a rede.

**Rejeita:**

- endereços loopback (`127.0.0.0/8`);
- link-local (`169.254.0.0/16`);
- `0.0.0.0`;
- strings que não sejam IPv4 válido.

**Retorno:** o IP canônico como string.

**Exceção:** `OSError` se o IP for inválido ou inadequado.

---

### 2.2 `DadosRede` e `obter_dados_rede(interface=None)`

**Local:** [`src/network/interfaces.py`](../src/network/interfaces.py).

**Objetivo:** descobrir, em uma única chamada, a interface, o IP local, a rede
e a máscara.

```python
@dataclass(frozen=True)
class DadosRede:
    interface: str
    ip_local: str
    rede: str
    mascara: str | None = None
```

**Como funciona:**

1. Resolve a interface; se `interface` for `None`, usa a rota padrão. Se a rota
   não puder ser determinada, gera `RuntimeError`.
2. Consulta o `psutil` e valida cada IPv4 com `_validar_ip_local`. Loopback,
   link-local, `0.0.0.0` e endereços inválidos são ignorados.
3. Monta a rede com `IPv4Network(ip/máscara, strict=False)`.
4. Se houver mais de um IPv4 válido, prefere o endereço que o Scapy usa na
   interface (`get_if_addr`), evitando escolher um adaptador secundário/VPN.
5. Se o `psutil` não estiver disponível ou não houver endereço válido, usa
   `get_if_addr(interface)` e assume `/24` como último recurso. Se o endereço
   também for inadequado, gera `RuntimeError`.

**Retorno:** `DadosRede`.

**Exceção:** `RuntimeError` se não houver IP local válido ou se a interface não
puder ser consultada.

**Observação:** o ICMP usa a mesma interface do ARP, evitando que cada módulo
escolha uma rede diferente.

---

### 2.3 `varrer_rede_icmp(...) -> Set[Host]`

```python
def varrer_rede_icmp(
    rede: Optional[Union[str, ipaddress.IPv4Network]] = None,
    cidr: int = 24,
    tempo_limite: float = 2.0,
    quantidade_pings: int = 2,
    intervalo: float = 0.05,
    tarefas_concorrentes: int = 50,
    privilegiado: bool = False,
    interface: NomeInterface | None = None,
) -> Set[Host]:
```

**Objetivo:** fazer um ping sweep na rede e retornar os hosts ativos.

**Parâmetros:**

| Parâmetro | Tipo | Padrão | Descrição |
|---|---|---|---|
| `rede` | `str \| IPv4Network \| None` | `None` | Rede alvo em CIDR, IP base ou objeto `IPv4Network`. Se `None`, usa a rede real da interface. |
| `cidr` | `int` | `24` | Prefixo usado quando `rede` é uma string sem `/`. Quando `rede` é `None`, a máscara real da interface é usada. |
| `tempo_limite` | `float` | `2.0` | Tempo máximo de espera por resposta. Finito e maior que zero. |
| `quantidade_pings` | `int` | `2` | Número de pacotes ICMP enviados por host. Inteiro maior que zero. |
| `intervalo` | `float` | `0.05` | Intervalo entre pacotes, em segundos. Finito e maior ou igual a zero. |
| `tarefas_concorrentes` | `int` | `50` | Número máximo de pings simultâneos. Inteiro maior que zero. |
| `privilegiado` | `bool` | `False` | Usa socket privilegiado. No Windows o `icmplib` força o modo privilegiado; no Linux/macOS pode exigir root ou `ping_group_range`. Também disponível no menu e em `descobrir_dispositivos(privilegiado=True)`. |
| `interface` | `str \| None` | `None` | Interface usada para descobrir a rede e definir o IP de origem. Se `None`, usa a rota padrão. |

**Retorno:** `Set[Host]` com apenas os hosts que responderam.

**Exceções:**

- `ValueError`: rede/CIDR/parâmetros inválidos ou rede maior que `MAXIMO_HOSTS_PADRAO`.
- `TypeError`: tipo inválido em `rede` ou `privilegiado`.
- `PermissionError`: falta de permissão para abrir o socket ICMP.
- `MemoryError`: falha ao montar uma lista muito grande de hosts.
- `RuntimeError`: erro de socket/rede durante o multiping.

**Como funciona:**

1. Valida `cidr`, `tempo_limite`, `quantidade_pings`, `intervalo`,
   `tarefas_concorrentes` e `privilegiado`, incluindo tipos e valores
   `NaN`/`inf`.
2. Chama `obter_dados_rede(interface)`.
3. Se `rede` for `None`, usa `dados.rede` (a máscara real da interface
   prevalece sobre `cidr`).
4. Usa `dados.ip_local` como IP de origem.
5. Resolve a rede:
   - `IPv4Network` → usa o objeto;
   - `str` → aceita CIDR ou IP base; se não tiver `/`, acrescenta `cidr`.
6. Verifica `MAXIMO_HOSTS_PADRAO` (65.536 endereços) para evitar redes
   gigantes como `/0` ou `/8`.
7. Gera a lista com `objeto_rede.hosts()`, que exclui rede e broadcast.
8. Chama `multiping` com `source=ip_origem`, forçando a saída pela interface
   escolhida.
9. Mantém apenas os hosts com `host.is_alive`.

**Exemplo simples:**

```python
from src.scanner.icmp import varrer_rede_icmp

hosts = varrer_rede_icmp()

for endereco in sorted(host.address for host in hosts):
    print(endereco)
```

**Exemplo com rede e timeout:**

```python
hosts = varrer_rede_icmp(
    rede="192.168.0.0/24",
    interface="Ethernet",
    tempo_limite=2.0,
    quantidade_pings=2,
    intervalo=0.05,
    tarefas_concorrentes=50,
    privilegiado=False,
)
```

**Exemplo com IP base e CIDR:**

```python
hosts = varrer_rede_icmp(
    rede="192.168.0.73",
    cidr=24,
)
```

**Exemplo com objeto `IPv4Network`:**

```python
import ipaddress

hosts = varrer_rede_icmp(
    rede=ipaddress.IPv4Network("192.168.0.0/24"),
)
```

---

## 3. Integração com o ARP

O `filtrar_bloqueados_icmp` do ARP aceita diretamente o `Set[Host]`:

```python
from src.scanner.arp import (
    filtrar_bloqueados_icmp,
    varrer_rede_arp,
)
from src.scanner.icmp import varrer_rede_icmp

rede = "192.168.0.0/24"
interface = "Ethernet"

hosts_icmp = varrer_rede_icmp(
    rede=rede,
    interface=interface,
    quantidade_pings=1,
    tempo_limite=1.0,
)

resultados_arp = varrer_rede_arp(
    rede=rede,
    interface=interface,
    tempo_limite=2.0,
    tentativas=2,
    intervalo=0.01,
)

bloqueados = filtrar_bloqueados_icmp(resultados_arp, hosts_icmp)

for ip, macs in bloqueados.items():
    print(ip, macs)
```

O ARP extrai `host.address` internamente. Não é necessário converter para
`set[str]` antes da chamada.

Para uma descoberta completa, prefira `descobrir_dispositivos`: ele executa
ICMP e ARP em paralelo, isola falhas de cada scanner e devolve
`ResultadoDescoberta.avisos`. Quando apenas um scanner falha, o resultado do
outro é preservado e os dispositivos não encontrados passam para `unknown`, em
vez de serem marcados como `offline`.

---

## 4. Permissões por sistema

| Sistema | Comportamento |
|---|---|
| Windows | O `icmplib` força o modo privilegiado. Na máquina de teste funcionou sem admin; se o socket for negado, o `descobrir_dispositivos` preserva o resultado do ARP e exibe um aviso. |
| Linux | `privilegiado=False` pode exigir `net.ipv4.ping_group_range`; `privilegiado=True` normalmente exige root/sudo. |
| macOS | Pode exigir permissões de socket; use `sudo` se necessário. |

O menu principal permite ativar o ICMP privilegiado. O padrão é ativado
automaticamente quando o processo roda como root (`geteuid() == 0`). No Linux,
se ocorrer `PermissionError`, a mensagem orienta a executar como root com
`privilegiado=True` ou configurar `net.ipv4.ping_group_range`. Em uma descoberta
completa, uma falha de ICMP não derruba o ARP: o resultado parcial é exibido
com aviso.

---

## 5. Limitações

1. **Hosts que bloqueiam ICMP não aparecem.** Use o ARP para encontrá-los.
2. **O IP local pode aparecer no resultado**, porque ele responde ao próprio
   ping. A interface atual o exibe como um dispositivo comum; isso é esperado.
3. **A rota padrão pode apontar para VPN.** Quando `interface` não é informada,
   o IP descoberto pode ser o da VPN. Passe `interface="Ethernet"`/`"Wi-Fi"`
   para alinhar com o ARP.
4. **Redes muito grandes são bloqueadas** por `MAXIMO_HOSTS_PADRAO = 65536`.
5. **Não detecta portas.** A varredura de portas é feita pelo `ports.py`.
6. **Não diferencia “offline” de “ICMP bloqueado”.** Isso é feito pelo
   cruzamento com o ARP.
7. **Falha de ICMP não derruba a descoberta completa.** Em
   `descobrir_dispositivos`, o ARP continua e o resultado é retornado com um
   aviso; dispositivos não encontrados ficam como `unknown`.

---

## 6. Validação manual

A validação pode ser feita pelo menu principal:

```powershell
.\.venv\Scripts\python.exe -m src.interface.terminal
```

Use uma faixa pequena, como `192.168.0.0/30`, e confira os hosts encontrados,
o status “ICMP bloqueado” e a coluna “Via”. Para testar diretamente:

```python
from src.scanner.icmp import varrer_rede_icmp

hosts = varrer_rede_icmp(
    rede="192.168.0.0/30",
    interface="Ethernet",
    quantidade_pings=1,
    tempo_limite=1.0,
)
print([host.address for host in hosts])
```

---

## 7. Relação com a atribuição

| Atividade | Onde está |
|---|---|
| Varredura da faixa `/24` | `varrer_rede_icmp` + `objeto_rede.hosts()` |
| Timeout parametrizável | `tempo_limite` |
| Quantidade de pacotes | `quantidade_pings` |
| Intervalo entre pacotes | `intervalo` |
| Concorrência | `tarefas_concorrentes` |
| Retorno de IPs ativos | `Set[Host]` com `host.address` |
| Cruzamento com ARP | `filtrar_bloqueados_icmp(resultados_arp, hosts_icmp)` |
