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
2. Resolver a rede (`rede`, `cidr` ou IP local).
3. Verificar o limite de tamanho da rede.
4. Gerar a lista de IPs utilizáveis.
5. Executar o `multiping` do `icmplib`.
6. Filtrar apenas os hosts com `is_alive == True`.
7. Retornar um `Set[Host]`.

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

**Objetivo:** validar o IP local antes de usá-lo para montar a rede.

**Rejeita:**

- endereços loopback (`127.0.0.0/8`);
- link-local (`169.254.0.0/16`);
- `0.0.0.0`;
- strings que não sejam IPv4 válido.

**Retorno:** o IP canônico como string.

**Exceção:** `OSError` se o IP for inválido ou inadequado.

---

### 2.2 `obter_ip_local() -> str`

**Objetivo:** descobrir o IPv4 local da máquina.

**Como funciona:**

1. Abre um socket UDP para `8.8.8.8:80`.
2. Usa `getsockname()[0]` para obter o IP da interface usada pela rota padrão.
3. Valida o IP com `_validar_ip_local`.
4. Se falhar, tenta `socket.gethostbyname(socket.gethostname())`.
5. Se o fallback também falhar, levanta `RuntimeError`.

**Retorno:** IPv4 local como string.

**Exceção:** `RuntimeError` se não houver IP local válido.

**Observação:** o socket UDP não envia pacotes; ele só consulta a rota.

**Limitação:** em máquina com VPN, a rota padrão pode apontar para a VPN. Para
controlar isso, seria necessário um parâmetro de interface ou usar o helper
compartilhado de interfaces do projeto.

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
) -> Set[Host]:
```

**Objetivo:** fazer um ping sweep na rede e retornar os hosts ativos.

**Parâmetros:**

| Parâmetro | Tipo | Padrão | Descrição |
|---|---|---|---|
| `rede` | `str \| IPv4Network \| None` | `None` | Rede alvo em CIDR, IP base ou objeto `IPv4Network`. Se `None`, usa o IP local com `cidr`. |
| `cidr` | `int` | `24` | Prefixo usado quando `rede` é `None` ou uma string sem `/`. |
| `tempo_limite` | `float` | `2.0` | Tempo máximo de espera por resposta de cada pacote. |
| `quantidade_pings` | `int` | `2` | Número de pacotes ICMP enviados por host. |
| `intervalo` | `float` | `0.05` | Intervalo entre pacotes, em segundos. |
| `tarefas_concorrentes` | `int` | `50` | Número máximo de pings simultâneos. |
| `privilegiado` | `bool` | `False` | Usa socket privilegiado. No Windows é ignorado; no Linux pode exigir root ou `ping_group_range`. |

**Retorno:** `Set[Host]` com apenas os hosts que responderam.

**Exceções:**

- `ValueError`: rede/CIDR/parâmetros inválidos ou rede maior que `MAXIMO_HOSTS_PADRAO`.
- `TypeError`: tipo inválido em `rede` ou `privilegiado`.
- `PermissionError`: falta de permissão para abrir o socket ICMP.
- `MemoryError`: falha ao montar uma lista muito grande de hosts.
- `RuntimeError`: erro de socket/rede durante o multiping.

**Como funciona:**

1. Valida `cidr`, `tempo_limite`, `quantidade_pings`, `intervalo`,
   `tarefas_concorrentes` e `privilegiado`.
2. Resolve a rede:
   - `None` → usa `obter_ip_local()` e `cidr`;
   - `IPv4Network` → usa o objeto;
   - `str` → aceita CIDR ou IP base; se não tiver `/`, acrescenta `cidr`.
3. Verifica `MAXIMO_HOSTS_PADRAO` (65.536 endereços) para evitar redes
   gigantes como `/0` ou `/8`.
4. Gera a lista com `objeto_rede.hosts()`, que exclui rede e broadcast.
5. Chama `multiping` com os parâmetros convertidos.
6. Mantém apenas os hosts com `host.is_alive`.

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

---

## 4. Permissões por sistema

| Sistema | Comportamento |
|---|---|
| Windows | `privilegiado` é ignorado. O teste real funcionou sem admin. |
| Linux | `privilegiado=False` pode exigir `net.ipv4.ping_group_range`; `privilegiado=True` normalmente exige root/sudo. |
| macOS | Pode exigir permissões de socket; use `sudo` se necessário. |

No Linux, se ocorrer `PermissionError`, a mensagem orienta a executar como
root com `privilegiado=True` ou configurar `net.ipv4.ping_group_range`.

---

## 5. Limitações

1. **Hosts que bloqueiam ICMP não aparecem.** Use o ARP para encontrá-los.
2. **O IP local pode aparecer no resultado**, porque ele responde ao próprio
   ping. Decida na UI se ele deve ser exibido.
3. **A rota padrão pode apontar para VPN.** O módulo não recebe uma interface
   explícita; em máquina com VPN, o IP descoberto pode ser o da VPN.
4. **Redes muito grandes são bloqueadas** por `MAXIMO_HOSTS_PADRAO = 65536`.
5. **Não detecta portas.** A varredura de portas é feita pelo `ports.py`.
6. **Não diferencia “offline” de “ICMP bloqueado”.** Isso é feito pelo
   cruzamento com o ARP.
7. **Sem testes automatizados.** O `tests/test_icmp.py` é um script manual.

---

## 6. Testes

O script manual está em [`tests/test_icmp.py`](../tests/test_icmp.py):

```powershell
.\.venv\Scripts\python.exe tests\test_icmp.py
```

Ele imprime os hosts encontrados e grava estatísticas em
`hosts_ativos_encontrados.txt`.

O `pytest` atual não coleta testes desse arquivo, porque ele usa
`if __name__ == "__main__"`. Para cobertura automatizada, seria necessário
criar funções `test_*` e mockar o `multiping`.

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
