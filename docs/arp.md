# Mecanismo de Colisão / ARP Probe

Documentação detalhada do módulo [`src/scanner/arp.py`](../src/scanner/arp.py).

Este módulo implementa a descoberta de dispositivos IPv4 na rede local usando
ARP e a detecção de conflitos de IP. Ele é independente do scanner ICMP e da
interface gráfica: não importa `icmp.py`, não imprime nada e retorna dados
simples em Python.

---

## 1. Visão geral

O ARP (Address Resolution Protocol) descobre qual MAC está associado a um IP
dentro da mesma rede local. Ele funciona na camada 2 e, por isso, não depende
de ICMP. É justamente essa característica que permite encontrar dispositivos
que bloqueiam ping.

O fluxo de uso do módulo é:

1. Descobrir a interface e a rede local.
2. Gerar a lista de IPs alvo.
3. Montar uma requisição ARP broadcast para cada IP.
4. Enviar as requisições com `srp` e `multi=True`.
5. Agrupar as respostas em `{ip: [macs]}`.
6. Cruzar com os IPs que responderam ao ICMP.
7. Destacar IPs com mais de um MAC (conflito).
8. Retornar os dados para a camada de integração/UI.

### Por que ARP contorna o bloqueio de ICMP

Um dispositivo pode estar configurado para não responder a ping, mas
normalmente continua respondendo a ARP para poder se comunicar na rede local.
Assim:

- ICMP respondeu → dispositivo online.
- ICMP não respondeu + ARP respondeu → dispositivo online, mas bloqueia ICMP.
- ICMP não respondeu + ARP não respondeu → provavelmente offline ou fora do
  alcance da camada 2.

### Formato do retorno

```python
{
    "192.168.0.1": ["aa:bb:cc:dd:ee:ff"],
    "192.168.0.10": ["11:22:33:44:55:66", "77:88:99:aa:bb:cc"],
}
```

Uma lista com mais de um MAC no mesmo IP indica **conflito de IP**.

### Organização interna do arquivo

O `arp.py` está dividido nas seguintes seções:

1. **Tipos e constantes** — aliases como `EnderecoIp`, `EnderecoMac` e
   `ResultadoArp`, além dos valores padrão de tempo limite, tentativas e
   intervalo.
2. **API pública** — `varrer_rede_arp`, `filtrar_bloqueados_icmp`,
   `encontrar_conflitos` e `encontrar_macs_duplicados`.
3. **Descoberta de interface e rede** — movida para
   [`src/network/interfaces.py`](../src/network/interfaces.py):
   `DadosRede`, `obter_dados_rede`, `_resolver_interface`,
   `_obter_dados_do_sistema` e `_candidatos_de_nome_da_interface`.
4. **Resolução dos alvos** — `_resolver_ips_alvo`, `_normalizar_ips_alvo`,
   `_ips_utilizaveis_da_rede` e `_validar_parametros_da_varredura`.
5. **Construção e envio dos pacotes ARP** — `_montar_requisicoes_arp` e
   `_enviar_requisicoes_arp`.
6. **Análise das respostas** — `_agrupar_respostas_por_ip`,
   `_converter_para_resultado_ordenado`, `_normalizar_macs` e
   `_normalizar_ip_ativo`.

Essa divisão mantém a API pública no topo e os detalhes de implementação
abaixo, facilitando a leitura e a manutenção.

---

## 2. Estrutura do pacote ARP

### Requisição (`who-has`)

```text
Ethernet:
  dst = ff:ff:ff:ff:ff:ff   (broadcast: todos recebem)
  src = nosso MAC

ARP:
  op    = 1                 (who-has)
  psrc  = nosso IP
  pdst  = IP alvo
  hwsrc = nosso MAC
  hwdst = 00:00:00:00:00:00 (desconhecido)
```

Pergunta feita: **“Quem tem o IP alvo? Responda para o meu IP.”**

O `Ether.dst` precisa ser broadcast porque ainda não sabemos o MAC do alvo. É
o ARP que vai descobrir isso.

### Resposta (`is-at`)

```text
ARP:
  op    = 2                 (is-at)
  psrc  = IP do dispositivo
  hwsrc = MAC do dispositivo
  pdst  = nosso IP
  hwdst = nosso MAC
```

Na resposta, `psrc` é o IP de quem respondeu e `hwsrc` é o MAC dele. Por isso
o código usa esses dois campos, e não `pdst`.

---

## 3. Referência das funções

### 3.1 `DadosRede` e `obter_dados_rede(interface=None)`

**Local:** [`src/network/interfaces.py`](../src/network/interfaces.py).

**Objetivo:** descobrir interface, IP local, rede e máscara em uma única
chamada.

```python
@dataclass(frozen=True)
class DadosRede:
    interface: str
    ip_local: str
    rede: str
    mascara: str | None = None
```

**Parâmetros:**

| Parâmetro   | Tipo          | Descrição                                                                                     |
| ----------- | ------------- | --------------------------------------------------------------------------------------------- |
| `interface` | `str \| None` | Nome da interface (`"Ethernet"`, `"Wi-Fi"` etc.). Se omitido, usa a interface da rota padrão. |

**Retorno:** `DadosRede`, por exemplo:

```python
DadosRede(
    interface="Ethernet",
    ip_local="192.168.0.73",
    rede="192.168.0.0/24",
    mascara="255.255.255.0",
)
```

**Como funciona:**

1. Resolve a interface. Se `interface` for `None`, usa a rota padrão
   (`conf.route.route("0.0.0.0")`); se a rota não puder ser determinada, gera
   `RuntimeError` com uma mensagem clara.
2. Tenta obter o nome amigável da interface com `resolve_iface(interface).name`,
   porque o `psutil` e o Scapy podem usar nomes diferentes no Windows.
3. Percorre `psutil.net_if_addrs()` e valida cada IPv4 com
   `_validar_ip_local`. Endereços loopback, link-local, `0.0.0.0` e inválidos
   são ignorados.
4. Monta a rede com `IPv4Network(f"{ip}/{mascara}", strict=False)`.
5. Quando há mais de um IPv4 válido, prefere o endereço que o Scapy usa na
   interface (`get_if_addr`), evitando escolher um adaptador secundário/VPN.
6. Se o `psutil` não estiver disponível, não tiver endereço válido ou não
   achar a máscara, usa `get_if_addr(interface)` e assume `/24` como último
   recurso. Se esse endereço também for inadequado, gera `RuntimeError`.

**Exceções:** `RuntimeError` se a rota padrão não puder ser determinada, se a
interface não puder ser consultada ou se não houver IPv4 local válido.

**Por que não usar `conf.iface`:**

Em máquinas com VPN, `conf.iface` pode apontar para o adaptador da VPN
enquanto a rota padrão real usa o Ethernet/Wi-Fi. Neste ambiente, por exemplo,
`conf.iface` apontava para a Radmin VPN (`26.20.183.30`), enquanto a rota
padrão era a Ethernet (`192.168.0.73`). Usar `conf.iface` faria a varredura
sair pela interface errada.

**Observação:** no projeto final, prefira o helper compartilhado de
`src/network/interfaces.py` e passe `interface`/`rede` explicitamente para
`varrer_rede_arp`.

---

### 3.2 `varrer_rede_arp(alvos=None, *, rede=None, interface=None, tempo_limite=1.0, tentativas=2, intervalo=0.0) -> dict[str, list[str]]`

**Objetivo:** descobrir dispositivos IPv4 na rede local via ARP.

**Parâmetros:**

| Parâmetro      | Tipo                           | Padrão | Descrição                                                                        |
| -------------- | ------------------------------ | ------ | -------------------------------------------------------------------------------- |
| `alvos`        | `Iterable[str] \| str \| None` | `None` | IPs específicos. Se omitido, usa `rede`. Uma string única é aceita.              |
| `rede`         | `str \| None`                  | `None` | Rede em CIDR, por exemplo `"192.168.0.0/24"`. Ignorada se `alvos` for fornecido. |
| `interface`    | `str \| None`                  | `None` | Interface de rede. Se omitida, usa a interface da rota padrão.                   |
| `tempo_limite` | `float`                        | `1.0`  | Segundos de espera por resposta. Finito, maior que zero e no máximo `60`.       |
| `tentativas`   | `int`                          | `2`    | Quantas vezes reenviar requisições sem resposta. Inteiro maior ou igual a zero.  |
| `intervalo`    | `float`                        | `0.0`  | Intervalo entre pacotes, em segundos. Finito, entre `0` e `60`.                  |

**Dica de confiabilidade:** em redes Wi-Fi ou com muitos dispositivos, use
`tempo_limite=2.0`, `tentativas=2` e `intervalo=0.01`. Com os valores padrão,
algumas respostas podem ser perdidas.

**Limite de alvos:** a varredura aceita no máximo **65.536 endereços**. Redes
maiores ou listas de alvos acima desse limite geram `ValueError` antes do envio
dos pacotes.

**Retorno:** `{ip: [macs]}`. IPs sem resposta ARP não entram no dicionário.

**Exceções:**

- `ValueError`: parâmetro com tipo ou valor inválido, `NaN`/`inf`, IP malformado,
  rede malformada ou rede/lista acima do limite de alvos.
- `RuntimeError`: interface sem IPv4 válido, falta de permissão, falha de camada
  2 ou Npcap indisponível no Windows.

**Como funciona:**

1. Valida `tempo_limite`, `tentativas` e `intervalo` (tipo, finitude e faixa).
2. Chama `_resolver_ips_alvo` para obter a lista de IPs e a interface.
3. Se a lista estiver vazia, retorna `{}`.
4. Verifica o limite de 65.536 alvos.
5. Chama `_enviar_requisicoes_arp` para enviar os pacotes e interpretar respostas.
6. Ordena os IPs numericamente e os MACs alfabeticamente.

**Exemplo:**

```python
from src.scanner.arp import varrer_rede_arp

resultado = varrer_rede_arp()

# ou
resultado = varrer_rede_arp(alvos=["192.168.0.1", "192.168.0.10"])

# ou
resultado = varrer_rede_arp(rede="192.168.0.0/24", interface="Ethernet")
```

**Detecção de conflito:** o dicionário usa listas como valores justamente para
preservar mais de um MAC no mesmo IP. Se fosse `{ip: mac}`, o segundo
dispositivo sobrescreveria o primeiro e o conflito desapareceria.

---

### 3.3 `filtrar_bloqueados_icmp(resultados_arp, ips_ativos) -> dict[str, list[str]]`

**Objetivo:** identificar dispositivos que estão ativos no ARP, mas não
responderam ao ping.

**Parâmetros:**

| Parâmetro        | Tipo                                             | Descrição                                                                 |
| ---------------- | ------------------------------------------------ | ------------------------------------------------------------------------- |
| `resultados_arp` | `Mapping[str, Iterable[str]]`                    | Resultado de `varrer_rede_arp`.                                           |
| `ips_ativos`     | `Iterable[str \| IPv4Address \| Host]`           | IPs vivos; aceita strings, `IPv4Address` ou objetos com atributo `address`. |

**Retorno:** subconjunto de `resultados_arp` cujos IPs não estão em
`ips_ativos`.

**Como funciona:**

1. Normaliza cada item de `ips_ativos` com `_normalizar_ip_ativo`:
   - `str` → `IPv4Address`;
   - `IPv4Address` → string canônica;
   - objeto com `.address` (como `icmplib.Host`) → usa o endereço.
2. Percorre `resultados_arp` e mantém apenas os IPs que não aparecem em
   `ips_ativos`.

**Exemplo com strings:**

```python
from src.scanner.arp import filtrar_bloqueados_icmp, varrer_rede_arp

resultados_arp = varrer_rede_arp()
ips_ativos = {"192.168.0.1", "192.168.0.11"}

bloqueados = filtrar_bloqueados_icmp(resultados_arp, ips_ativos)
```

**Exemplo com Hosts do ICMP:**

```python
from icmplib import Host

hosts_icmp = {
    Host("192.168.0.1", 1, [1.0]),
    Host("192.168.0.11", 1, [2.0]),
}

bloqueados = filtrar_bloqueados_icmp(resultados_arp, hosts_icmp)
```

Isso permite passar diretamente o retorno de `varrer_rede_icmp`, que devolve
`Set[Host]`.

Se `resultados_arp` tem `192.168.0.10` e ele não está em `ips_ativos`, ele
entra em `bloqueados`: está online, mas bloqueia ICMP.

**Importante:** essa função não executa ping. Ela apenas cruza os dados. Quem
executa o ping é o módulo ICMP da outra pessoa.

---

### 3.4 `encontrar_conflitos(resultados_arp) -> dict[str, list[str]]`

**Objetivo:** detectar conflito de IP clássico: dois dispositivos usando o
mesmo IP.

**Parâmetros:**

| Parâmetro        | Tipo                          | Descrição                       |
| ---------------- | ----------------------------- | ------------------------------- |
| `resultados_arp` | `Mapping[str, Iterable[str]]` | Resultado de `varrer_rede_arp`. |

**Retorno:** apenas os IPs com mais de um MAC.

**Como funciona:**

1. Para cada IP, chama `_normalizar_macs` para remover duplicatas e padronizar.
2. Se sobrar mais de um MAC, adiciona o IP ao resultado.

**Exemplo:**

```python
from src.scanner.arp import encontrar_conflitos

resultado = {
    "192.168.0.50": [
        "aa:bb:cc:dd:ee:01",
        "aa:bb:cc:dd:ee:02",
    ],
}

print(encontrar_conflitos(resultado))
# {"192.168.0.50": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]}
```

---

### 3.5 `encontrar_macs_duplicados(resultados_arp) -> dict[str, list[str]]`

**Objetivo:** encontrar o mesmo MAC associado a mais de um IP.

**Parâmetros:**

| Parâmetro        | Tipo                          | Descrição                       |
| ---------------- | ----------------------------- | ------------------------------- |
| `resultados_arp` | `Mapping[str, Iterable[str]]` | Resultado de `varrer_rede_arp`. |

**Retorno:** `{mac: [ips]}` apenas para MACs que aparecem em mais de um IP.

**Como funciona:**

1. Inverte o mapa para `MAC -> conjunto de IPs`.
2. Retorna apenas os MACs com mais de um IP.

**Atenção:** isso **não é necessariamente conflito**. Um roteador fazendo
proxy ARP, um balanceador ou um dispositivo com múltiplos IPs pode ter o mesmo
MAC em vários endereços. Use como informação extra, não como conflito
automático.

---

### 3.6 Descoberta de interface e rede

Esses helpers agora ficam em
[`src/network/interfaces.py`](../src/network/interfaces.py). O `arp.py` importa
`_resolver_interface` e `obter_dados_rede`.

#### `_resolver_interface(interface) -> str`

**Objetivo:** garantir uma interface concreta.

**Como funciona:**

```python
if not interface:
    rota = conf.route.route("0.0.0.0")
    if not rota or not rota[0]:
        raise RuntimeError("Não foi possível determinar a interface da rota padrão.")
    interface = rota[0]

try:
    return resolve_iface(interface).name or interface
except Exception:
    return interface
```

Se o usuário passou uma interface, tenta convertê-la para o nome amigável
usado pelo Scapy. Se a interface não puder ser resolvida, devolve o nome
original; a validação posterior de IP gera `RuntimeError` com uma mensagem
clara. Não usa `conf.iface` para evitar o problema da VPN descrito em
`obter_dados_rede`.

#### `_obter_dados_do_sistema(interface) -> DadosRede | None`

**Objetivo:** tentar obter IP, máscara e rede da interface via `psutil`.

**Como funciona:**

1. Se o `psutil` não estiver disponível ou falhar, retorna `None`.
2. Percorre os nomes candidatos da interface.
3. Para cada endereço IPv4 com máscara, valida o IP com `_validar_ip_local`;
   loopback, link-local, `0.0.0.0` e endereços inválidos são ignorados.
4. Monta `IPv4Network(ip/máscara)` e guarda um `DadosRede` candidato.
5. Se houver mais de um IPv4 válido, prefere o que coincide com o endereço
   retornado por `get_if_addr(interface)`.
6. Se não achar nenhum candidato válido, retorna `None` para o
   `obter_dados_rede` usar a alternativa `/24`.

#### `_candidatos_de_nome_da_interface(interface) -> list[str]`

**Objetivo:** lidar com a diferença de nomes entre Scapy e `psutil`.

O `psutil` usa nomes como `"Ethernet"` e `"Wi-Fi"`, enquanto o Scapy pode usar
caminhos como `\Device\NPF_{...}`. A função devolve o nome amigável (quando
consegue) e o nome original. Se os dois nomes forem iguais, devolve apenas uma
vez.

---

### 3.7 Resolução dos alvos

#### `_resolver_ips_alvo(alvos, rede, interface) -> tuple[list[str], str]`

**Objetivo:** transformar `alvos` ou `rede` na lista final de IPs e resolver a
interface.

**Como funciona:**

1. Se `alvos` foi fornecido, normaliza os IPs com `_normalizar_ips_alvo` e
   resolve a interface. A rede não é usada nesse caso.
2. Se `alvos` não foi fornecido:
   - se `rede` também não foi, chama `obter_dados_rede`;
   - caso contrário, resolve a interface.
3. Chama `_ips_utilizaveis_da_rede(rede)` para gerar os IPs utilizáveis; a
   função aplica o limite de 65.536 endereços.

#### `_normalizar_ips_alvo(alvos) -> list[str]`

**Objetivo:** validar e normalizar os IPs informados pelo usuário.

- Se `alvos` for uma string, envolve em uma lista.
- Valida cada item com `IPv4Address`.
- Retorna os IPs no formato canônico.

**Por que tratar string separadamente:** se o usuário passar
`"192.168.0.1"` e o código iterar diretamente, o Python percorre caractere por
caractere (`"1"`, `"9"`, `"2"` etc.) e tenta validar cada um como IP.

#### `_ips_utilizaveis_da_rede(rede) -> list[str]`

**Objetivo:** gerar todos os IPs utilizáveis de uma rede IPv4.

Antes de materializar a lista, verifica `num_addresses` contra
`MAXIMO_HOSTS_PADRAO` (`65.536`). Redes maiores geram `ValueError` para evitar
consumo excessivo de memória e o envio de milhões de pacotes.

Usa `IPv4Network(rede, strict=False).hosts()`, que exclui endereço de rede e
broadcast.

**Por que `strict=False`:** permite receber um IP de host com prefixo, como
`192.168.0.73/24`, e normalizar para `192.168.0.0/24`.

#### `_validar_parametros_da_varredura(tempo_limite, tentativas, intervalo) -> None`

**Objetivo:** validar os parâmetros de tempo e tentativas.

- `tempo_limite` deve ser um número finito, maior que zero e no máximo `60`.
  Caso contrário, gera `ValueError`.
- `tentativas` deve ser um inteiro maior ou igual a zero. `bool`, `float` e
  strings geram `ValueError`.
- `intervalo` deve ser um número finito entre `0` e `60`. `NaN`, `inf` e tipos
  inválidos geram `ValueError`.

Essas validações evitam que valores como `inf` cheguem ao `srp` e travem a
thread de envio do Scapy.

---

### 3.8 `_montar_requisicoes_arp(ips_alvo, interface) -> list[Ether]`

**Objetivo:** montar uma requisição ARP broadcast para cada IP alvo.

**Como funciona:**

1. Pega o MAC e o IPv4 da interface:
   - `get_if_hwaddr(interface)`;
   - `get_if_addr(interface)`.
2. Valida se o IPv4 existe e não é `0.0.0.0`.
3. Para cada alvo, monta:

```python
Ether(dst=MAC_BROADCAST, src=mac_origem)
/ ARP(pdst=ip_alvo, psrc=ip_origem)
```

**Por que definir `src` e `psrc` explicitamente:** sem isso, o Scapy preenche
esses campos a partir de `conf.iface`/da rota padrão no momento da montagem.
Em máquina com mais de um adaptador, isso pode gerar um pacote com MAC/IP de
outra interface.

---

### 3.9 `_enviar_requisicoes_arp(ips_alvo, *, interface, tempo_limite, tentativas, intervalo) -> dict[str, set[str]]`

**Objetivo:** enviar os pacotes e interpretar as respostas.

**Como funciona:**

1. Chama `_montar_requisicoes_arp`.
2. Chama `srp` com:

```python
pacotes_respondidos, _pacotes_sem_resposta = srp(
    requisicoes_arp,
    iface=interface,
    timeout=tempo_limite,
    retry=tentativas,
    inter=intervalo,
    multi=True,
    verbose=False,
)
```

**Parâmetros do `srp`:**

| Parâmetro         | Função                                                                                         |
| ----------------- | ---------------------------------------------------------------------------------------------- |
| `requisicoes_arp` | Lista de requisições ARP.                                                                      |
| `iface`           | Interface de saída (recebe o valor de `interface`).                                            |
| `timeout`         | Tempo máximo de espera (recebe `tempo_limite`).                                                |
| `retry`           | Reenvios para requisições sem resposta (recebe `tentativas`).                                  |
| `inter`           | Intervalo entre pacotes (recebe `intervalo`).                                                  |
| `multi=True`      | Continua esperando respostas adicionais para o mesmo pacote. Essencial para detectar conflito. |
| `verbose=False`   | Desliga os logs do Scapy.                                                                      |

3. Trata erros e converte em `RuntimeError` com mensagem orientativa:
   - `PermissionError`: o Npcap/driver negou o acesso; normalmente ocorre em
     instalação “admin-only” ou quando falta permissão.
   - `Scapy_Exception` e outros `OSError`: falha ao abrir/usar a camada 2,
     Npcap ausente ou camada 2 indisponível.
   - `RuntimeError` com “winpcap” ou “layer 2”: mantém a mensagem específica
     de Npcap/camada 2.
4. Chama `_agrupar_respostas_por_ip`.

Quando a varredura é executada por `descobrir_dispositivos`, uma falha do ARP
não descarta o resultado do ICMP: a descoberta retorna os dispositivos
encontrados pelo ICMP e um aviso em `ResultadoDescoberta.avisos`.

**Por que `multi=True` é essencial:**

Sem `multi=True`, o Scapy para na primeira resposta de cada IP. Em um conflito,
o segundo dispositivo seria ignorado. Com `multi=True`, as duas respostas são
capturadas e o IP aparece com dois MACs.

Exemplo:

```text
Pergunta: quem tem 192.168.0.50?
Dispositivo A responde: é aa:bb:cc:dd:ee:01
Dispositivo B responde: é aa:bb:cc:dd:ee:02
Resultado: 192.168.0.50 -> [aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02]
```

---

### 3.10 `_agrupar_respostas_por_ip(pacotes_respondidos) -> dict[str, set[str]]`

**Objetivo:** transformar os pares `(enviado, recebido)` do Scapy em
`{ip: {macs}}`.

**Como funciona:**

1. Cria `respostas_por_ip: dict[str, set[str]]` usando `defaultdict(set)`.
2. Para cada par `(requisicao, resposta)`:
   - ignora pacotes sem ARP;
   - ignora `op != 2` (só respostas);
   - ignora `psrc == "0.0.0.0"` (probes/gratuitous sem IP de origem).
3. Adiciona `camada_arp.hwsrc.lower()` ao conjunto de `camada_arp.psrc`.

**Por que usar `set`:** evita duplicar o mesmo MAC caso a mesma resposta seja
capturada mais de uma vez.

**Por que usar `psrc`:** na resposta ARP, `psrc` é o IP do dispositivo que
respondeu. `pdst` é o nosso IP, não o alvo.

---

### 3.11 `_converter_para_resultado_ordenado(respostas_por_ip) -> dict[str, list[str]]`

**Objetivo:** converter o agrupamento interno no resultado público ordenado.

1. Ordena os IPs numericamente com `IPv4Address`.
2. Converte cada conjunto de MACs em lista ordenada.
3. Retorna `{ip: [macs]}`.

Essa separação deixa o `varrer_rede_arp` mais limpo: ele só coordena o fluxo e
delega a formatação para essa função.

---

### 3.12 `_normalizar_macs(enderecos_mac) -> list[str]`

**Objetivo:** normalizar listas de MACs para comparação.

**Como funciona:**

```python
return sorted({endereco_mac.lower() for endereco_mac in enderecos_mac})
```

Remove duplicatas, converte para minúsculo e ordena. É usada por
`filtrar_bloqueados_icmp` e `encontrar_conflitos`.

---

## 4. Integração com o ICMP

O contrato com o módulo ICMP é:

```python
from src.scanner.arp import (
    encontrar_conflitos,
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
conflitos = encontrar_conflitos(resultados_arp)

for endereco_ip, enderecos_mac in resultados_arp.items():
    if endereco_ip in conflitos:
        status = "CONFLITO"
    elif endereco_ip in bloqueados:
        status = "online (ICMP bloqueado)"
    else:
        status = "online"

    print(endereco_ip, enderecos_mac, status)
```

O `varrer_rede_icmp` retorna `Set[Host]`; o `filtrar_bloqueados_icmp` extrai
`host.address` automaticamente. Para uma descoberta completa, prefira
`descobrir_dispositivos`, que executa ICMP e ARP em paralelo, isola falhas de
cada scanner e devolve avisos sem descartar o resultado do outro.

---

## 5. Validação manual

A validação pode ser feita pelo menu principal:

1. Execute o menu principal:
   ```powershell
   .\.venv\Scripts\python.exe -m src.interface.terminal
   ```
2. Selecione uma interface/rede pequena, como `192.168.0.0/30`, e execute a
   varredura.
3. Confira a coluna “Via” (ARP/ICMP), os conflitos e os avisos exibidos.

Também é possível testar diretamente em Python:

```python
from src.scanner.arp import varrer_rede_arp

resultado = varrer_rede_arp(
    alvos=["192.168.0.1"],
    interface="Ethernet",
    tempo_limite=1.0,
    tentativas=1,
)
print(resultado)
```

---

## 6. Limitações e cuidados

1. **Npcap no Windows.** ARP é camada 2; sem Npcap não funciona. A instalação
   do Npcap pode ser restrita a administradores (opção “Restrict Npcap driver's
   access to Administrators only”); nesse caso, também é preciso rodar como
   admin. Em instalações sem essa restrição, um usuário comum pode usar.
   `PermissionError`, `Scapy_Exception` e `OSError` são convertidos em
   `RuntimeError` com mensagem orientativa. Quando a varredura é feita pelo
   `descobrir_dispositivos`, o ICMP continua e o aviso é exibido.
2. **ARP só funciona na mesma rede local (L2).** Não atravessa roteador, VPN
   ou outra sub-rede.
3. **Isolamento de clientes no Wi-Fi** pode bloquear ARP entre dispositivos.
   Teste na rede real.
4. **Conflito só aparece se os dois dispositivos responderem.** Se um estiver
   em silêncio, o `multi=True` não faz mágica. Para melhorar, rode a varredura
   mais de uma vez, aumente o `tempo_limite` e/ou use um `intervalo` pequeno
   (por exemplo, `0.01`).
5. **`encontrar_macs_duplicados` não é automaticamente conflito.** Proxy ARP e
   roteadores podem repetir MAC em IPs diferentes.
6. **`obter_dados_rede` vive em `src/network/interfaces.py`.** Use
   `interface`/`rede` explicitamente quando a máquina tiver mais de um
   adaptador.
7. **Rede limitada a 65.536 alvos.** Redes maiores são rejeitadas antes do
   envio para evitar consumo excessivo de memória e tráfego.
8. **Tempo e intervalo limitados a 60 s.** Valores `NaN`, `inf`, negativos ou
   acima do limite são rejeitados; isso evita travamentos no Scapy.
9. **Não altere o `device.py` sozinho.** O retorno é um dicionário; a camada
   de integração/UI decide como transformar em `Device` e como mostrar o
   status “ICMP bloqueado” ou “conflito”.
