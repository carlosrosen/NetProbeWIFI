# Mecanismo de Colisão / ARP Probe

Documentação detalhada do módulo [`src/scanner/arp.py`](../src/scanner/arp.py).

Este módulo implementa a descoberta de dispositivos IPv4 na rede local usando
ARP e a detecção de conflitos de IP. Ele é independente do scanner ICMP e da
interface gráfica: não importa `icmp.py`, não imprime nada (fora do bloco de
teste manual) e retorna dados simples em Python.

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
2. **API pública** — `obter_rede_local`, `varrer_rede_arp`, `filtrar_bloqueados_icmp`,
   `encontrar_conflitos` e `encontrar_macs_duplicados`.
3. **Descoberta de interface e rede** — `_resolver_interface`,
   `_obter_rede_do_sistema` e `_candidatos_de_nome_da_interface`.
4. **Resolução dos alvos** — `_resolver_ips_alvo`, `_normalizar_ips_alvo`,
   `_ips_utilizaveis_da_rede` e `_validar_parametros_da_varredura`.
5. **Construção e envio dos pacotes ARP** — `_montar_requisicoes_arp` e
   `_enviar_requisicoes_arp`.
6. **Análise das respostas** — `_agrupar_respostas_por_ip`,
   `_converter_para_resultado_ordenado` e `_normalizar_macs`.
7. **Teste manual** — bloco `if __name__ == "__main__"`.

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

### 3.1 `obter_rede_local(interface=None) -> tuple[str, str]`

**Objetivo:** descobrir a interface e a rede IPv4 local quando o usuário não
passa esses dados explicitamente.

**Parâmetros:**

| Parâmetro   | Tipo          | Descrição                                                                                     |
| ----------- | ------------- | --------------------------------------------------------------------------------------------- |
| `interface` | `str \| None` | Nome da interface (`"Ethernet"`, `"Wi-Fi"` etc.). Se omitido, usa a interface da rota padrão. |

**Retorno:** `(interface, rede)`, por exemplo `("Ethernet", "192.168.0.0/24")`.

**Como funciona:**

1. Resolve a interface; se `interface` for `None`, usa
   `conf.route.route("0.0.0.0")[0]`.
2. Chama `_obter_rede_do_sistema`, que tenta obter o nome amigável da
   interface com `resolve_iface(interface).name`, porque o `psutil` e o Scapy
   podem usar nomes diferentes no Windows.
3. Essa função percorre `psutil.net_if_addrs()` e procura um endereço IPv4 com
   máscara.
4. Monta a rede com `IPv4Network(f"{ip}/{mascara}", strict=False)`.
5. Se o `psutil` não estiver disponível ou não achar a máscara, usa
   `get_if_addr(interface)` e assume `/24` como último recurso.

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
| `tempo_limite` | `float`                        | `1.0`  | Segundos de espera por resposta. Deve ser maior que zero.                        |
| `tentativas`   | `int`                          | `2`    | Quantas vezes reenviar requisições sem resposta.                                 |
| `intervalo`    | `float`                        | `0.0`  | Intervalo entre pacotes, em segundos.                                            |

**Dica de confiabilidade:** em redes Wi-Fi ou com muitos dispositivos, use
`tempo_limite=2.0`, `tentativas=2` e `intervalo=0.01`. Com os valores padrão,
algumas respostas podem ser perdidas.

**Retorno:** `{ip: [macs]}`. IPs sem resposta ARP não entram no dicionário.

**Exceções:**

- `ValueError`: parâmetro inválido, IP malformado ou rede malformada.
- `RuntimeError`: interface sem IPv4 válido, falta de permissão ou falta do
  Npcap no Windows.

**Como funciona:**

1. Valida `tempo_limite`, `tentativas` e `intervalo`.
2. Chama `_resolver_ips_alvo` para obter a lista de IPs e a interface.
3. Se a lista estiver vazia, retorna `{}`.
4. Chama `_enviar_requisicoes_arp` para enviar os pacotes e interpretar respostas.
5. Ordena os IPs numericamente e os MACs alfabeticamente.

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

| Parâmetro        | Tipo                          | Descrição                              |
| ---------------- | ----------------------------- | -------------------------------------- |
| `resultados_arp` | `Mapping[str, Iterable[str]]` | Resultado de `varrer_rede_arp`.        |
| `ips_ativos`     | `Iterable[str]`               | IPs que o módulo ICMP encontrou vivos. |

**Retorno:** subconjunto de `resultados_arp` cujos IPs não estão em
`ips_ativos`.

**Como funciona:**

1. Normaliza `ips_ativos` com `IPv4Address` para comparar strings canônicas.
2. Percorre `resultados_arp` e mantém apenas os IPs que não aparecem em
   `ips_ativos`.

**Exemplo:**

```python
from src.scanner.arp import filtrar_bloqueados_icmp, varrer_rede_arp

resultados_arp = varrer_rede_arp()
ips_ativos = {"192.168.0.1", "192.168.0.11"}

bloqueados = filtrar_bloqueados_icmp(resultados_arp, ips_ativos)
```

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

#### `_resolver_interface(interface) -> str`

**Objetivo:** garantir uma interface concreta.

**Como funciona:**

```python
if interface:
    return interface
return conf.route.route("0.0.0.0")[0]
```

Se o usuário passou uma interface, usa ela. Caso contrário, usa a interface da
rota padrão. Não usa `conf.iface` para evitar o problema da VPN descrito em
`obter_rede_local`.

#### `_obter_rede_do_sistema(interface) -> str | None`

**Objetivo:** tentar obter a rede IPv4 da interface via `psutil`.

**Como funciona:**

1. Se o `psutil` não estiver disponível, retorna `None`.
2. Percorre os nomes candidatos da interface.
3. Para cada endereço IPv4 com máscara, monta `IPv4Network(ip/máscara)` e
   retorna o CIDR.
4. Se não achar nada, retorna `None` para o `obter_rede_local` usar a
   alternativa `/24`.

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

1. Se `alvos` foi fornecido, normaliza os IPs com `_normalizar_ips_alvo`.
2. Se `alvos` não foi fornecido:
   - se `rede` também não foi, chama `obter_rede_local`;
   - caso contrário, resolve a interface.
3. Chama `_ips_utilizaveis_da_rede(rede)` para gerar os IPs utilizáveis.

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

Usa `IPv4Network(rede, strict=False).hosts()`, que exclui endereço de rede e
broadcast.

**Por que `strict=False`:** permite receber um IP de host com prefixo, como
`192.168.0.73/24`, e normalizar para `192.168.0.0/24`.

#### `_validar_parametros_da_varredura(tempo_limite, tentativas, intervalo) -> None`

**Objetivo:** validar os parâmetros de tempo e tentativas.

- `tempo_limite <= 0` → `ValueError`.
- `tentativas < 0` → `ValueError`.
- `intervalo < 0` → `ValueError`.

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

3. Trata erros:
   - `PermissionError`: o Npcap/driver negou o acesso; normalmente ocorre em
     instalação “admin-only” ou quando falta permissão.
   - `RuntimeError` com “winpcap” ou “layer 2”: Npcap não instalado ou camada 2
     indisponível.
4. Chama `_agrupar_respostas_por_ip`.

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

### 3.13 `__main__`

O bloco final permite testar o módulo manualmente:

```powershell
.\.venv\Scripts\python.exe -m src.scanner.arp
```

Ele chama `varrer_rede_arp()` e imprime IP, MACs e o marcador `<-- CONFLITO` quando
um IP tem mais de um MAC.

---

## 4. Integração com o ICMP

O contrato sugerido com o módulo ICMP é:

```python
from ipaddress import IPv4Network

from src.scanner.arp import (
    encontrar_conflitos,
    filtrar_bloqueados_icmp,
    varrer_rede_arp,
)
from src.scanner.icmp import ping_sweep

rede = "192.168.0.0/24"
interface = "Ethernet"

alvos = [str(endereco_ip) for endereco_ip in IPv4Network(rede).hosts()]

ips_ativos_icmp = ping_sweep(alvos, timeout=1.0)
resultados_arp = varrer_rede_arp(alvos, interface=interface)

bloqueados = filtrar_bloqueados_icmp(resultados_arp, ips_ativos_icmp)
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

Se a função da outra pessoa tiver outro nome ou outro retorno, só adapta essa
parte; o `arp.py` não precisa mudar.

---

## 5. Testes

Os testes unitários estão em [`tests/test_arp.py`](../tests/test_arp.py) e não
acessam a rede: o `srp` do Scapy é substituído por um fake. Atualmente são
**8 testes**.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_arp.py -v
```

Cobertura atual:

- agrupamento de dois MACs no mesmo IP;
- ignorar pacotes que não são resposta ARP;
- geração de alvos a partir de uma rede `/30`;
- cruzamento com ICMP;
- detecção de conflito de IP;
- detecção de MAC duplicado em IPs diferentes;
- caminho completo do `varrer_rede_arp` com `srp` mockado;
- rejeição de `tempo_limite` inválido.

O bloco `__main__` não é coberto pelo `pytest`; ele serve para teste manual.

---

## 6. Limitações e cuidados

1. **Npcap no Windows.** ARP é camada 2; sem Npcap não funciona. A instalação
   do Npcap pode ser restrita a administradores (opção “Restrict Npcap driver's
   access to Administrators only”); nesse caso, também é preciso rodar como
   admin. Em instalações sem essa restrição, um usuário comum pode conseguir
   usar. O código detecta a falha e mostra uma mensagem clara.
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
6. **`obter_rede_local` é uma alternativa de conveniência.** No projeto
   final, o ideal é usar o `src/network/interfaces.py` do grupo e passar
   `interface`/`rede` explicitamente.
7. **Não altere o `device.py` sozinho.** O retorno é um dicionário; a camada
   de integração/UI decide como transformar em `Device` e como mostrar o
   status “ICMP bloqueado” ou “conflito”.
