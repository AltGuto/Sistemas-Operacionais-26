# Protocolo e transporte — Pessoa 1

## Escopo e fontes

Esta camada conecta o controlador (cliente TCP) ao agente (servidor TCP), transporta
mensagens e encaminha ações autorizadas. Base: leitura integral dos documentos
`ACORDOS_iniciais_Admin_Remota_Sockets.pdf` (8 páginas) e
`Divisao_Responsabilidades_Entregas.pdf` (7 páginas), versão 1.0 de 28/10/2026.
Os PDFs são referências do contrato do grupo; este módulo não implementa as tarefas
atribuídas aos demais integrantes.

Porta padrão: **5000**, configurável. Ambiente acordado: **Windows 10/11 e Python
3.15.2**. A implementação utiliza apenas a biblioteca padrão. No ambiente desta
entrega havia Python 3.13.16 e 3.14.8; a validação em 3.15.2 continua pendente, sem
alterar a decisão do grupo. Compatibilidade de PyAutoGUI e outras dependências dos
colegas deve ser conferida pelo grupo na versão acordada.

Uma sessão por agente; um comando pendente por conexão. O endereço padrão é
`127.0.0.1`, permitindo testes locais. Para o laboratório, a inicialização integrada
deve configurar explicitamente o endereço privado, TLS, autenticação, aviso e logs.
Importar `agent.main` não inicia servidor nem executa ações.

## Fluxo de sessão

1. A inicialização manual integrada cria `AgentServer` e chama `start()`.
2. `Connection.connect()` abre TCP na thread de rede; a camada da Pessoa 4 estabelece
   TLS e valida o certificado do agente antes de liberar o socket.
3. O controlador envia `AUTH` pelo canal TLS. A Pessoa 4 lê e compara o segredo
   compartilhado configurado localmente; o transporte não verifica tokens.
4. Somente após `authenticate(args) is True` **e** `is_authorized() is True`, a sessão
   libera handlers funcionais. A autorização é consultada novamente a cada ação.
5. O controlador aguarda a resposta correlacionada antes de iniciar outro comando.
   Eventos de arquivos podem circular durante essa espera.
6. `CLOSE {}` recebe confirmação e fecha a sessão. O listener continua disponível.
   Uma falha de AUTH responde `AUTH_FAILED` e fecha a conexão.
7. `disconnect()` no cliente ou `stop()` no agente interrompe localmente a rede.
   O kill switch da Pessoa 3 é independente de uma solicitação CLOSE.

No teste isolado, TCP sem TLS permite somente `PING` e `CLOSE`. O cliente recusa
enviar AUTH/ações funcionais em texto aberto. O agente recusa AUTH sem TLS e não
chama a fábrica de segurança nesse canal. Não existe flag de produção para ignorar
TLS/autorização, token embutido ou implementação fictícia de autenticação.

## Framing

```text
[4 bytes: N unsigned big-endian][N bytes: JSON UTF-8]
```

`N` mede **bytes UTF-8**, não caracteres. Intervalo aceito: 1 a 8.388.608 bytes
(8 MiB), inclusive. Cabeçalho zero é inválido; tamanho acima do limite é recusado
antes de ler/alocar o corpo. Qualquer sequência de quatro bytes representa um
unsigned; a validade depende desse intervalo. Não há delimitador de linha.

`recv_exact()` acumula leituras até obter o tamanho pedido. A leitura do cabeçalho
não consome o início do corpo; a leitura do corpo não consome a próxima mensagem.
Por isso, fragmentos e mensagens agrupadas no mesmo fluxo são suportados.
`sendall()` envia o frame completo. EOF no cabeçalho ou corpo encerra a sessão.

Um prazo absoluto baseado em `time.monotonic()` cobre cabeçalho e corpo; receber
um fragmento não renova esse prazo. Após timeout ou leitura parcial, a conexão é
fechada, pois continuar poderia perder o alinhamento do fluxo.

## Envelope

| Campo | Tipo e regra |
| --- | --- |
| `id` | String UUID na forma hifenizada; novos IDs usam UUID4. |
| `tipo` | `comando`, `resposta` ou `evento`. |
| `acao` | String não vazia; nomes do catálogo abaixo são sensíveis a maiúsculas. |
| `args` | Objeto JSON. Argumentos de domínio são validados pelo handler responsável. |
| `timestamp` | String ISO 8601 com data/hora e UTC (`Z` ou offset zero); emissão usa `Z`. |

Campos adicionais não substituem os obrigatórios. São rejeitados tipos incorretos,
UUIDs inválidos, timestamps sem fuso ou fora de UTC, chaves JSON duplicadas, UTF-8
inválido, JSON excessivamente aninhado e valores não JSON, incluindo NaN/Infinity.
IDs e ações das respostas devem repetir **exatamente** os da solicitação. O cliente
fecha a conexão diante de resposta inesperada ou sem comando pendente.

```json
{
  "id": "2d916cef-60b5-4fd8-90d0-297d2bade0f7",
  "tipo": "comando",
  "acao": "PING",
  "args": {},
  "timestamp": "2026-10-28T22:30:00Z"
}
```

```json
{
  "id": "2d916cef-60b5-4fd8-90d0-297d2bade0f7",
  "tipo": "resposta",
  "acao": "PING",
  "args": {"ok": true, "resultado": {"pong": true}, "erro": null},
  "timestamp": "2026-10-28T22:30:01Z"
}
```

Exemplo de falha (em resposta a um comando SYSINFO com esse ID):

```json
{
  "id": "2d916cef-60b5-4fd8-90d0-297d2bade0f7",
  "tipo": "resposta",
  "acao": "SYSINFO",
  "args": {
    "ok": false,
    "resultado": null,
    "erro": {"codigo": "NOT_AUTHORIZED", "mensagem": "Sessão não autorizada."}
  },
  "timestamp": "2026-10-28T22:30:01Z"
}
```

Em sucesso, `ok` é booleano verdadeiro, `erro` é null e `resultado` é um valor JSON
do handler. Em falha, `ok` é falso, `resultado` é null e `erro` contém strings não
vazias `codigo`/`mensagem`. O transporte cria o envelope; handlers retornam apenas
o resultado, sem criar respostas completas.

## Catálogo obrigatório

| Ação | `args` do contrato | Resultado/responsável |
| --- | --- | --- |
| `AUTH` | Token compartilhado, somente dentro do TLS. Chave `token` a confirmar com P4. | P4 autentica; adaptador retorna `{"authenticated": true}` no sucesso. |
| `EXEC` | `{"cmd": "whoami"}` | P2: `stdout`, `stderr`, `codigo_saida`; sem elevação. |
| `SYSINFO` | `{}` | P2: SO, usuário, hostname, CPU, memória e discos. |
| `LS` | `{"path": "."}` | P2: nome, tipo, tamanho e data de modificação. |
| `GET` | `{"path": "relatorio.txt"}` | P2: arquivo do agente para controlador, via eventos. |
| `PUT` | `{"path": "entrada.txt", "size": 123, "sha256": "..."}` | P2: arquivo do controlador para agente, via eventos. |
| `MOUSE_MOVE` | `{"x": 840, "y": 410, "abs": true}` | P3: posição absoluta ou relativa. |
| `MOUSE_CLICK` | `{"button": "left", "double": false}` | P3: left/right/middle, simples/duplo. |
| `MOUSE_SCROLL` | `{"dx": 0, "dy": 120}` | P3: rolagem horizontal/vertical. |
| `KEY` | `{"text": "ola"}` ou `{"combo": ["ctrl", "c"]}` | P3: texto ou combinação na sessão visível. |
| `PING` | `{}` obrigatório | P1: `{"pong": true}`. |
| `CLOSE` | `{}` obrigatório | P1: `{"closed": true}`, seguido do fechamento. |

São preservados os nomes e exemplos dos PDFs. Os PDFs descrevem vários resultados
por significado, sem um esquema JSON completo; as chaves finais desses resultados
e de AUTH devem ser confirmadas com seus responsáveis. O transporte não inventa
esses esquemas nem valida caminhos, teclas ou comandos. RF9–RF12 estão fora do
registro de handlers desta entrega.

## Eventos de arquivos

São envelopes com `tipo: "evento"`, usando o mesmo framing, UUID e timestamp:

| Evento | Conteúdo determinado nos PDFs |
| --- | --- |
| `FILE_META` | `transfer_id`, nome, tamanho total, número esperado de blocos, SHA-256. |
| `FILE_CHUNK` | `transfer_id`, índice sequencial, `data_b64`. |
| `FILE_END` | Tamanho final e SHA-256 calculado no emissor. |

Blocos têm até **131.072 bytes originais (128 KiB)**. Um bloco cheio ocupa 174.764
caracteres Base64, mais o envelope, abaixo de 8 MiB. O SHA-256 cobre o arquivo
completo. P2 confere tamanho/hash, ordem, duplicatas, ausências, limites, caminhos
relativos e gravação em `.part` antes da renomeação final.

Os PDFs não fixam as chaves literais de todos os metadados (por exemplo, índice,
nome e contagem de blocos) nem a relação entre UUID do evento e ID do comando.
Esses detalhes precisam ser fechados com P2/P4 antes da integração de arquivos.
Esta camada preserva `args` e aceita tanto UUID próprio quanto um UUID explicitamente
fornecido no evento; não impõe uma segunda correlação à de `transfer_id`.

Durante GET, o handler pode emitir eventos por `session.send_event()`. Durante PUT,
o handler pode ler eventos por `session.receive_event()`, enquanto o cliente usa
`Connection.send_event()`. Os eventos antecedem a resposta final do comando. Eventos
recebidos fora do contexto esperado pelo agente encerram a sessão. Nenhuma leitura,
gravação de arquivo, codificação Base64 ou verificação SHA-256 é feita pelo transporte.
Uma transferência longa precisa de timeout configurado de acordo com seu tamanho.

## Erros e limites da sessão

| Código da resposta | Condição |
| --- | --- |
| `INVALID_ARGS` | PING/CLOSE com argumentos não vazios. |
| `TLS_REQUIRED` | AUTH recebido sem TLS; conexão fechada após a resposta. |
| `AUTH_FAILED` | Autenticador ausente, rejeição ou falha de autenticação; fecha a sessão. |
| `NOT_AUTHORIZED` | Sem AUTH bem-sucedido, autorização revogada ou erro no autorizador. |
| `UNKNOWN_ACTION` | Ação fora do catálogo, em sessão autorizada. |
| `NOT_IMPLEMENTED` | Ação obrigatória ainda sem handler registrado. |
| `HANDLER_ERROR` | Exceção inesperada ou resultado inválido/excessivo do handler. |
| `INVALID_EVENT` | Handler tentou emitir evento fora dos três eventos de arquivo. |

Handlers podem levantar `ActionError(codigo, mensagem)` com conteúdo público e
seguro. A mensagem de uma exceção inesperada **não** é devolvida: ela pode conter
segredos. Framing inválido, JSON inválido, EOF, timeout, erro de socket e eventos fora
de ordem encerram somente a conexão afetada; o listener permanece ativo. Não se
tenta responder usando IDs extraídos de um envelope inválido.

Exceções locais: `InvalidMessage`, `InvalidHeader`, `MessageTooLarge`,
`ConnectionClosed`, `ProtocolTimeout`, `UnexpectedResponse` (todas `ProtocolError`).
`IdleTimeout` especializa `ProtocolTimeout` quando nenhum byte de um novo frame
chegou: sem comando pendente, o loop pode continuar, inclusive após registros de
controle internos do TLS. Timeout depois de qualquer byte do cabeçalho ou durante
o corpo sempre encerra a sessão. Erros locais de SO levantados por um handler são
convertidos em `HANDLER_ERROR`; erros de rede nos métodos Session encerram a sessão.
Erros do sistema de sockets também podem ser `OSError`; os loops de sessão os tratam.

Timeout padrão: 5 segundos, configurável. O cliente limita o tempo entre envio do
comando e resposta final; eventos não renovam esse prazo. Leituras de frames têm
prazo total. Sessões ociosas sem comando pendente não expiram por esse timeout.
Não há reconexão ou repetição automática: uma ação pode ter sido executada antes
da queda, e repeti-la poderia duplicar seus efeitos.

## API de integração

### `common.protocol` — todos os integrantes

- `new_message(action, args=None, kind="comando", request_id=None)`.
- `success_response(request, result)` / `error_response(request, code, message)`.
- `validate_message(message)` e `correlate_response(response, request)`.
- `encode_message(message)` devolve frame completo; `decode_message(body)` recebe
  **somente o corpo**, sem o cabeçalho.
- `encode_header(size)`, `decode_header(header)`, `recv_exact(sock, size)`.
- `send_message(sock, message)` / `recv_message(sock, deadline=None)`.
- `DEFAULT_PORT`, `MAX_BODY_SIZE`, `FILE_CHUNK_SIZE`, `FILE_EVENTS`.

As funções de socket são bloqueantes e pertencem à thread de rede. Os handlers
usam o contexto Session, sem abrir sockets ou ler diretamente do socket compartilhado.

### `controller.connection.Connection` — Pessoa 4 / interface

```python
from controller.connection import Connection

# envolver_tls_cliente é fornecido pela Pessoa 4: faz handshake e valida certificado.
connection = Connection(host="127.0.0.1", port=5000,
                        timeout=5.0, tls_wrapper=envolver_tls_cliente)
connection.connect()  # Retorna sem aguardar DNS/TCP/TLS.
```

Alternativamente, `connect(connected_socket=socket_tls_validado)` transfere a posse
de um socket já estabelecido pela Pessoa 4. Nesse caso, não fornecer wrapper que
faça outro handshake. Configuração TLS, CA/certificado esperado e hostname pertencem
à Pessoa 4; não há desativação de validação neste código.

Depois do aviso `connected`, a UI solicita AUTH com os argumentos definidos pela
Pessoa 4 e aguarda a resposta de sucesso antes de enviar ações funcionais.
`request(action, args)` retorna imediatamente o UUID; rejeita um segundo comando
pendente com `RuntimeError`. O estado `connected` indica transporte pronto, não
autenticação concluída. `state` vale `connecting`, `connected` ou `disconnected`.

A UI consulta `inbox.get_nowait()` em seu ciclo `after()`; não usa `recv()`/`join()`.
Itens da fila:

| `kind` | Campos adicionais |
| --- | --- |
| `connected` | Transporte pronto. |
| `response` | `message`: envelope da resposta validada/correlacionada. |
| `event` | `message`: envelope FILE_META/FILE_CHUNK/FILE_END. |
| `error` | `code`: classe da falha, `id`: comando pendente ou null, `message`: texto público. |
| `disconnected` | Fim da sessão; cancelar estado pendente na interface. |

`send_event(action, args, event_id=None)` enfileira eventos durante uma requisição;
o módulo de arquivos do controlador deve tratar `queue.Full` e aguardar consumo,
sem bloquear a UI. A fila de envio suporta 16 itens; a de recepção, 128. Se a UI não
consumir a fila de recepção, a conexão termina com erro; avisos terminais podem
substituir itens antigos. Não se deve confirmar uma transferência após overflow.
O transporte faz uma cópia JSON dos argumentos antes de enfileirá-los.

`disconnect()` cancela e fecha o socket sem esperar a thread. Para desligamento
fora da thread gráfica/testes, `wait_closed(timeout)` devolve se a thread terminou.
Cada instância é de uso único; uma reconexão usa outra `Connection` e novo AUTH.

### `agent.main.AgentServer` — integração do agente

```python
from agent.main import AgentServer

server = AgentServer(
    host="127.0.0.1", port=5000, timeout=5.0,
    handlers={"SYSINFO": handler_sysinfo, "LS": handler_ls},
    tls_wrapper=envolver_tls_servidor,
    security_factory=criar_seguranca_da_sessao,
)
server.start()
```

Os nomes acima são pontos de integração, não implementações incluídas nesta entrega.
Registre handlers no construtor antes de iniciar; não altere o dicionário durante
uma sessão. PING/CLOSE/AUTH não podem ser sobrescritos por esse registro.

- `tls_wrapper(raw_socket) -> SSLSocket`: P4 devolve canal após handshake; deve
  respeitar o timeout e fechar qualquer socket intermediário se o handshake falhar.
- `security_factory(tls_socket, peer) -> SecuritySession`: P4 cria **um novo estado
  por conexão**, com `authenticate(args) -> bool`, `is_authorized() -> bool` e
  `close() -> None`. O factory só é chamado após TLS. Não retornar autorização
  baseada apenas no endereço do controlador.
- `handler(args, session) -> valor JSON`: P2/P3 implementam ou adaptam suas funções
  locais, por exemplo `lambda args, session: funcao_local(args)`.
- `session.peer`: endereço do controlador; `session.stopping`: `threading.Event`
  para cancelamento cooperativo; `session.authorized()`: consulta à autorização.
- `session.send_event(action, args, event_id=None)` e `session.receive_event()`:
  usar na própria thread do handler; ambos exigem autorização.
- `start() -> (host, port)`: inicia listener em thread; porta zero serve para testes.
- `stop()`: fecha listener e conexão ativa; `wait_closed(timeout)`: aguarda recursos.

Existe uma thread de listener e no máximo uma de sessão ativa. O listener fecha
imediatamente conexões adicionais. Um handler termina antes de ler o próximo comando.
Handlers devem respeitar cancelamento e ter tempos de execução limitados: Python
não permite interromper à força uma função arbitrária que bloqueie para sempre.
`wait_closed()` retorna falso se algum callback/handler não terminou. DNS e callbacks
TLS também precisam de comportamento limitado pela camada responsável.

`server.notices` fornece metadados `connected`, `refused`, `response`, `error` e
`disconnected`, com `peer` e, quando aplicável, ID, ação, sucesso e código. Nunca
inclui `args`, tokens ou blocos. É uma fila de diagnóstico limitada (128); avisos
excedentes são descartados. P3/P4 devem consumir e combinar esses avisos com seus
próprios mecanismos de aviso permanente, auditoria e desligamento. Esta fila **não
é um log persistente nem substitui o aviso obrigatório**.

### TLS/AUTH e pendências da Pessoa 4

O contrato define certificado local do agente, certificado público esperado no
controlador, token aleatório compartilhado em configuração local e comparação
segura (ex.: `hmac.compare_digest`). O token só atravessa TLS; falha é registrada sem
revelá-lo e encerra a sessão. Detalhes de certificado, hostname, caminhos de
configuração, formato exato de AUTH e registro de logs devem ser confirmados com P4.
Esta implementação entrega os pontos de conexão e nega acesso na ausência deles.

## Teste isolado

Na raiz do repositório, sem dependências externas:

```powershell
python -X utf8 -W error::ResourceWarning -m unittest discover -s tests -v
```

Os testes abrem somente sockets locais/portas efêmeras e usam funções fictícias.
Não executam comandos do SO, não controlam entrada e não acessam arquivos pessoais.
O teste `test_ping_and_close` demonstra TCP real entre controlador e agente.
`test_handler_forwarding_after_auth` demonstra o encaminhamento com segurança
simulada. `test_file_events_in_both_directions_during_request` demonstra o transporte
bidirecional de eventos sem implementar transferência de arquivos.

Os doubles `simulated_tls`/`simulated_security` existem **somente em tests/**.
Eles não fazem criptografia nem comprovam validação real de certificados. Testes
TLS reais, integração dos handlers, aviso, logs e demonstração final pertencem à
integração do grupo. Resultados executados e matriz de aceite:
[entrega_pessoa1.md](entrega_pessoa1.md).
