# Entrega da Pessoa 1

Data de referência: 14/11/2026 (America/Sao_Paulo).

## Inspeção e plano aplicado

Repositório: `Sistemas-Operacionais-26`, remoto já existente
`https://github.com/AltGuto/Sistemas-Operacionais-26.git`.
A inspeção encontrou somente `README.md`, commit `c8348d5` (`Initial commit`), branch
`main`, sem mudanças locais. Não havia código, framework de testes, dependências ou
AGENTS.md no projeto. `agent/main.py` ainda não existia; nenhum código compartilhado
precisou ser substituído.

Foram lidos integralmente os dois PDFs fornecidos: decisões técnicas (8 páginas) e
divisão de responsabilidades (7 páginas). O plano foi criar, nesta ordem: protocolo
comum, transporte do controlador, servidor/encaminhamento, testes e documentação.
Não havia implementação reutilizável. Integrações de domínio e segurança ficaram
explicitamente reservadas aos colegas.

O executável Git não estava no PATH; os comandos Git foram executados por
`C:\Program Files\Git\cmd\git.exe`. Um leitor de PDF foi instalado em pasta
temporária externa ao repositório exclusivamente para ler os documentos; não é
dependência da aplicação.

## Arquivos entregues

| Arquivo | Implementação |
| --- | --- |
| `common/protocol.py` | JSON UTF-8, framing, limites, envelope, UUID/UTC, respostas, correlação e erros controlados. |
| `controller/connection.py` | Cliente TCP em thread, filas limitadas, timeout, eventos, cancelamento e socket TLS fornecido por P4. |
| `agent/main.py` | Listener, uma sessão ativa, PING/CLOSE, registro de handlers e autorização negada por padrão. |
| `tests/test_protocol.py` | 24 testes de protocolo e leitura. |
| `tests/test_transport.py` | 37 testes de transporte, sessões e interfaces simuladas. |
| `docs/protocolo.md` | Especificação e API de integração. |
| `docs/relatorio_pessoa1.md` | Texto separado para o relatório acadêmico. |
| `docs/entrega_pessoa1.md` | Este registro de evidências e pendências. |
| `.gitignore` | Exclusão de caches, configurações locais, logs, transferências e formatos de chaves privadas. |

README e módulos das Pessoas 2, 3 e 4 não foram alterados. Não foram implementados
comandos reais, arquivos, mouse/teclado, TLS, verificação de token, UI ou opcionais.

## Testes executados

Executados na raiz do repositório em Windows:

```powershell
python -X utf8 -W error::ResourceWarning -m unittest discover -s tests -v
py -3.14 -X utf8 -W error::ResourceWarning -m unittest discover -s tests -v
```

| Ambiente efetivo | Resultado final | Duração reportada pelo unittest |
| --- | --- | --- |
| Python 3.13.16 (`python`) | 61 executados, 61 aprovados, 0 falhas/erros | 3,042 s |
| Python 3.14.8 (`py -3.14`) | 61 executados, 61 aprovados, 0 falhas/erros | 2,987 s |

O desenvolvimento teve uma primeira suíte de 49 testes aprovada. Ao acrescentar
oito casos de revisão, uma verificação foi inserida no teste errado, causando um
erro nas duas versões. O teste foi corrigido e ambas as suítes de 57 casos passaram.
A revisão acrescentou quatro testes para erros locais de handlers e distinção entre
espera sem início de frame e leitura parcial, incluindo a simulação de registros
de controle TLS. As suítes completas de 61 casos tiveram os resultados finais acima.
Nenhum teste foi omitido
ou marcado como sucesso sem execução.

Os sockets dos testes usam loopback/portas efêmeras ou socketpair. A segurança é
simulada somente em `tests/`, sem certificados ou segredos reais. Não houve acesso a
arquivos pessoais, execução de comandos remotos ou automação de mouse/teclado.
Os testes de teardown verificam o término das threads e o encerramento das sessões.
Nenhum ResourceWarning foi emitido nas execuções finais.

## Matriz dos 20 requisitos de teste

| Requisito | Evidência em testes |
| --- | --- |
| 1. Serialização/desserialização | `test_json_utf8_roundtrip` |
| 2. Cabeçalho big-endian | `test_header_big_endian` |
| 3. Fragmentação | `test_fragmented_header_and_body` |
| 4. Mensagens agrupadas | `test_coalesced_messages`, `test_real_socket_grouped_frames` |
| 5. Corpo dentro do limite | `test_body_exactly_at_limit` (exatos 8 MiB) |
| 6. Corpo acima de 8 MiB | `test_oversized_body_send_and_receive` |
| 7. Cabeçalho truncado/inválido | `test_invalid_header`, `test_eof_at_every_header_position` |
| 8. JSON malformado | `test_malformed_json_and_utf8` |
| 9. Campos ausentes | `test_missing_fields` |
| 10. Tipos incorretos | `test_wrong_field_types`, `test_invalid_response_shapes` |
| 11. ID preservado | `test_response_correlation`, `test_ping_and_close` |
| 12. ID inesperado | `test_unexpected_response_id_and_action` |
| 13. Queda no cabeçalho | `test_eof_at_every_header_position`, `test_disconnect_during_header_or_body` |
| 14. Queda no corpo | `test_eof_during_body`, `test_disconnect_during_header_or_body` |
| 15. Timeout | `test_connection_timeout`, `test_response_timeout`, `test_socket_read_timeout` |
| 16. PING | `test_ping_and_close` |
| 17. CLOSE | `test_ping_and_close`, `test_ping_close_require_empty_args` |
| 18. Handler simulado | `test_handler_forwarding_after_auth` |
| 19. Bloqueio sem autorização | `test_all_functional_actions_denied_without_security`, `test_authorizer_cannot_skip_auth` |
| 20. Encerramento/recursos | `test_stop_interrupts_idle_session_and_listener`, `test_disconnect_cancels_pending_read`, teardown de todos os testes de transporte |

Casos adicionais cobrem revogação de autorização, falhas dos wrappers TLS, limpeza
da segurança, resposta não solicitada, prazo absoluto entre fragmentos, eventos
bidirecionais, isolamento entre sessões e listener disponível após mensagem inválida.

## Critérios de aceite e limites

Atendidos isoladamente: troca de mensagens fictícias, framing fragmentado/agrupado,
validação de IDs/formatos, PING/CLOSE, tratamento de falhas por sessão, encerramento
dos sockets/threads nos cenários testados, bloqueio de todos os handlers funcionais
sem autorização, registro de handlers, testes executados e interfaces documentadas.

Pendências de integração, sem bloquear a entrega isolada da Pessoa 1:

- **Pessoa 2:** adaptar handlers para `(args, session)`, definir as chaves restantes
  dos eventos, validar arquivos, blocos/Base64, SHA-256 e caminhos. O protocolo já
  transporta os três eventos; não há transferência funcional implementada aqui.
- **Pessoa 3:** integrar handlers de entrada, aviso permanente, início manual e
  kill switch com `server.stop()`. Handlers longos precisam observar cancelamento.
- **Pessoa 4:** fornecer wrappers TLS validados, `SecuritySession` por conexão,
  formato definitivo de AUTH, configuração local, logs e consumo das filas pela UI.
  Combinar mudanças futuras em `agent/main.py` antes de integrar.
- **Grupo:** validar Python 3.15.2 e dependências. Essa versão não está instalada
  neste ambiente; a decisão do documento foi preservada. Testes em 3.13/3.14 não
  substituem a validação acordada nem comprovam compatibilidade de PyAutoGUI.

O protocolo documenta lacunas dos PDFs sem impor nomes não definidos. A garantia
de cancelamento não se estende a handlers externos que bloqueiem indefinidamente;
essa limitação e os contratos de timeout estão descritos na especificação.

## Git e proposta de publicação

Branch de contribuição: `feature/pessoa1-protocolo-tcp`, criada a partir de `main`.
Remoto `origin` preservado. Nenhum commit, push, merge ou rebase foi realizado.
Não foi executado fetch; o estado atual do remoto não foi atualizado nesta sessão.

Os nove arquivos novos foram marcados com `git add --intent-to-add` apenas para
permitir revisão por `git diff`; não há conteúdo preparado em `git diff --cached`.
A revisão incluiu código, testes e documentos. `git diff --check` terminou sem
erros, e `git diff -- README.md` confirmou que o README permanece intacto. A busca
por padrões de chaves privadas e credenciais não encontrou ocorrências; a entrega
não contém arquivos de logs, certificados privados ou configuração secreta. O único
valor de token nos testes é um marcador fictício, usado para comprovar que AUTH
não é enviado em texto aberto.

Mensagem sugerida de commit:

```text
feat: implementa protocolo TCP e sessões da Pessoa 1
```

Descrição sugerida para a contribuição:

> Implementa framing JSON UTF-8, validação de envelopes, cliente assíncrono e servidor
> de sessão única com PING/CLOSE. Expõe registro de handlers e integração com TLS/AUTH,
> mantendo ações funcionais bloqueadas sem autorização. Inclui documentação do
> protocolo, seção acadêmica e 61 testes aprovados em Python 3.13.16 e 3.14.8.
> A integração real de segurança e a validação em Python 3.15.2 permanecem pendentes.

A publicação depende da autorização explícita do usuário para commit/push,
conforme o pedido original. Antes de integrar com a branch compartilhada, revisar
eventuais mudanças dos colegas em `agent/main.py` e resolver a integração em conjunto.

## Material a fornecer à Pessoa 4

Entregar `docs/protocolo.md`, `docs/relatorio_pessoa1.md`, este registro e os testes.
A seção acadêmica aborda arquitetura cliente-servidor, sockets, fluxo de bytes,
framing, JSON, threads, sincronização e tratamento de falhas. A Pessoa 4 pode usar
a matriz de testes no roteiro consolidado e o teste PING/CLOSE como base da
demonstração da comunicação. README, roteiro coletivo e relatório final continuam
sob responsabilidade de consolidação da Pessoa 4.
