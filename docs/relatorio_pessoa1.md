# Contribuição da Pessoa 1 ao relatório técnico

Texto separado para consolidação pela Pessoa 4; não substitui as seções dos colegas.

## Arquitetura cliente-servidor e sockets TCP

A ferramenta adota uma arquitetura cliente-servidor. O controlador inicia a conexão
TCP e solicita ações, enquanto o agente escuta na porta configurada, cujo padrão é
5000. Cada agente mantém uma sessão de controle por vez. Essa restrição simplifica
a sincronização e evita a execução simultânea de comandos de controladores distintos.
O servidor continua disponível após o encerramento de uma sessão e recusa conexões
adicionais enquanto existe um controlador ativo.

Sockets oferecem a interface entre os processos da aplicação e a pilha de rede do
sistema operacional. No agente, as operações bind, listen e accept estabelecem o
listener e o socket da sessão; no controlador, connect estabelece a comunicação.
Os dados são enviados e recebidos pelos sockets da sessão, cuja liberação usa
shutdown e close no encerramento normal ou em falhas.

## Fluxo de bytes e framing

TCP entrega um fluxo ordenado de bytes, sem preservar as fronteiras das chamadas
de envio. Uma mensagem pode chegar em várias leituras, e uma leitura pode conter
dados de mensagens consecutivas. Por esse motivo, a implementação não considera
cada recv como uma mensagem completa.

O protocolo utiliza um cabeçalho de quatro bytes com inteiro unsigned em ordem
big-endian, indicando o tamanho do corpo. O receptor primeiro lê os quatro bytes
completos e depois acumula exatamente a quantidade indicada. Essa estratégia
reconstrói mensagens fragmentadas e deixa no fluxo os bytes da próxima mensagem.
O limite de 8 MiB por corpo evita aceitar tamanhos arbitrários anunciados pelo par.
Uma interrupção antes de completar o frame encerra a sessão, pois o restante do
fluxo não pode ser interpretado de maneira confiável.

## Serialização e identificação das mensagens

Os corpos são objetos JSON codificados em UTF-8. O envelope comum contém id, tipo,
acao, args e timestamp. A aplicação gera UUIDs para identificar solicitações e usa
timestamps UTC para representar o instante de criação das mensagens. A resposta
preserva o identificador e a ação originais, permitindo confirmar que corresponde
ao comando pendente.

A validação verifica os campos obrigatórios e seus tipos, o formato do UUID, o
timestamp UTC e a estrutura das respostas. JSON malformado, chaves duplicadas e
valores incompatíveis são rejeitados. Respostas de sucesso contêm ok verdadeiro,
resultado e erro nulo; respostas de falha contêm ok falso, resultado nulo e um erro
com código e mensagem públicos. A validação de argumentos de domínio permanece
nos módulos de sistema, arquivos e entrada.

## Threads e sincronização

O controlador executa conexão, envio e recebimento em uma thread de rede separada
da futura interface Tkinter. Filas thread-safe levam solicitações à rede e devolvem
respostas, eventos e mudanças de estado à interface. Um lock protege o estado da
conexão e a identificação da requisição pendente. A interface pode consultar a fila
periodicamente, sem bloquear seu loop de eventos em uma leitura de socket.

No agente, uma thread mantém o listener e outra atende a única sessão ativa.
Os handlers são chamados sequencialmente, mantendo uma requisição por vez. Eventos
FILE_META, FILE_CHUNK e FILE_END usam o mesmo transporte durante uma requisição de
transferência. O módulo de arquivos continua responsável por Base64, limites dos
blocos originais de 128 KiB, SHA-256, caminhos e gravação temporária.

## Falhas, cancelamento e separação de responsabilidades

A implementação usa prazos de comunicação e trata timeout, EOF, erros de socket e
mensagens inválidas sem encerrar todo o servidor. O prazo de leitura abrange o frame
completo, em vez de reiniciar a cada fragmento. Após uma falha que possa comprometer
o alinhamento do fluxo, o socket é fechado. Não há reenvio automático de comandos,
pois uma ação pode ter sido executada antes de a resposta se perder.

PING permite verificar a comunicação e CLOSE confirma o pedido antes de finalizar a
sessão. O encerramento local fecha os sockets independentemente do controlador. A
interrupção de funções dos handlers exige colaboração desses módulos: funções longas
devem observar o sinal de cancelamento e limitar suas próprias operações bloqueantes.

O encaminhamento depende de autorização da camada de segurança. Sem TLS, AUTH não
é enviado pelo controlador nem processado pelo autenticador do agente. Sem AUTH
bem-sucedido e autorização atual, nenhum handler funcional é chamado. Certificados,
validação do token, logs e interface pertencem à Pessoa 4; entrada, aviso e kill switch
pertencem à Pessoa 3; comandos e arquivos pertencem à Pessoa 2. O código da Pessoa 1
fornece contratos de integração sem implementar essas funcionalidades.

## Evidência experimental e limites

Os testes automatizados utilizam unittest, sockets locais, fragmentos simulados e
handlers fictícios. Eles cobrem o enquadramento, a validação, a correlação, a recusa
sem autorização, o encerramento e a continuidade do listener após falhas de sessão.
Os resultados e as versões efetivamente utilizadas estão em
[entrega_pessoa1.md](entrega_pessoa1.md).

A aprovação isolada dessa camada não comprova TLS real, compatibilidade das
bibliotecas dos colegas nem os requisitos funcionais completos. A versão acordada
Python 3.15.2 ainda deve ser validada pelo grupo, assim como a integração de segurança,
arquivos, entrada, aviso permanente, logs e demonstração final.
