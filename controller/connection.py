"""Cliente assíncrono: a UI chama métodos rápidos e consome a fila inbox."""

import queue
import select
import socket
import threading
import time

from common.protocol import (
    DEFAULT_PORT, FILE_EVENTS, IdleTimeout, ProtocolError, ProtocolTimeout, UnexpectedResponse,
    close_socket, correlate_response, decode_message, encode_message,
    new_message, recv_message, send_message, tls_established,
)


class Connection:
    """Uma instância por sessão. O socket entregue passa a pertencer ao transporte.

    tls_wrapper(raw_socket) deve devolver o socket após handshake/validação.
    O wrapper roda na thread de rede e deve respeitar o timeout do socket.
    """

    def __init__(self, host="127.0.0.1", port=DEFAULT_PORT, *, timeout=5.0,
                 tls_wrapper=None):
        if timeout <= 0:
            raise ValueError("Timeout deve ser positivo.")
        self.host, self.port, self.timeout = host, port, timeout
        self.tls_wrapper = tls_wrapper
        self.inbox = queue.Queue(maxsize=128)
        self._outbox = queue.Queue(maxsize=16)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._socket = None
        self._state = "disconnected"
        self._busy_id = None
        self._started = False

    @property
    def state(self):
        with self._lock:
            return self._state

    def connect(self, *, connected_socket=None):
        with self._lock:
            if self._started:
                raise RuntimeError("Crie outra Connection para uma nova sessão.")
            self._started = True
            self._state = "connecting"
            self._socket = connected_socket
            self._thread = threading.Thread(target=self._run, name="controller-network")
            self._thread.start()

    def request(self, action, args=None):
        message = new_message(action, args)
        # Snapshot: mudanças posteriores no dict da UI não alteram o envio.
        message = decode_message(encode_message(message)[4:])
        with self._lock:
            if self._state != "connected" or self._stop.is_set():
                raise RuntimeError("Sessão não conectada.")
            if self._busy_id is not None:
                raise RuntimeError("Já existe uma requisição pendente.")
            self._outbox.put_nowait(message)
            self._busy_id = message["id"]
        return message["id"]

    def send_event(self, action, args, *, event_id=None):
        if action not in FILE_EVENTS:
            raise ValueError("Evento de arquivo desconhecido.")
        message = new_message(action, args, kind="evento", request_id=event_id)
        message = decode_message(encode_message(message)[4:])
        with self._lock:
            if self._state != "connected" or self._stop.is_set():
                raise RuntimeError("Sessão não conectada.")
            if self._busy_id is None:
                raise RuntimeError("Envie eventos durante a requisição de transferência.")
            self._outbox.put_nowait(message)
        return message["id"]

    def disconnect(self):
        """Interrupção local imediata; não faz join na thread da UI."""
        self._stop.set()
        with self._lock:
            sock = self._socket
        close_socket(sock)

    def wait_closed(self, timeout=None):
        """Para testes/encerramento; não chamar com espera longa na UI."""
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout)
        return self._thread is None or not self._thread.is_alive()

    def _terminal_notice(self, notice):
        # Se a UI não consumir a fila, a sessão falha em vez de crescer sem limite.
        try:
            self.inbox.put_nowait(notice)
        except queue.Full:
            try:
                self.inbox.get_nowait()
            except queue.Empty:
                pass
            self.inbox.put_nowait(notice)

    def _run(self):
        sock = None
        pending = None
        deadline = None
        authenticated = False
        try:
            sock = self._socket
            if sock is None:
                sock = socket.create_connection((self.host, self.port), self.timeout)
            sock.settimeout(self.timeout)
            with self._lock:
                self._socket = sock
            if self._stop.is_set():
                return
            if self.tls_wrapper is not None:
                sock = self.tls_wrapper(sock)
                with self._lock:
                    self._socket = sock
                if not tls_established(sock):
                    raise ProtocolError("A camada TLS não forneceu um canal protegido.")
            sock.settimeout(self.timeout)
            with self._lock:
                if self._stop.is_set():
                    return
                self._state = "connected"
            self.inbox.put_nowait({"kind": "connected"})
            while not self._stop.is_set():
                if pending is not None and time.monotonic() >= deadline:
                    raise ProtocolTimeout("Prazo da resposta excedido.")
                try:
                    outgoing = self._outbox.get_nowait()
                except queue.Empty:
                    outgoing = None
                if outgoing is not None:
                    protected = outgoing["tipo"] == "evento" or outgoing["acao"] not in {"PING", "CLOSE"}
                    if protected and not tls_established(sock):
                        raise ProtocolError("TLS obrigatório antes de AUTH ou ações funcionais.")
                    if protected and outgoing["acao"] != "AUTH" and not authenticated:
                        raise ProtocolError("AUTH deve concluir antes de ações funcionais.")
                    if outgoing["tipo"] == "comando":
                        if pending is not None:
                            raise ProtocolError("Mais de uma requisição em andamento.")
                        pending = outgoing
                        deadline = time.monotonic() + self.timeout
                    elif pending is None:
                        raise ProtocolError("Evento fora de uma requisição pendente.")
                    send_message(sock, outgoing)
                # SSLSocket pode ter bytes decifrados sem legibilidade no socket TCP.
                buffered = tls_established(sock) and sock.pending() > 0
                if not buffered and not select.select([sock], [], [], 0.02)[0]:
                    continue
                try:
                    message = recv_message(sock, deadline=deadline if pending else time.monotonic() + self.timeout)
                except IdleTimeout:
                    # TLS pode consumir mensagens de controle sem entregar bytes JSON.
                    if pending is not None:
                        raise
                    continue
                if message["tipo"] == "evento" and message["acao"] in FILE_EVENTS:
                    if not authenticated or not tls_established(sock):
                        raise ProtocolError("Evento recebido fora de sessão autorizada.")
                    self.inbox.put_nowait({"kind": "event", "message": message})
                    continue
                if pending is None:
                    raise UnexpectedResponse("Resposta recebida sem requisição pendente.")
                correlate_response(message, pending)
                action = pending["acao"]
                if action == "AUTH":
                    authenticated = message["args"]["ok"]
                pending = None
                deadline = None
                with self._lock:
                    self._busy_id = None
                self.inbox.put_nowait({"kind": "response", "message": message})
                if (action == "CLOSE" and message["args"]["ok"]) or (action == "AUTH" and not authenticated):
                    break
        except Exception as exc:
            if not self._stop.is_set():
                # Não publicar str(exc): wrappers/handlers podem incluir segredos.
                self._terminal_notice({"kind": "error", "code": type(exc).__name__,
                                       "id": self._busy_id,
                                       "message": "Sessão encerrada por falha de comunicação."})
        finally:
            close_socket(sock)
            with self._lock:
                close_socket(self._socket)
                self._socket = None
                self._state = "disconnected"
                self._busy_id = None
            while True:
                try:
                    self._outbox.get_nowait()
                except queue.Empty:
                    break
            self._terminal_notice({"kind": "disconnected"})
