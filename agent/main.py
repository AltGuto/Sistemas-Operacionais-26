"""Servidor e encaminhamento da Pessoa 1; segurança e handlers são injetados."""

import queue
import select
import socket
import threading
import time
from typing import Protocol

from common.protocol import (
    DEFAULT_PORT, FILE_EVENTS, FUNCTIONAL_ACTIONS, IdleTimeout, ProtocolError,
    close_socket, encode_message, error_response, new_message, recv_message,
    send_message, success_response, tls_established,
)


class SecuritySession(Protocol):
    """Contrato a implementar pela Pessoa 4, com estado exclusivo por conexão."""

    def authenticate(self, args: dict) -> bool: ...

    def is_authorized(self) -> bool: ...

    def close(self) -> None: ...


class ActionError(Exception):
    """Falha esperada do handler. Use código/mensagem públicos, sem segredos."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class Session:
    """Contexto do handler: metadados, cancelamento e eventos sem I/O de rede próprio.

    Os métodos de eventos só podem ser chamados na thread do handler.
    A Pessoa 2 continua responsável por validar transfer_id, blocos e integridade.
    """

    def __init__(self, sock, peer, security, stop_event, timeout):
        self._socket = sock
        self.peer = peer
        self._security = security
        self.stopping = stop_event
        self.timeout = timeout
        self._authenticated = False

    def authorized(self):
        if not tls_established(self._socket) or not self._authenticated or self._security is None:
            return False
        try:
            return self._security.is_authorized() is True
        except Exception:
            return False

    def send_event(self, action, args, *, event_id=None):
        if not self.authorized():
            raise ActionError("NOT_AUTHORIZED", "Sessão não autorizada.")
        if action not in FILE_EVENTS:
            raise ActionError("INVALID_EVENT", "Evento de arquivo desconhecido.")
        message = new_message(action, args, kind="evento", request_id=event_id)
        try:
            send_message(self._socket, message)
        except OSError:
            raise ProtocolError("Falha no transporte de evento.") from None
        return message["id"]

    def receive_event(self):
        if not self.authorized():
            raise ActionError("NOT_AUTHORIZED", "Sessão não autorizada.")
        try:
            message = recv_message(self._socket, deadline=time.monotonic() + self.timeout)
        except OSError:
            raise ProtocolError("Falha no transporte de evento.") from None
        if message["tipo"] != "evento" or message["acao"] not in FILE_EVENTS:
            raise ProtocolError("Esperado evento de arquivo durante transferência.")
        if not self.authorized():
            raise ActionError("NOT_AUTHORIZED", "Autorização da sessão revogada.")
        return message

    def dispatch(self, request, handlers):
        """Retorna (resposta, encerrar). Erros de framing encerram só esta sessão."""
        if request["tipo"] != "comando":
            raise ProtocolError("Esperado comando no início da requisição.")
        action, args = request["acao"], request["args"]
        if action in {"PING", "CLOSE"}:
            if args:
                return error_response(request, "INVALID_ARGS", "Esta ação exige args vazio."), False
            result = {"pong": True} if action == "PING" else {"closed": True}
            return success_response(request, result), action == "CLOSE"
        if action == "AUTH":
            # Nunca chamar o autenticador em conexão sem TLS.
            self._authenticated = False
            if not tls_established(self._socket):
                return error_response(request, "TLS_REQUIRED", "TLS obrigatório para AUTH."), True
            try:
                accepted = self._security is not None and self._security.authenticate(args) is True
                self._authenticated = accepted
                accepted = accepted and self.authorized()
            except Exception:
                accepted = False
            if not accepted:
                self._authenticated = False
                return error_response(request, "AUTH_FAILED", "Autenticação recusada."), True
            return success_response(request, {"authenticated": True}), False
        if not self.authorized():
            return error_response(request, "NOT_AUTHORIZED", "Sessão não autorizada."), False
        if action not in FUNCTIONAL_ACTIONS:
            return error_response(request, "UNKNOWN_ACTION", "Ação desconhecida."), False
        handler = handlers.get(action)
        if handler is None:
            return error_response(request, "NOT_IMPLEMENTED", "Handler ainda não integrado."), False
        try:
            result = handler(args, self)
        except ActionError as exc:
            return error_response(request, exc.code, exc.message), False
        except ProtocolError:
            # Fluxo parcial/timeout não pode ser reutilizado com segurança.
            raise
        except Exception:
            return error_response(request, "HANDLER_ERROR", "Falha interna no handler."), False
        try:
            response = success_response(request, result)
            encode_message(response)
        except ProtocolError:
            return error_response(request, "HANDLER_ERROR", "Resultado do handler inválido ou excessivo."), False
        return response, False


class AgentServer:
    """Um controlador ativo; conexões adicionais são aceitas e fechadas de imediato.

    tls_wrapper(raw_socket) e security_factory(tls_socket, peer) vêm da Pessoa 4.
    Sem essas integrações, somente PING/CLOSE funcionam; AUTH é recusado.
    """

    def __init__(self, host="127.0.0.1", port=DEFAULT_PORT, *, handlers=None,
                 tls_wrapper=None, security_factory=None, timeout=5.0):
        if timeout <= 0:
            raise ValueError("Timeout deve ser positivo.")
        self.host, self.port, self.timeout = host, port, timeout
        self.handlers = dict(handlers or {})
        if not self.handlers.keys() <= FUNCTIONAL_ACTIONS:
            raise ValueError("Registre somente as ações funcionais obrigatórias.")
        if not all(callable(handler) for handler in self.handlers.values()):
            raise TypeError("Handlers devem ser funções chamáveis.")
        self.tls_wrapper = tls_wrapper
        self.security_factory = security_factory
        self.notices = queue.Queue(maxsize=128)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._listener = None
        self._active_socket = None
        self._thread = None
        self._session_thread = None

    def _notice(self, kind, **metadata):
        # Metadados públicos para integração com aviso/logs; nunca args ou tokens.
        try:
            self.notices.put_nowait({"kind": kind, **metadata})
        except queue.Full:
            pass

    @property
    def address(self):
        return self._listener.getsockname() if self._listener else None

    def start(self):
        if self._thread is not None or self._stop.is_set():
            raise RuntimeError("Crie outro AgentServer para reiniciar.")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind((self.host, self.port))
            listener.listen(1)
            listener.settimeout(0.1)
        except Exception:
            listener.close()
            raise
        self._listener = listener
        self._thread = threading.Thread(target=self._accept_loop, name="agent-listener")
        self._thread.start()
        return self.address

    def stop(self):
        """Interrompe listener/rede; o kill switch da Pessoa 3 pode chamar este método."""
        self._stop.set()
        with self._lock:
            close_socket(self._active_socket)
            close_socket(self._listener)

    def wait_closed(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        for thread in (self._thread, self._session_thread):
            if thread is not None and thread is not threading.current_thread():
                remaining = None if deadline is None else max(0, deadline - time.monotonic())
                thread.join(remaining)
        return all(t is None or not t.is_alive() for t in (self._thread, self._session_thread))

    def _accept_loop(self):
        try:
            while not self._stop.is_set():
                try:
                    sock, peer = self._listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                with self._lock:
                    if self._stop.is_set() or (self._session_thread and self._session_thread.is_alive()):
                        close_socket(sock)
                        self._notice("refused", peer=peer)
                        continue
                    self._active_socket = sock
                    self._session_thread = threading.Thread(
                        target=self._serve_session, args=(sock, peer), name="agent-session")
                    self._session_thread.start()
        finally:
            close_socket(self._listener)

    def _serve_session(self, sock, peer):
        security = None
        try:
            sock.settimeout(self.timeout)
            if self.tls_wrapper is not None:
                sock = self.tls_wrapper(sock)
                with self._lock:
                    self._active_socket = sock
                if not tls_established(sock):
                    raise ProtocolError("A camada TLS não forneceu um canal protegido.")
            sock.settimeout(self.timeout)
            if self._stop.is_set():
                return
            if self.security_factory is not None and tls_established(sock):
                security = self.security_factory(sock, peer)
            session = Session(sock, peer, security, self._stop, self.timeout)
            self._notice("connected", peer=peer)
            while not self._stop.is_set():
                buffered = tls_established(sock) and sock.pending() > 0
                if not buffered and not select.select([sock], [], [], 0.05)[0]:
                    continue
                try:
                    request = recv_message(sock, deadline=time.monotonic() + self.timeout)
                except IdleTimeout:
                    continue
                response, closing = session.dispatch(request, self.handlers)
                send_message(sock, response)
                self._notice("response", peer=peer, id=request["id"], action=request["acao"],
                             ok=response["args"]["ok"],
                             code=None if response["args"]["ok"] else response["args"]["erro"]["codigo"])
                if closing:
                    break
        except Exception as exc:
            if not self._stop.is_set():
                self._notice("error", peer=peer, code=type(exc).__name__)
        finally:
            close_socket(sock)
            with self._lock:
                close_socket(self._active_socket)
                self._active_socket = None
            if security is not None:
                try:
                    security.close()
                except Exception:
                    self._notice("error", peer=peer, code="SecurityCleanupError")
            self._notice("disconnected", peer=peer)
