"""Envelope JSON e framing TCP compartilhados (sem lógica de autenticação)."""

import json
import math
import socket
import ssl
import struct
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

DEFAULT_PORT = 5000
MAX_BODY_SIZE = 8 * 1024 * 1024
FILE_CHUNK_SIZE = 128 * 1024
FILE_EVENTS = frozenset({"FILE_META", "FILE_CHUNK", "FILE_END"})
FUNCTIONAL_ACTIONS = frozenset({
    "EXEC", "SYSINFO", "LS", "GET", "PUT", "MOUSE_MOVE",
    "MOUSE_CLICK", "MOUSE_SCROLL", "KEY",
})


class ProtocolError(Exception):
    """Erro controlado; mensagens não incluem o conteúdo recebido."""


class InvalidMessage(ProtocolError):
    pass


class InvalidHeader(ProtocolError):
    pass


class MessageTooLarge(ProtocolError):
    pass


class ConnectionClosed(ProtocolError):
    pass


class ProtocolTimeout(ProtocolError):
    def __init__(self, message, *, bytes_received=0):
        super().__init__(message)
        self.bytes_received = bytes_received


class IdleTimeout(ProtocolTimeout):
    """Prazo expirou antes do primeiro byte de um novo frame."""


class UnexpectedResponse(ProtocolError):
    pass


def _json_value(value):
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            _json_value(item)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _json_value(item)
        return
    raise InvalidMessage("Valor incompatível com JSON.")


def validate_message(message):
    if not isinstance(message, dict):
        raise InvalidMessage("O envelope deve ser um objeto.")
    required = {"id": str, "tipo": str, "acao": str, "args": dict, "timestamp": str}
    if any(type(message.get(key)) is not kind for key, kind in required.items()):
        raise InvalidMessage("Campo obrigatório ausente ou tipo inválido.")
    try:
        parsed_id = UUID(message["id"])
        if str(parsed_id) != message["id"].lower():
            raise ValueError
        stamp = datetime.fromisoformat(message["timestamp"].replace("Z", "+00:00"))
        if "T" not in message["timestamp"] or stamp.utcoffset() != timedelta(0):
            raise ValueError
    except (ValueError, OverflowError):
        raise InvalidMessage("UUID ou timestamp UTC inválido.") from None
    if message["tipo"] not in {"comando", "resposta", "evento"} or not message["acao"].strip():
        raise InvalidMessage("Tipo ou ação inválida.")
    if message["tipo"] == "resposta":
        args = message["args"]
        if not {"ok", "resultado", "erro"} <= args.keys() or type(args["ok"]) is not bool:
            raise InvalidMessage("Resposta fora do formato padrão.")
        if args["ok"]:
            if args["erro"] is not None:
                raise InvalidMessage("Sucesso não pode conter erro.")
        else:
            error = args["erro"]
            if (args["resultado"] is not None or type(error) is not dict
                    or any(type(error.get(k)) is not str or not error[k]
                           for k in ("codigo", "mensagem"))):
                raise InvalidMessage("Falha fora do formato padrão.")
    try:
        _json_value(message)
    except RecursionError:
        raise InvalidMessage("JSON excessivamente aninhado ou cíclico.") from None
    return message


def new_message(action, args=None, *, kind="comando", request_id=None):
    return validate_message({
        "id": str(uuid4()) if request_id is None else request_id,
        "tipo": kind,
        "acao": action,
        "args": {} if args is None else args,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    })


def success_response(request, result=None):
    validate_message(request)
    return new_message(request["acao"], {"ok": True, "resultado": result, "erro": None},
                       kind="resposta", request_id=request["id"])


def error_response(request, code, message):
    validate_message(request)
    return new_message(request["acao"], {
        "ok": False, "resultado": None, "erro": {"codigo": code, "mensagem": message},
    }, kind="resposta", request_id=request["id"])


def correlate_response(response, request):
    validate_message(response)
    if (response["tipo"] != "resposta" or response["id"] != request["id"]
            or response["acao"] != request["acao"]):
        raise UnexpectedResponse("Resposta sem correspondência com a requisição pendente.")
    return response


def encode_header(size):
    if type(size) is not int or size <= 0:
        raise InvalidHeader("Tamanho de corpo inválido.")
    if size > MAX_BODY_SIZE:
        raise MessageTooLarge("Corpo excede 8 MiB.")
    return struct.pack("!I", size)


def decode_header(header):
    if not isinstance(header, bytes) or len(header) != 4:
        raise InvalidHeader("Cabeçalho deve conter quatro bytes.")
    size = struct.unpack("!I", header)[0]
    encode_header(size)
    return size


def encode_message(message):
    validate_message(message)
    try:
        body = json.dumps(message, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError):
        raise InvalidMessage("Não foi possível serializar JSON UTF-8.") from None
    return encode_header(len(body)) + body


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidMessage("Chaves JSON duplicadas.")
        result[key] = value
    return result


def decode_message(body):
    encode_header(len(body))
    try:
        message = json.loads(body.decode("utf-8"), object_pairs_hook=_object)
    except (ValueError, UnicodeError, RecursionError):
        raise InvalidMessage("JSON UTF-8 malformado.") from None
    return validate_message(message)


def recv_exact(sock, size, *, deadline=None):
    """Lê exatamente size bytes; deadline é um instante de time.monotonic()."""
    chunks = bytearray()
    original_timeout = sock.gettimeout()
    try:
        while len(chunks) < size:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProtocolTimeout("Prazo de leitura excedido.", bytes_received=len(chunks))
                sock.settimeout(remaining)
            chunk = sock.recv(size - len(chunks))
            if not chunk:
                raise ConnectionClosed("Conexão encerrada antes de completar a leitura.")
            chunks.extend(chunk)
    except TimeoutError:
        raise ProtocolTimeout("Prazo de leitura excedido.", bytes_received=len(chunks)) from None
    finally:
        if deadline is not None:
            try:
                sock.settimeout(original_timeout)
            except OSError:
                pass
    return bytes(chunks)


def recv_message(sock, *, deadline=None):
    try:
        header = recv_exact(sock, 4, deadline=deadline)
    except ProtocolTimeout as exc:
        if exc.bytes_received == 0:
            raise IdleTimeout("Nenhum frame começou antes do prazo.") from None
        raise
    size = decode_header(header)
    return decode_message(recv_exact(sock, size, deadline=deadline))


def send_message(sock, message):
    try:
        sock.sendall(encode_message(message))
    except TimeoutError:
        raise ProtocolTimeout("Prazo de envio excedido.") from None


def tls_established(sock):
    """A configuração e a validação do certificado pertencem à Pessoa 4."""
    return isinstance(sock, ssl.SSLSocket) and sock.version() is not None


def close_socket(sock):
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
