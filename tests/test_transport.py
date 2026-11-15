import queue
import socket
import ssl
import threading
import time
import unittest
from unittest.mock import Mock, patch

from agent.main import ActionError, AgentServer
from common import protocol as p
from controller.connection import Connection


def simulated_tls(sock):
    """Somente testes: socket local com interface TLS simulada, sem criptografia."""
    wrapped = Mock(spec=ssl.SSLSocket)
    for method in ("recv", "sendall", "gettimeout", "settimeout", "fileno", "shutdown", "close"):
        setattr(wrapped, method, getattr(sock, method))
    wrapped.version.return_value = "TLS-test-double"
    wrapped.pending.return_value = 0
    return wrapped


def simulated_security(accepted=True):
    security = Mock()
    security.authenticate.return_value = accepted
    security.is_authorized.return_value = accepted
    return security


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.servers = []
        self.clients = []
        self.sockets = []

    def tearDown(self):
        for client in self.clients:
            client.disconnect()
        for server in self.servers:
            server.stop()
        for sock in self.sockets:
            p.close_socket(sock)
        for client in self.clients:
            self.assertTrue(client.wait_closed(2), "Thread do controlador não terminou")
        for server in self.servers:
            self.assertTrue(server.wait_closed(2), "Thread do agente não terminou")

    def server(self, **kwargs):
        server = AgentServer(port=0, timeout=0.8, **kwargs)
        server.start()
        self.servers.append(server)
        return server

    def client(self, server=None, **kwargs):
        if server:
            client = Connection(*server.address, timeout=0.8, **kwargs)
            self.clients.append(client)
            client.connect()
        else:
            left, right = socket.socketpair()
            right.settimeout(1)
            self.sockets.append(right)
            client = Connection(timeout=0.2, **kwargs)
            self.clients.append(client)
            client.connect(connected_socket=left)
        self.notice(client.inbox, "connected")
        return client if server else (client, right)

    def notice(self, inbox, kind):
        deadline = time.monotonic() + 2
        while True:
            item = inbox.get(timeout=max(0.001, deadline - time.monotonic()))
            if item["kind"] == kind:
                return item
            if time.monotonic() >= deadline:
                self.fail("Não recebeu aviso: " + kind)

    def response(self, client, action, args=None):
        request_id = client.request(action, args)
        response = self.notice(client.inbox, "response")["message"]
        self.assertEqual(response["id"], request_id)
        self.assertEqual(response["acao"], action)
        return response["args"]

    def raw(self, server):
        sock = socket.create_connection(server.address, timeout=1)
        self.sockets.append(sock)
        return sock

    def raw_request(self, sock, action, args=None):
        request = p.new_message(action, args)
        p.send_message(sock, request)
        response = p.recv_message(sock)
        p.correlate_response(response, request)
        return response["args"]

    def secure_pair(self, *, handlers=None, security=None):
        security = security or simulated_security()
        server = self.server(handlers=handlers, tls_wrapper=simulated_tls,
                             security_factory=lambda sock, peer: security)
        client = self.client(server, tls_wrapper=simulated_tls)
        return server, client, security

    def test_ping_and_close(self):
        server = self.server()
        client = self.client(server)
        self.assertEqual(self.response(client, "PING")["resultado"], {"pong": True})
        self.assertEqual(self.response(client, "CLOSE")["resultado"], {"closed": True})
        self.notice(client.inbox, "disconnected")
        self.assertTrue(client.wait_closed(1))
        self.assertEqual(client.state, "disconnected")
        self.assertIsNone(client._socket)
        self.assertTrue(server._thread.is_alive())

    def test_ping_close_require_empty_args(self):
        client = self.client(self.server())
        for action in ("PING", "CLOSE"):
            self.assertEqual(self.response(client, action, {"extra": 1})["erro"]["codigo"], "INVALID_ARGS")
        self.assertTrue(self.response(client, "PING")["ok"])

    def test_handler_forwarding_after_auth(self):
        handler = Mock(return_value={"simulado": True})
        server, client, security = self.secure_pair(handlers={"SYSINFO": handler})
        self.assertTrue(self.response(client, "AUTH")["ok"])
        result = self.response(client, "SYSINFO")
        self.assertEqual(result["resultado"], {"simulado": True})
        handler.assert_called_once()
        self.assertEqual(handler.call_args.args[0], {})
        self.assertTrue(handler.call_args.args[1].authorized())
        self.response(client, "CLOSE")
        server._session_thread.join(1)
        security.close.assert_called_once()

    def test_all_functional_actions_denied_without_security(self):
        handler = Mock()
        sock = self.raw(self.server(handlers={action: handler for action in p.FUNCTIONAL_ACTIONS}))
        for action in p.FUNCTIONAL_ACTIONS:
            self.assertEqual(self.raw_request(sock, action)["erro"]["codigo"], "NOT_AUTHORIZED")
        handler.assert_not_called()

    def test_authorizer_cannot_skip_auth(self):
        handler = Mock()
        security = simulated_security()
        server = self.server(handlers={"SYSINFO": handler}, tls_wrapper=simulated_tls,
                             security_factory=lambda sock, peer: security)
        sock = self.raw(server)
        self.assertEqual(self.raw_request(sock, "SYSINFO")["erro"]["codigo"], "NOT_AUTHORIZED")
        handler.assert_not_called()
        security.authenticate.assert_not_called()

    def test_auth_plaintext_denied_without_calling_security(self):
        factory = Mock()
        sock = self.raw(self.server(security_factory=factory))
        self.assertEqual(self.raw_request(sock, "AUTH")["erro"]["codigo"], "TLS_REQUIRED")
        with self.assertRaises((p.ConnectionClosed, OSError)):
            p.recv_message(sock)
        factory.assert_not_called()

    def test_missing_security_auth_denied(self):
        sock = self.raw(self.server(tls_wrapper=simulated_tls))
        self.assertEqual(self.raw_request(sock, "AUTH")["erro"]["codigo"], "AUTH_FAILED")

    def test_failed_auth_closes_connection(self):
        server, client, security = self.secure_pair(security=simulated_security(False))
        self.assertEqual(self.response(client, "AUTH")["erro"]["codigo"], "AUTH_FAILED")
        self.notice(client.inbox, "disconnected")
        self.assertTrue(client.wait_closed(1))

    def test_authorization_revocation_and_exception_fail_closed(self):
        handler = Mock(return_value={})
        server, client, security = self.secure_pair(handlers={"SYSINFO": handler})
        self.response(client, "AUTH")
        security.is_authorized.return_value = False
        self.assertEqual(self.response(client, "SYSINFO")["erro"]["codigo"], "NOT_AUTHORIZED")
        security.is_authorized.side_effect = RuntimeError("private data")
        self.assertEqual(self.response(client, "SYSINFO")["erro"]["codigo"], "NOT_AUTHORIZED")
        handler.assert_not_called()

    def test_handler_error_is_sanitized_and_session_survives(self):
        handler = Mock(side_effect=RuntimeError("private data"))
        server, client, security = self.secure_pair(handlers={"SYSINFO": handler})
        self.response(client, "AUTH")
        result = self.response(client, "SYSINFO")
        self.assertEqual(result["erro"]["codigo"], "HANDLER_ERROR")
        self.assertNotIn("private data", str(result))
        self.assertTrue(self.response(client, "PING")["ok"])

    def test_expected_handler_error(self):
        handler = Mock(side_effect=ActionError("TEST_FAILURE", "Falha simulada."))
        server, client, security = self.secure_pair(handlers={"LS": handler})
        self.response(client, "AUTH")
        self.assertEqual(self.response(client, "LS")["erro"]["codigo"], "TEST_FAILURE")

    def test_handler_oserror_returns_standard_response(self):
        handler = Mock(side_effect=FileNotFoundError("private path"))
        server, client, security = self.secure_pair(handlers={"LS": handler})
        self.response(client, "AUTH")
        result = self.response(client, "LS")
        self.assertEqual(result["erro"]["codigo"], "HANDLER_ERROR")
        self.assertNotIn("private path", str(result))
        self.assertTrue(self.response(client, "PING")["ok"])

    def test_server_survives_idle_tls_control_message(self):
        server = self.server()
        sock = self.raw(server)
        first = True

        def receive(connection, **kwargs):
            nonlocal first
            if first:
                first = False
                connection.recv(1)
                raise p.IdleTimeout("simulated control record")
            return p.recv_message(connection, **kwargs)

        with patch("agent.main.recv_message", side_effect=receive):
            # Deixa o socket legível, simulando registro TLS sem bytes de aplicação.
            sock.sendall(b"x")
            self.assertTrue(self.raw_request(sock, "PING")["ok"])

    def test_client_survives_idle_tls_control_message(self):
        client, peer = self.client()
        entered = threading.Event()
        release = threading.Event()

        def receive(sock, **kwargs):
            sock.recv(1)
            entered.set()
            release.wait(1)
            raise p.IdleTimeout("simulated control record")

        with patch("controller.connection.recv_message", side_effect=receive):
            peer.sendall(b"x")
            self.assertTrue(entered.wait(1))
            release.set()
        client.request("PING")
        p.send_message(peer, p.success_response(p.recv_message(peer), {}))
        self.assertTrue(self.notice(client.inbox, "response")["message"]["args"]["ok"])

    def test_invalid_handler_result_is_controlled(self):
        handler = Mock(return_value=object())
        server, client, security = self.secure_pair(handlers={"SYSINFO": handler})
        self.response(client, "AUTH")
        self.assertEqual(self.response(client, "SYSINFO")["erro"]["codigo"], "HANDLER_ERROR")
        self.assertTrue(self.response(client, "PING")["ok"])

    def test_unregistered_and_unknown_actions(self):
        server, client, security = self.secure_pair()
        self.response(client, "AUTH")
        self.assertEqual(self.response(client, "SYSINFO")["erro"]["codigo"], "NOT_IMPLEMENTED")
        self.assertEqual(self.response(client, "BOGUS")["erro"]["codigo"], "UNKNOWN_ACTION")

    def test_one_request_at_a_time(self):
        client, peer = self.client()
        client.request("PING")
        with self.assertRaises(RuntimeError):
            client.request("PING")
        request = p.recv_message(peer)
        p.send_message(peer, p.success_response(request, {}))
        self.notice(client.inbox, "response")

    def test_unexpected_response_id_and_action(self):
        for field, value in (("id", p.new_message("PING")["id"]), ("acao", "CLOSE")):
            with self.subTest(field=field):
                client, peer = self.client()
                client.request("PING")
                response = p.success_response(p.recv_message(peer), {})
                response[field] = value
                p.send_message(peer, response)
                self.assertEqual(self.notice(client.inbox, "error")["code"], "UnexpectedResponse")
                self.assertTrue(client.wait_closed(1))

    def test_unsolicited_response_rejected(self):
        client, peer = self.client()
        p.send_message(peer, p.success_response(p.new_message("PING"), {}))
        self.assertEqual(self.notice(client.inbox, "error")["code"], "UnexpectedResponse")

    def test_response_timeout(self):
        client, peer = self.client()
        client.request("PING")
        p.recv_message(peer)
        self.assertEqual(self.notice(client.inbox, "error")["code"], "ProtocolTimeout")
        self.assertTrue(client.wait_closed(1))

    def test_connection_timeout(self):
        client = Connection(timeout=0.05)
        self.clients.append(client)
        with patch("controller.connection.socket.create_connection", side_effect=TimeoutError):
            client.connect()
            self.assertEqual(self.notice(client.inbox, "error")["code"], "TimeoutError")
            self.assertTrue(client.wait_closed(1))

    def test_disconnect_cancels_pending_read(self):
        client, peer = self.client()
        client.request("PING")
        p.recv_message(peer)
        peer.sendall(b"\x00")
        client.disconnect()
        self.assertTrue(client.wait_closed(1))
        self.assertEqual(client.state, "disconnected")

    def test_disconnect_during_header_or_body(self):
        frame = p.encode_message(p.new_message("PING"))
        for data in (b"\x00\x00", frame[:-1]):
            client, peer = self.client()
            client.request("PING")
            p.recv_message(peer)
            peer.sendall(data)
            p.close_socket(peer)
            self.assertEqual(self.notice(client.inbox, "error")["code"], "ConnectionClosed")
            self.assertTrue(client.wait_closed(1))

    def test_client_never_sends_auth_on_plaintext(self):
        client, peer = self.client()
        client.request("AUTH", {"token": "test-only-placeholder"})
        self.assertEqual(self.notice(client.inbox, "error")["code"], "ProtocolError")
        self.assertEqual(peer.recv(1), b"")

    def test_tls_wrapper_failure_closes_original_socket(self):
        wrapper = Mock(side_effect=RuntimeError("private data"))
        left, right = socket.socketpair()
        self.sockets.append(right)
        client = Connection(tls_wrapper=wrapper)
        self.clients.append(client)
        client.connect(connected_socket=left)
        notice = self.notice(client.inbox, "error")
        self.assertNotIn("private data", str(notice))
        self.assertTrue(client.wait_closed(1))
        self.assertEqual(left.fileno(), -1)

    def test_server_tls_failure_preserves_listener(self):
        server = self.server(tls_wrapper=Mock(side_effect=RuntimeError("private data")))
        sock = self.raw(server)
        self.assertEqual(sock.recv(1), b"")
        notice = self.notice(server.notices, "error")
        self.assertNotIn("private data", str(notice))
        self.notice(server.notices, "disconnected")
        self.assertTrue(server._thread.is_alive())

    def test_plain_socket_returned_by_tls_wrapper_is_rejected(self):
        left, right = socket.socketpair()
        self.sockets.append(right)
        client = Connection(tls_wrapper=lambda sock: sock)
        self.clients.append(client)
        client.connect(connected_socket=left)
        self.assertEqual(self.notice(client.inbox, "error")["code"], "ProtocolError")
        self.assertTrue(client.wait_closed(1))

    def test_attached_tls_socket_is_supported(self):
        left, right = socket.socketpair()
        self.sockets.append(right)
        client = Connection()
        self.clients.append(client)
        client.connect(connected_socket=simulated_tls(left))
        self.notice(client.inbox, "connected")
        client.request("PING")
        p.send_message(right, p.success_response(p.recv_message(right), {"pong": True}))
        self.assertTrue(self.notice(client.inbox, "response")["message"]["args"]["ok"])

    def test_input_args_are_snapshotted(self):
        client, peer = self.client()
        args = {"nested": {"value": "original"}}
        client.request("PING", args)
        args["nested"]["value"] = "modified"
        request = p.recv_message(peer)
        self.assertEqual(request["args"]["nested"]["value"], "original")

    def test_slow_header_times_out_only_its_session(self):
        server = self.server()
        sock = self.raw(server)
        sock.sendall(b"\x00")
        self.assertEqual(self.notice(server.notices, "error")["code"], "ProtocolTimeout")
        self.notice(server.notices, "disconnected")
        server._session_thread.join(1)
        client = self.client(server)
        self.assertTrue(self.response(client, "PING")["ok"])

    def test_invalid_session_does_not_stop_listener(self):
        server = self.server()
        sock = self.raw(server)
        sock.sendall(p.encode_header(1) + b"{")
        self.notice(server.notices, "disconnected")
        server._session_thread.join(1)
        client = self.client(server)
        self.assertTrue(self.response(client, "PING")["ok"])

    def test_second_controller_is_refused(self):
        server = self.server()
        first = self.client(server)
        self.response(first, "PING")
        second = self.raw(server)
        self.assertEqual(second.recv(1), b"")
        self.assertTrue(self.response(first, "PING")["ok"])

    def test_stop_interrupts_idle_session_and_listener(self):
        server = self.server()
        client = self.client(server)
        self.response(client, "PING")
        server.stop()
        self.assertTrue(server.wait_closed(1))
        self.assertTrue(client.wait_closed(1))

    def test_idle_client_can_send_later(self):
        client, peer = self.client()
        self.assertFalse(client.wait_closed(0.25))
        client.request("PING")
        p.send_message(peer, p.success_response(p.recv_message(peer), {}))
        self.notice(client.inbox, "response")

    def test_file_events_in_both_directions_during_request(self):
        received = []

        def handler(args, session):
            for action in ("FILE_META", "FILE_CHUNK", "FILE_END"):
                event = session.receive_event()
                received.append(event)
                session.send_event(action, event["args"])
            return {"simulado": True}

        server, client, security = self.secure_pair(handlers={"PUT": handler})
        self.response(client, "AUTH")
        request_id = client.request("PUT", {"path": "simulado.txt", "size": 0, "sha256": "simulado"})
        for action in ("FILE_META", "FILE_CHUNK", "FILE_END"):
            client.send_event(action, {"transfer_id": "simulation"})
        events = [self.notice(client.inbox, "event")["message"] for _ in range(3)]
        response = self.notice(client.inbox, "response")["message"]
        self.assertEqual(response["id"], request_id)
        self.assertEqual([e["acao"] for e in events], ["FILE_META", "FILE_CHUNK", "FILE_END"])
        self.assertEqual(len(received), 3)

    def test_events_cannot_bypass_auth(self):
        server = self.server()
        sock = self.raw(server)
        p.send_message(sock, p.new_message("FILE_CHUNK", {}, kind="evento"))
        with self.assertRaises((p.ConnectionClosed, OSError)):
            p.recv_message(sock)
        self.notice(server.notices, "disconnected")

    def test_security_state_is_not_reused_between_sessions(self):
        factory = Mock(side_effect=lambda sock, peer: simulated_security())
        server = self.server(tls_wrapper=simulated_tls, security_factory=factory)
        first = self.raw(server)
        self.assertTrue(self.raw_request(first, "AUTH")["ok"])
        self.raw_request(first, "CLOSE")
        self.notice(server.notices, "disconnected")
        server._session_thread.join(1)
        second = self.raw(server)
        self.assertEqual(self.raw_request(second, "SYSINFO")["erro"]["codigo"], "NOT_AUTHORIZED")
        self.assertEqual(factory.call_count, 2)


if __name__ == "__main__":
    unittest.main()
