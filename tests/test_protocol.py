import json
import socket
import struct
import time
import unittest

from common import protocol as p


class FragmentedSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.timeout = 1.0

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value

    def recv(self, count):
        if not self.chunks:
            return b""
        data = self.chunks[0][:count]
        self.chunks[0] = self.chunks[0][count:]
        if not self.chunks[0]:
            self.chunks.pop(0)
        return data


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.message = p.new_message("PING")

    def test_json_utf8_roundtrip(self):
        message = p.new_message("SYSINFO", {"texto": "ação ☕", "lista": [True, None, 12]})
        frame = p.encode_message(message)
        self.assertIn("ação".encode(), frame)
        self.assertEqual(p.decode_message(frame[4:]), message)

    def test_header_big_endian(self):
        self.assertEqual(p.encode_header(0x010203), b"\x00\x01\x02\x03")
        self.assertEqual(p.decode_header(b"\x00\x01\x02\x03"), 0x010203)
        frame = p.encode_message(self.message)
        self.assertEqual(p.decode_header(frame[:4]), len(frame) - 4)

    def test_fragmented_header_and_body(self):
        frame = p.encode_message(self.message)
        sock = FragmentedSocket([frame[:1], frame[1:3], frame[3:9], frame[9:15], frame[15:]])
        self.assertEqual(p.recv_message(sock), self.message)

    def test_coalesced_messages(self):
        other = p.new_message("CLOSE")
        sock = FragmentedSocket([p.encode_message(self.message) + p.encode_message(other)])
        self.assertEqual(p.recv_message(sock), self.message)
        self.assertEqual(p.recv_message(sock), other)

    def test_body_exactly_at_limit(self):
        message = p.new_message("PING", {"pad": ""})
        overhead = len(p.encode_message(message)) - 4
        message["args"]["pad"] = "a" * (p.MAX_BODY_SIZE - overhead)
        frame = p.encode_message(message)
        self.assertEqual(len(frame) - 4, p.MAX_BODY_SIZE)
        self.assertEqual(p.decode_message(frame[4:]), message)

    def test_oversized_body_send_and_receive(self):
        with self.assertRaises(p.MessageTooLarge):
            p.encode_message(p.new_message("PING", {"pad": "a" * p.MAX_BODY_SIZE}))
        with self.assertRaises(p.MessageTooLarge):
            p.decode_message(b"a" * (p.MAX_BODY_SIZE + 1))
        sock = FragmentedSocket([struct.pack("!I", p.MAX_BODY_SIZE + 1), b"unread"])
        with self.assertRaises(p.MessageTooLarge):
            p.recv_message(sock)
        self.assertEqual(sock.chunks, [b"unread"])

    def test_invalid_header(self):
        for header in (b"", b"\x00", b"12345", b"\x00\x00\x00\x00"):
            with self.subTest(header=header), self.assertRaises(p.InvalidHeader):
                p.decode_header(header)
        for size in (-1, 0, True, "1"):
            with self.subTest(size=size), self.assertRaises(p.InvalidHeader):
                p.encode_header(size)

    def test_eof_at_every_header_position(self):
        for count in range(4):
            with self.subTest(count=count), self.assertRaises(p.ConnectionClosed):
                p.recv_message(FragmentedSocket([b"\x00" * count] if count else []))

    def test_eof_during_body(self):
        frame = p.encode_message(self.message)
        with self.assertRaises(p.ConnectionClosed):
            p.recv_message(FragmentedSocket([frame[:-1]]))

    def test_malformed_json_and_utf8(self):
        for body in (b"{", b"\xff", b"null", b"[]", b'{"id": 1, "id": 2}'):
            with self.subTest(body=body), self.assertRaises(p.InvalidMessage):
                p.decode_message(body)

    def test_missing_fields(self):
        for field in self.message:
            message = dict(self.message)
            del message[field]
            with self.subTest(field=field), self.assertRaises(p.InvalidMessage):
                p.validate_message(message)

    def test_wrong_field_types(self):
        for field, value in {"id": 1, "tipo": [], "acao": False, "args": [], "timestamp": 1}.items():
            with self.subTest(field=field), self.assertRaises(p.InvalidMessage):
                p.validate_message({**self.message, field: value})

    def test_bad_uuid_type_action_and_timestamp(self):
        cases = [("id", "not-a-uuid"), ("tipo", "request"), ("acao", " "),
                 ("timestamp", "2026-10-28"), ("timestamp", "2026-10-28T22:30:00"),
                 ("timestamp", "2026-10-28T22:30:00-03:00")]
        for field, value in cases:
            with self.subTest(field=field, value=value), self.assertRaises(p.InvalidMessage):
                p.validate_message({**self.message, field: value})

    def test_unique_ids_and_utc(self):
        self.assertNotEqual(self.message["id"], p.new_message("PING")["id"])
        self.assertTrue(self.message["timestamp"].endswith("Z"))

    def test_response_correlation(self):
        response = p.success_response(self.message, {"pong": True})
        self.assertEqual(response["id"], self.message["id"])
        self.assertEqual(response["acao"], self.message["acao"])
        self.assertIs(p.correlate_response(response, self.message), response)
        for field, value in (("id", p.new_message("PING")["id"]), ("acao", "CLOSE")):
            with self.subTest(field=field), self.assertRaises(p.UnexpectedResponse):
                p.correlate_response({**response, field: value}, self.message)

    def test_error_response(self):
        response = p.error_response(self.message, "TEST_ERROR", "Erro público.")
        self.assertEqual(response["args"], {
            "ok": False, "resultado": None,
            "erro": {"codigo": "TEST_ERROR", "mensagem": "Erro público."}})
        p.correlate_response(response, self.message)

    def test_invalid_response_shapes(self):
        valid = p.success_response(self.message, {})
        for args in ({}, {"ok": 1, "resultado": {}, "erro": None},
                     {"ok": True, "resultado": {}, "erro": {}},
                     {"ok": False, "resultado": {}, "erro": None},
                     {"ok": False, "resultado": None, "erro": {"codigo": 1, "mensagem": "x"}}):
            with self.subTest(args=args), self.assertRaises(p.InvalidMessage):
                p.validate_message({**valid, "args": args})

    def test_non_json_values_and_duplicate_keys(self):
        for value in (float("nan"), float("inf"), object(), {1: "x"}, (1, 2)):
            with self.subTest(value=type(value)), self.assertRaises(p.InvalidMessage):
                p.new_message("PING", {"value": value})
        encoded = json.dumps(self.message).replace('"args": {}', '"args": {"x": NaN}')
        with self.assertRaises(p.InvalidMessage):
            p.decode_message(encoded.encode())
        cycle = {}
        cycle["self"] = cycle
        with self.assertRaises(p.InvalidMessage):
            p.new_message("PING", cycle)

    def test_socket_read_timeout(self):
        reader, writer = socket.socketpair()
        with reader, writer:
            reader.settimeout(0.04)
            with self.assertRaises(p.ProtocolTimeout):
                p.recv_message(reader)

    def test_idle_timeout_differs_from_partial_frame_timeout(self):
        for prefix, idle in ((b"", True), (b"\x00", False), (p.encode_header(2), False)):
            with self.subTest(prefix=prefix):
                reader, writer = socket.socketpair()
                with reader, writer:
                    reader.settimeout(0.02)
                    if prefix:
                        writer.sendall(prefix)
                    with self.assertRaises(p.ProtocolTimeout) as raised:
                        p.recv_message(reader)
                    self.assertEqual(isinstance(raised.exception, p.IdleTimeout), idle)

    def test_deadline_and_timeout_restoration(self):
        sock = FragmentedSocket([p.encode_message(self.message)])
        with self.assertRaises(p.ProtocolTimeout):
            p.recv_message(sock, deadline=time.monotonic() - 1)
        self.assertEqual(sock.gettimeout(), 1.0)
        self.assertEqual(p.recv_message(sock, deadline=time.monotonic() + 1), self.message)
        self.assertEqual(sock.gettimeout(), 1.0)

    def test_deadline_is_not_reset_for_each_fragment(self):
        from unittest.mock import patch
        sock = FragmentedSocket([b"\x00", b"\x00", b"\x00", b"\x01", b"{"])
        with patch("common.protocol.time.monotonic", side_effect=[10, 10.4, 10.8, 11.2]):
            with self.assertRaises(p.ProtocolTimeout):
                p.recv_message(sock, deadline=11)
        self.assertEqual(sock.gettimeout(), 1.0)

    def test_real_socket_grouped_frames(self):
        reader, writer = socket.socketpair()
        with reader, writer:
            reader.settimeout(1)
            writer.sendall(p.encode_message(self.message) * 2)
            self.assertEqual(p.recv_message(reader), self.message)
            self.assertEqual(p.recv_message(reader), self.message)

    def test_file_events_share_envelope(self):
        import base64
        block = base64.b64encode(b"a" * p.FILE_CHUNK_SIZE).decode("ascii")
        for action in p.FILE_EVENTS:
            message = p.new_message(action, {"transfer_id": "test", "data_b64": block}, kind="evento")
            frame = p.encode_message(message)
            self.assertLess(len(frame) - 4, p.MAX_BODY_SIZE)
            self.assertEqual(p.decode_message(frame[4:]), message)


if __name__ == "__main__":
    unittest.main()
