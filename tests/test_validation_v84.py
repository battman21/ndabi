import importlib.util
import pathlib
import socket
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validation_suite_v84", ROOT / "validation_suite_v84.py")
SUITE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUITE)


class ValidationSuiteV84Tests(unittest.TestCase):
    def test_address_parser_requires_host_and_port(self):
        self.assertEqual(SUITE.split_address("127.0.0.1:1234"), ("127.0.0.1", 1234))
        with self.assertRaises(ValueError):
            SUITE.split_address("1234")

    def test_relay_preserves_exact_bytes(self):
        source_writer, source_reader = socket.socketpair()
        target_reader, target_writer = socket.socketpair()
        payload = bytes(range(251)) * 40
        thread = SUITE.threading.Thread(
            target=SUITE.relay,
            args=(source_reader, target_writer, 0.0),
        )
        thread.start()
        source_writer.sendall(payload)
        source_writer.shutdown(socket.SHUT_WR)
        received = bytearray()
        while True:
            chunk = target_reader.recv(65_536)
            if not chunk:
                break
            received.extend(chunk)
        thread.join(timeout=2)
        for item in (source_writer, source_reader, target_reader, target_writer):
            item.close()
        self.assertEqual(bytes(received), payload)

    def test_tls_error_classes_keep_refusal_direction(self):
        self.assertEqual(SUITE.tls_error_class("invalid peer certificate: UnknownIssuer"), "unknown-issuer")
        self.assertEqual(SUITE.tls_error_class("received fatal alert: UnknownCA"), "peer-alert")
        self.assertEqual(SUITE.tls_error_class("certificate not valid for name"), "server-name")

    def test_build_monitor_records_contamination(self):
        stop = SUITE.threading.Event()
        contaminated = SUITE.threading.Event()
        original = SUITE.active_build_process_count
        SUITE.active_build_process_count = lambda: 1
        try:
            thread = SUITE.threading.Thread(
                target=SUITE.monitor_build_processes,
                args=(stop, contaminated),
            )
            thread.start()
            thread.join(timeout=1)
            self.assertTrue(contaminated.is_set())
        finally:
            stop.set()
            SUITE.active_build_process_count = original


if __name__ == "__main__":
    unittest.main()
