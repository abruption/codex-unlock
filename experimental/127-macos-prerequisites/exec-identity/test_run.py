import os
import unittest
from run import Reader, parse_record


class ProtocolTests(unittest.TestCase):
    def test_record_validation(self):
        self.assertEqual(parse_record(b"before 42 100 200\n", "before", 42)["start"], [100, 200])
        for value in [b"before 43 100 200\n", b"after 42 100 200\n",
                      b"before 42 0 0\n", b"before 42 100 1000000\n",
                      b"before 42 100 200", b"before 42 100 200\nextra"]:
            with self.assertRaises(ValueError):
                parse_record(value, "before", 42)

    def reader(self, content):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, content)
        os.close(write_fd)
        stream = os.fdopen(read_fd, "rb", buffering=0)
        self.addCleanup(stream.close)
        return Reader(stream)

    def test_multiple_records(self):
        reader = self.reader(b"one\ntwo\n")
        self.assertEqual(reader.line(), b"one\n")
        self.assertEqual(reader.line(), b"two\n")

    def test_line_boundary(self):
        self.assertEqual(len(self.reader(b"a" * 1024 + b"\n").line()), 1025)
        for value in [b"a" * 1025 + b"\n", b"a" * 1025]:
            with self.assertRaises(ValueError):
                self.reader(value).line()

    def test_incomplete_record(self):
        with self.assertRaises(ValueError):
            self.reader(b"partial").line()


if __name__ == "__main__":
    unittest.main()
