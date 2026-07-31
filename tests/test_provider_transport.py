from __future__ import annotations

import io
import unittest
import urllib.error

from agentsec.providers import UrllibJsonTransport
from agentsec.reasoning import ModelUnavailableError


class Headers:
    def __init__(self, content_type="application/json"):
        self.content_type = content_type

    def get_content_type(self):
        return self.content_type


class Response:
    def __init__(self, body, content_type="application/json"):
        self.body = body
        self.headers = Headers(content_type)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


class Opener:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    def open(self, *_args, **_kwargs):
        if self.error:
            raise self.error
        return self.response


class ProviderTransportTests(unittest.TestCase):
    def call(self, transport):
        return transport.post(
            url="https://api.openai.com/v1/responses",
            headers={"Authorization": "Bearer test"},
            payload={"model": "exact-test"},
            timeout_seconds=1,
        )

    def test_response_size_and_content_type_fail_closed(self):
        oversized = UrllibJsonTransport(max_response_bytes=1024)
        oversized._opener = Opener(Response(b"{" + b"x" * 2048 + b"}"))
        with self.assertRaisesRegex(ModelUnavailableError, "byte limit"):
            self.call(oversized)

        wrong_type = UrllibJsonTransport(max_response_bytes=1024)
        wrong_type._opener = Opener(Response(b"{}", "text/html"))
        with self.assertRaisesRegex(ModelUnavailableError, "content type"):
            self.call(wrong_type)

    def test_redirect_is_not_followed_and_is_normalized(self):
        transport = UrllibJsonTransport()
        transport._opener = Opener(
            error=urllib.error.HTTPError(
                "https://api.openai.com/v1/responses",
                302,
                "redirect",
                {},
                io.BytesIO(b""),
            )
        )
        with self.assertRaisesRegex(ModelUnavailableError, "HTTP 302"):
            self.call(transport)


if __name__ == "__main__":
    unittest.main()
