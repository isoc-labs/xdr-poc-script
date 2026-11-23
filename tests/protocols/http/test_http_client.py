"""HTTP protocol client unit tests."""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import pytest

from dsp.protocols.base import HttpProtocolError
from dsp.protocols.http import HttpClient, send_request
from dsp.protocols.http.urls import PlannedHttpRequest


def test_mock_http_request():
    client = HttpClient(mode="mock")
    plan = PlannedHttpRequest(host="10.10.10.20", port=443, path="/login")
    request = client.make_request(plan)
    result = client.request(request)
    assert result.outcome == "response"
    assert result.status_code == 200
    assert result.dry_run is True


def test_live_mode_rejects_mock_outcome():
    client = HttpClient(mode="live")
    plan = PlannedHttpRequest(host="10.10.10.20", port=80, path="/")
    request = client.make_request(plan)
    with pytest.raises(HttpProtocolError, match="mock_outcome"):
        client.request(request, mock_outcome="response")


def test_send_request_parses_http_response():
    plan = PlannedHttpRequest(host="10.10.10.20", port=80, path="/health")
    url = plan.url

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    mock_resp.status = 200
    mock_resp.getcode.return_value = 200
    mock_resp.reason = "OK"
    mock_resp.read.return_value = b"ok"

    with patch("urllib.request.build_opener") as build_opener:
        opener = MagicMock()
        opener.open.return_value = mock_resp
        build_opener.return_value = opener
        result = send_request(url, timeout=1.0)

    assert result.outcome == "response"
    assert result.status_code == 200
    assert result.dry_run is False


def test_send_request_http_error_is_response():
    import urllib.error

    plan = PlannedHttpRequest(host="10.10.10.20", port=80, path="/missing")
    url = plan.url
    err = urllib.error.HTTPError(url, 404, "Not Found", hdrs=None, fp=io.BytesIO(b""))

    with patch("urllib.request.build_opener") as build_opener:
        opener = MagicMock()
        opener.open.side_effect = err
        build_opener.return_value = opener
        result = send_request(url, timeout=1.0)

    assert result.outcome == "response"
    assert result.status_code == 404


def test_send_request_http_does_not_pass_ssl_context():
    plan = PlannedHttpRequest(host="10.10.10.20", port=80, path="/")
    url = plan.url

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    mock_resp.status = 302
    mock_resp.getcode.return_value = 302
    mock_resp.reason = "Found"
    mock_resp.read.return_value = b""

    with patch("urllib.request.build_opener") as build_opener:
        opener = MagicMock()
        opener.open.return_value = mock_resp
        build_opener.return_value = opener
        result = send_request(url, timeout=1.0)

    assert result.outcome == "response"
    assert result.status_code == 302
    _, kwargs = opener.open.call_args
    assert "context" not in kwargs


@pytest.mark.parametrize("verify_tls,expected_verify", [(True, True), (False, False)])
def test_send_request_https_binds_tls_on_handler_not_opener_open(
    verify_tls: bool, expected_verify: bool
):
    """SSL verification mode travels through HTTPSHandler, not opener.open."""
    import ssl
    import urllib.request

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.status = 200
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = b""
    with patch("urllib.request.build_opener") as build_opener:
        opener = MagicMock()
        opener.open.return_value = mock_resp
        build_opener.return_value = opener
        result = send_request("https://example.invalid/health", verify_tls=verify_tls)

    assert result.outcome == "response"
    handlers = build_opener.call_args.args
    assert len(handlers) == 2
    assert issubclass(handlers[0], urllib.request.HTTPRedirectHandler)
    assert isinstance(handlers[1], urllib.request.HTTPSHandler)
    ctx = handlers[1]._context
    assert ctx.check_hostname is expected_verify
    assert ctx.verify_mode == (ssl.CERT_REQUIRED if expected_verify else ssl.CERT_NONE)
    _, options = opener.open.call_args
    assert "context" not in options

def test_send_request_real_loopback_http_open_handler_has_no_context():
    """Real stdlib OpenerDirector rejects context kwarg even on plain HTTP."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class LocalHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), LocalHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        response = send_request(
            f"http://127.0.0.1:{server.server_address[1]}/health",
            timeout=2.0,
        )
        assert response.outcome == "response"
        assert response.status_code == 204
        assert response.dry_run is False
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
