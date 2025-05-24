from objects.saxo_config import SaxoConfig
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from threading import Thread
from urllib.parse import urlparse, parse_qs
import logging
import ipaddress

logger = logging.getLogger(__name__)


class RequestHandler(BaseHTTPRequestHandler):
    def is_valid_requestor(self):
        sender = self.client_address[0]
        if ipaddress.ip_address(sender).is_loopback:
            return True
        elif ipaddress.ip_address(sender).is_private:
            return True
        else:
            logger.warning(f"Request from non-local address: {sender}")
            self.reject_request()
            return False

    def do_GET(self):
        if not self.is_valid_requestor():
            return

        parsed_path = urlparse(self.path).path
        query_params = parse_qs(urlparse(self.path).query)
        logger.debug(f"Received GET request: {self.path}")

        if parsed_path == "/":
            if AuthServer.get_code() is None:
                self.send_response(302)
                self.send_header("Location", str(AuthServer.get_auth_url()))
                self.end_headers()
                logger.debug(f"Redirecting to auth URL: {AuthServer.get_auth_url()}")
            else:
                self.send_response(200)
                self.end_headers()
                logger.debug("Already authenticated, no action needed")
        elif parsed_path == "/redirect":
            if "code" in query_params:
                AuthServer.set_code(query_params["code"][0])
                self.handle_auth(query_params)
            else:
                logger.warning("No code provided in redirect")
                self.reject_request()

    def handle_auth(self, query_params):
        # Handle authentication logic here
        logger.debug(f"Handling auth with params: {query_params}")
        # Simulate a successful authentication
        self.send_response(200)
        self.end_headers()
        self.wfile.write(
            b"<html><head><title>Authentication Successful</title></head>"
            + b"<body><h1>Authentication Successful</h1><br><h3>This page can now be closed</h3></body>"
            + b"</html>"
        )

    def reject_request(self):
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b"Forbidden")


class AuthServer(ThreadingMixIn, HTTPServer):
    _code = None
    _auth_url = None

    def __init__(
        self,
        saxo_config: SaxoConfig,
        signin_url: str,
        port: int = 44315,
        host: str = "0.0.0.0",
        request_handler_class=RequestHandler,
    ):
        super().__init__((host, port), request_handler_class)
        self.client_id = saxo_config.app_key
        self.client_secret = saxo_config.app_secret
        self.redirect_uri = [
            uri for uri in saxo_config.redirect_urls if urlparse(uri).port == port
        ][0]
        self.server_thread = Thread(target=self.serve_forever)
        AuthServer.set_auth_url(signin_url)

    def start(self):
        logger.info(f"Starting auth server on {self.server_address}")
        self.server_thread.start()

    def stop(self):
        logger.info("Stopping auth server")
        self.shutdown()
        self.server_thread.join()

    @staticmethod
    def get_auth_url():
        return AuthServer._auth_url

    @staticmethod
    def set_auth_url(auth_url):
        AuthServer._auth_url = auth_url

    @staticmethod
    def get_code():
        return AuthServer._code

    @staticmethod
    def set_code(code):
        AuthServer._code = code


def run_server(saxo_config: SaxoConfig, signin_url: str, port: int = 44315):
    """Run the authentication server."""
    server = AuthServer(
        saxo_config,
        port=port,
        signin_url=signin_url,
    )
    server.start()
    return server
