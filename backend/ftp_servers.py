from __future__ import annotations

import os
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.ioloop import IOLoop
from pyftpdlib.servers import FTPServer


APP_DIR = Path(__file__).resolve().parent
DATA_ROOT = APP_DIR / "ftp_data"
CERT_FILE = APP_DIR / "certs" / "localhost.pem"
KEY_FILE = APP_DIR / "certs" / "localhost-key.pem"

FTPS_USER = os.getenv("FTPS_USERNAME", "ftpuser")
FTPS_PASS = os.getenv("FTPS_PASSWORD", "ftppass")

SERVER_CONFIGS = [
    {
        "name": "server1",
        "host": "0.0.0.0",
        "port": 2121,
        "pasv_start": 30001,
        "pasv_end": 30020,
    },
    {
        "name": "server2",
        "host": "0.0.0.0",
        "port": 2122,
        "pasv_start": 30021,
        "pasv_end": 30040,
    },
    {
        "name": "server3",
        "host": "0.0.0.0",
        "port": 2123,
        "pasv_start": 30041,
        "pasv_end": 30060,
    },
]


def build_handler(home_dir: Path, pasv_start: int, pasv_end: int) -> type[TLS_FTPHandler]:
    authorizer = DummyAuthorizer()
    authorizer.add_user(FTPS_USER, FTPS_PASS, str(home_dir), perm="elradfmwMT")

    class ChatPortalTLSHandler(TLS_FTPHandler):
        pass

    ChatPortalTLSHandler.authorizer = authorizer
    ChatPortalTLSHandler.certfile = str(CERT_FILE)
    ChatPortalTLSHandler.keyfile = str(KEY_FILE)
    ChatPortalTLSHandler.tls_control_required = True
    ChatPortalTLSHandler.tls_data_required = True
    ChatPortalTLSHandler.passive_ports = range(pasv_start, pasv_end + 1)
    return ChatPortalTLSHandler


def main() -> None:
    if not CERT_FILE.exists() or not KEY_FILE.exists():
        raise FileNotFoundError(
            f"Missing TLS certs. Expected {CERT_FILE} and {KEY_FILE}. "
            "Generate/copy certs before running FTPS servers."
        )

    DATA_ROOT.mkdir(parents=True, exist_ok=True)

    servers: list[FTPServer] = []
    for config in SERVER_CONFIGS:
        server_dir = DATA_ROOT / config["name"]
        server_dir.mkdir(parents=True, exist_ok=True)

        handler_cls = build_handler(server_dir, config["pasv_start"], config["pasv_end"])
        server = FTPServer((config["host"], config["port"]), handler_cls)
        servers.append(server)

        print(
            f"[FTPS] {config['name']} started on {config['host']}:{config['port']} "
            f"home={server_dir} passive_ports={config['pasv_start']}-{config['pasv_end']}"
        )

    print(
        f"[FTPS] Login credentials -> username='{FTPS_USER}' password='{FTPS_PASS}' "
        "(set FTPS_USERNAME/FTPS_PASSWORD env vars to override)"
    )
    print("[FTPS] Press Ctrl+C to stop all servers.")

    try:
        IOLoop.instance().loop()
    except KeyboardInterrupt:
        print("\n[FTPS] Shutting down...")
        for server in servers:
            server.close_all()


if __name__ == "__main__":
    main()

