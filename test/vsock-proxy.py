#!/usr/bin/env python3
"""AF_VSOCK to TCP proxy for mock services.

Listens on AF_VSOCK and forwards connections to a TCP endpoint.
Used to bridge enclave vsock connections to host-side mock services.

Usage: vsock-proxy.py <vsock_port> <tcp_host> <tcp_port>
"""

import socket
import sys
import threading

VMADDR_CID_ANY = 0xFFFFFFFF

def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        src.close()
        dst.close()

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <vsock_port> <tcp_host> <tcp_port>", file=sys.stderr)
        sys.exit(1)

    vsock_port = int(sys.argv[1])
    tcp_host = sys.argv[2]
    tcp_port = int(sys.argv[3])

    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((VMADDR_CID_ANY, vsock_port))
    sock.listen(5)
    print(f"vsock-proxy: vsock:{vsock_port} -> {tcp_host}:{tcp_port}", flush=True)

    while True:
        try:
            conn, (cid, port) = sock.accept()
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.connect((tcp_host, tcp_port))
            threading.Thread(target=forward, args=(conn, tcp), daemon=True).start()
            threading.Thread(target=forward, args=(tcp, conn), daemon=True).start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"vsock-proxy: error: {e}", file=sys.stderr, flush=True)

    sock.close()

if __name__ == '__main__':
    main()
