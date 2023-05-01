import socketserver

import gmpy2

HOST = "127.0.0.1"
PORT = 65432


class GMPTCPHandler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.data = b""

    def handle(self):
        while True:
            self.data = self.rfile.readline().strip()
            print("data:", self.data)
            cmd = self.data.decode("utf-8")
            num = gmpy2.mpz(0)
            print("num:", num)
            out = bytes(f"{num}\n", "utf-8")
            self.wfile.write(out)


def main():
    with socketserver.TCPServer((HOST, PORT), GMPTCPHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
