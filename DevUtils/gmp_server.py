import re
import socketserver
from typing import Dict
from typing import List

import gmpy2

HOST = "127.0.0.1"
PORT = 65432


class GMPTCPHandler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.data = b""

    def handle(self):
        id_regex = re.compile(r"T(\d+)\s.*")
        cmd_regex = re.compile(r"\[(.*?)]")

        while True:
            self.data = self.rfile.readline().strip()

            if not self.data:
                break

            cmd_data = self.data.decode("utf-8")
            if match := id_regex.match(cmd_data):
                t_id = match.group(1)
            else:
                raise ValueError("invalid t_id")

            cmds: List[str] = cmd_regex.findall(cmd_data)
            print("cmds:", cmds)

            mpz_vars: Dict[str, gmpy2.mpz] = {}
            mpz_ops: List[List[str]] = []

            for cmd in cmds:
                parts = cmd.split(" ")
                c_type = parts[0]
                match c_type.lower():
                    case "var":
                        digits = parts[2].replace("'", "") or "0"
                        mpz_vars[parts[1]] = gmpy2.mpz(digits, 16)
                    case "op":
                        mpz_ops.append(
                            [parts[1], parts[2], parts[3], parts[4]]
                        )

            dst = ""
            for op in mpz_ops:
                op_type = op[0]
                dst = op[1]
                a = mpz_vars[op[2]]
                b = mpz_vars[op[3]]
                match op_type.lower():
                    case "mpz_add":
                        mpz_vars[dst] = a + b
                        print(f"\t{op[1]} = {op[2]} + {op[3]} ({a} + {b})")
                    case "mpz_mod":
                        mpz_vars[dst] = a % b
                        print(f"\t{op[1]} = {op[2]} % {op[3]} ({a} % {b})")

            if not dst:
                raise ValueError("no operations with dst")

            # TODO: should we send back all variables here?
            #   Or only the result? Double-check test_math.c.
            out = bytes(
                f"{t_id} {dst} {mpz_vars[dst].digits(16)}\n",
                "utf-8",
            )
            print("out:", out)
            self.wfile.write(out)

            # for name, value in mpz_vars.items():
            #     self.wfile.write(
            #         bytes(
            #             f"{t_id} {name} {value.digits(16)}\n",
            #             "utf-8",
            #         )
            #     )


class TCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    with TCPServer((HOST, PORT), GMPTCPHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
