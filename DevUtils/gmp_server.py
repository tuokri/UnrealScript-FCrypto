#!/usr/bin/env python

# MIT License
#
# Copyright (c) 2023 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""GMP test utility server for FCrypto. Reads in variables
and operations from the client, performs GMP mpz big integer
calculations, and returns the results back to the client.
"""

import argparse
import re
import socketserver
import sys
import time
from traceback import print_exc
from typing import Dict
from typing import List

import gmpy2

HOST = "127.0.0.1"
PORT = 65432


class GMPTCPHandler(socketserver.StreamRequestHandler):
    id_regex = re.compile(r"T(\w+)\s.*")
    cmd_regex = re.compile(r"\[(.*?)]")
    rng = gmpy2.random_state(int(time.time()))

    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.data = b""

    def handle(self):
        while True:
            self.data = self.rfile.readline().strip()

            cmd_data = self.data.decode("utf-8")
            if not cmd_data.strip():
                break

            try:
                self.calculate(cmd_data)
                sys.stdout.flush()
            except Exception as e:
                self.wfile.write(bytes("SERVER_ERROR\n", "utf-8"))
                print(e)
                print_exc()

        print("done\n\n")
        sys.stdout.flush()

    def calculate(self, cmd_data):
        t_id = ""
        if match := self.id_regex.match(cmd_data):
            t_id = match.group(1)
        else:
            raise ValueError("invalid t_id")

        cmds: List[str] = self.cmd_regex.findall(cmd_data)
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
                    print(f"\t{dst} = {op[2]} + {op[3]} ({a} + {b})")
                case "mpz_sub":
                    mpz_vars[dst] = a - b
                    print(f"\t{dst} = {op[2]} - {op[3]} ({a} - {b})")
                case "mpz_mod":
                    mpz_vars[dst] = a % b
                    print(f"\t{dst} = {op[2]} % {op[3]} ({a} % {b})")
                case "mpz_mul_2exp":
                    mpz_vars[dst] = a << b
                    print(f"\t{dst} = {op[2]} << {op[3]} ({a} << {b})")
                case "nop":
                    mpz_vars[dst] = a
                    print(f"\t{dst} = {op[2]} (NO OPERATION)")
                case "rand_prime":
                    while True:
                        x = gmpy2.mpz_urandomb(self.rng, a - 1)
                        x = x.bit_set(0)
                        x = x.bit_set(a - 1)
                        # if x.is_probab_prime(50):
                        if x.is_prime(50):
                            x -= 1
                            if x.is_divisible(65537):
                                continue
                            x += 1
                            mpz_vars[dst] = x
                            break
                    print(f"\t{dst} = rand_prime({a}) ({mpz_vars[dst]})")

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
    global PORT
    global HOST

    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--host", default=HOST)
    args = ap.parse_args()
    PORT = args.port
    HOST = args.host

    with TCPServer((HOST, PORT), GMPTCPHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
