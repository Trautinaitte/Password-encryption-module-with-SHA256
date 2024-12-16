#!/usr/bin/env python3
# ipc_server.py

import socket, errno, time, sys
import tink
from tink import daead
from tink import secret_key_access


def encryption(cleartxt):
  daead.register()
  keyset = r"""{
      "key": [{
          "keyData": {
              "keyMaterialType":
                  "SYMMETRIC",
              "typeUrl":
                  "type.googleapis.com/google.crypto.tink.AesSivKey",
              "value":
                  "EkAl9HCMmKTN1p3V186uhZpJQ+tivyc4IKyE+opg6SsEbWQ/WesWHzwCRrlgRuxdaggvgMzwWhjPnkk9gptBnGLK"
          },
          "keyId": 1919301694,
          "outputPrefixType": "TINK",
          "status": "ENABLED"
      }],
      "primaryKeyId": 1919301694
  }"""
  keyset_handle = tink.json_proto_keyset_format.parse(
      keyset, secret_key_access.TOKEN
  )
  primitive = keyset_handle.primitive(daead.DeterministicAead)
  ciphertext = primitive.encrypt_deterministically(cleartxt.encode('utf-8'), b'associated_data')
  return ciphertext



def main():
    HOST = '0.0.0.0'  # Standard loopback interface address (localhost)
    PORT = 9898        # Port to listen on (non-privileged ports are > 1023)

    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((HOST, PORT))
                s.listen(1)
                conn, addr = s.accept()

                with conn:
                    print('Connected by', addr)
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            print('Client disconnected')
                            break

                        #decrypted_data = encryption(data.decode("utf-8"))
                        conn.sendall(encryption(data.decode("utf-8")))

            except BrokenPipeError:
                print('Broken pipe error occurred. Client might have disconnected abruptly.')


if __name__ == "__main__":
    main()