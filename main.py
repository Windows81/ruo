import time
import pathlib
import threading
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

import urllib.parse
import base64
import datetime
import email.utils
import requests
import json
import io


class Client:
    def __init__(self, akey=None, pkey=None, host=None, code=None, response=None, keyfile=None) -> None:
        if keyfile:
            self.import_key(keyfile)
        else:
            self.pubkey = RSA.generate(2048)

        self.pkey = pkey
        self.akey = akey
        self.host = host
        self.info = {}

        if code:
            self.read_code(code)
        if response:
            self.import_response(response)

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        return "Client(" + ",".join([(self.__dict__[i] or '') and (i + '=' + self.__dict__[i]) for i in ["akey", "pkey", "host"]]) + ")"

    def import_key(self, keyfile) -> None:
        if issubclass(type(keyfile), io.IOBase):
            self.pubkey = RSA.import_key(keyfile.read())
        else:
            try:
                self.pubkey = RSA.import_key(keyfile)
            except ValueError:
                with open(keyfile, "rb") as f:
                    self.pubkey = RSA.import_key(f.read())

    def export_key(self, file) -> None:
        if type(file) is str:
            with open(file, "wb") as f:
                f.write(self.pubkey.export_key("PEM"))
        else:
            file.write(self.pubkey.export_key("PEM"))

    def read_code(self, code) -> None:
        code, host = map(lambda x: x.strip("<>"), code.split("-"))
        missing_padding = len(host) % 4
        if missing_padding:
            host += '=' * (4 - missing_padding)
        self.code = code
        self.host = base64.decodebytes(host.encode("ascii")).decode('ascii')

    def import_response(self, response) -> None:
        if type(response) is str:
            with open(response, "r") as f:
                response = json.load(f)
        if "response" in response:
            response = response["response"]
        self.info = response
        if self.host and ("host" not in self.info or not self.info["host"]):
            self.info["host"] = self.host
        elif not self.host and ("host" in self.info and self.info["host"]):
            self.host = self.info["host"]
        self.akey = response["akey"]
        self.pkey = response["pkey"]

    def export_response(self) -> None:
        if self.host and ("host" not in self.info or not self.info["host"]):
            self.info["host"] = self.host
        with open("response.json", 'w') as f:
            json.dump(self.info, f)

    def activate(self) -> None:
        if self.code:
            # set up URL parameters
            # taken from https://github.com/FreshSupaSulley/DuOSU
            pubkey = self.pubkey.publickey().export_key("PEM").decode('ascii')
            params = {
                "jailbroken": False,
                "architecture": "arch64",
                "region": "US",
                "app_id": "com.duosecurity.duomobile",
                "full_disk_encryption": True,
                "passcode_status": True,
                "platform": "Android",
                "app_version": "4.59.0",
                "app_build_number": "459010",
                "version": "13",
                "manufacturer": "unknown",
                "language": "en",
                "model": "Extension",
                "security_patch_level": "2023-08-05",
                "pkpush": "rsa-sha512",
                "pubkey": pubkey,
            }
            # send activation request
            r = requests.post(
                f"https://{self.host}/push/v2/activation/{self.code}", params=params)
            # print(r.request.url)

            response = r.json()
            self.import_response(response)
        else:
            raise ValueError("Code is null")

    def generate_signature(self, method, path, time, data):
        assert isinstance(self.host, str)
        assert isinstance(self.pkey, str)
        message = (time + "\n" + method + "\n" + self.host.lower() + "\n" +
                   path + '\n' + urllib.parse.urlencode(data)).encode('ascii')
        print(message.decode('utf-8'))

        h = SHA512.new(message)
        signature = pkcs1_15.new(self.pubkey).sign(h)
        signature_b64 = base64.b64encode(signature).decode('ascii')
        sig_pair_b64 = self.pkey + ":" + signature_b64
        auth = b"Basic "+base64.b64encode(sig_pair_b64.encode('ascii'))
        return auth.decode('ascii')

    def get_transactions(self) -> dict:
        dt = datetime.datetime.now(datetime.UTC)
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/transactions"
        data = {
            "akey": self.akey,
            "fips_status": "1",
            "hsm_status": "true",
            "pkpush": "rsa-sha512",
        }

        signature = self.generate_signature("GET", path, time, data)
        r = requests.get(
            f"https://{self.host}{path}",
            params=data, headers={
                "Authorization": signature,
                "x-duo-date": time,
                "host": self.host,
            }
        )

        return r.json()

    def reply_transaction(self, transactionid, answer):
        dt = datetime.datetime.now(datetime.UTC)
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/transactions/" + transactionid
        data = {"akey": self.akey, "answer": answer, "fips_status": "1",
                "hsm_status": "true", "pkpush": "rsa-sha512"}

        # if answer == "approve":
        #     data["touch_id"] = False
        # data["push_received"] = True
        # data["pull_to_refresh_used"] = True
        signature = self.generate_signature("POST", path, time, data)
        r = requests.post(
            f"https://{self.host}{path}",
            data=data, headers={
                "Authorization": signature,
                "x-duo-date": time,
                "host": self.host,
                "txId": transactionid,
            }
        )

        return r.json()

    def register(self, token) -> dict:
        dt = datetime.datetime.now(datetime.UTC)
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/registration"
        data = {"akey": self.akey, "token": token}

        # if answer == "approve":
        #     data["touch_id"] = False
        # data["push_received"] = True
        # data["pull_to_refresh_used"] = True
        signature = self.generate_signature("POST", path, time, data)
        r = requests.post(
            f"https://{self.host}{path}",
            data=data,
            headers={
                "Authorization": signature,
                "x-duo-date": time,
                "host": self.host,
            }
        )
        return r.json()

    def device_info(self) -> dict:
        dt = datetime.datetime.now(datetime.UTC)
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/info"
        data = {
            "akey": self.akey,
            "fips_status": "1",
            "hsm_status": "true",
            "pkpush": "rsa-sha512"
        }

        signature = self.generate_signature("GET", path, time, data)
        r = requests.post(
            f"https://{self.host}{path}",
            params=data,
            headers={
                "Authorization": signature,
                "x-duo-date": time,
                "host": self.host,
            }
        )
        return r.json()


def loop_each(c: Client) -> None:
    try:
        r = c.get_transactions()
    except requests.exceptions.ConnectionError:
        print("Connection Error")
        time.sleep(5)
        return

    if r["stat"] == "FAIL":
        print(r)
        return

    t = r["response"]["transactions"]
    print("Checking for transactions")
    if len(t):
        for tx in t:
            print(tx)
            c.reply_transaction(tx["urgid"], 'approve')
            time.sleep(2)
    else:
        print("No transactions")
    time.sleep(10)


def loop(*a, **kwa):
    while True:
        loop_each(*a, **kwa)

# c = Client(response="response.json",keyfile="mykey.pem",code="")
# print(c)
# print(c.get_transactions())
# print(c.reply_transaction("","approve"))


def main():
    code = ""
    host = ""
    c = Client()
    key_exists = False
    if pathlib.Path("key.pem").is_file():
        c.import_key("key.pem")
        key_exists = True
    else:
        c.export_key("key.pem")

    if pathlib.Path("response.json").is_file() and key_exists:
        c.import_response("response.json")
        if code:
            c.read_code(code)
        if not c.host and host:
            c.host = host
        if not c.host:
            code = input("Input code:")
            c.read_code(code)
            c.export_response()
    else:
        if not code:
            code = input("Input code:")
        c.read_code(code)
        c.activate()
        c.export_response()

    l = threading.Thread(target=loop, args=(c,), daemon=True)
    l.start()
    input()


if __name__ == "__main__":
    main()
