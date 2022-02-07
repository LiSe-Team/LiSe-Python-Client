""" MIT License

Copyright (c) 2022 Runette Software Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. """

from kivy.network.urlrequest import UrlRequest
import certifi
from kivy.logger import Logger
import json
import rsa

from base64 import b64decode

SERVER_URL = "<INSERT HERE>"

class LicenceUsage:

    def __init__(self, RSA):
        self.licence = False
        self.RSA = RSA

    @classmethod
    def load(cls, RSA, key):
        try:
            newkey: LicenceUsage = LicenceUsage(RSA)
            token = key.get("token")
            signature = key.get("signature")
            rsa.verify(token.encode(), b64decode(signature.encode()),
                       rsa.PublicKey.load_pkcs1(RSA))
            newkey.token = json.loads(token)
            newkey.key = key
            newkey.licence = True
            return newkey
        except rsa.VerificationError:
            return None
        except:
            Logger.error("LiSe Validate error: No Key defined")
            return None

    def validate(self, success_callback):
        if self.key:
            self.success_callback = success_callback
            url = SERVER_URL + "validate_key"
            payload = json.dumps(self.key)
            headers = {'Content-type': 'application/json'}
            UrlRequest(
                url,
                req_body=payload,
                on_success=self.validate_sucess,
                on_failure=self.validate_failure,
                on_error=self.validate_failure,
                ca_file=certifi.where(),
                debug=True,
                req_headers=headers
            ).wait()
        else:
            raise ValueError("LiSe Validate error: No Key defined")

    def validate_sucess(self, urlrequest, data):
        try:
            self.licence = True
            self.token = json.loads(data.get('token'))
            self.key = data
            self.success_callback(self)
        except Exception as e:
            Logger.error(str(e))

    def validate_failure(self, urlrequest, data):
        Logger.error(str(data))

    @classmethod
    def create_key(cls, RSA, success_callback, **kwargs):
        newkey: LicenceUsage = LicenceUsage(RSA)
        newkey.success_callback = success_callback
        url = SERVER_URL + "get_key"
        payload = json.dumps({
            "instance_code": kwargs.get("instance_code"),
            "instance_type": kwargs.get("instance_type"),
            "auth_code": kwargs.get("auth_code"),
            "auth_type": kwargs.get("auth_type"),
            "product_id": kwargs.get("product_id")
        })
        headers = {'Content-type': 'application/json'}
        UrlRequest(
            url,
            req_body=payload,
            on_success=newkey.validate_sucess,
            on_failure=newkey.validate_failure,
            on_error=newkey.validate_failure,
            ca_file=certifi.where(),
            debug=True,
            req_headers=headers
        ).wait()
        return newkey
