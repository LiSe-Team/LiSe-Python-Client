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
from appdirs import *
from pathlib import Path
import os

from base64 import b64decode

class Service:
    
    def __init__(self, org: str, product: str, product_id: int, pub_key: str, URL: str):
        self.pub_key = pub_key
        self.URL = URL
        self.org = org
        self.product = product
        self.product_id = product_id

class LicenceUsage:

    def __init__(self, service: Service):
        self.loaded: bool = False
        self.valid: bool = False
        self.service: Service = service
        
    def validate(self, success_callback, failure_callback):
        if self.loaded:
            self.success_callback = success_callback
            self.failure_callback = failure_callback
            url = self.service.URL + "validate_key"
            payload = json.dumps({
                "signature": self.signature,
                "token": self.token
            })
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
            self.valid = True
            self.signature = data.get('signature')
            self.token = data.get('token')
            self.success_callback(self)
        except Exception as e:
            Logger.error(str(e))

    def validate_failure(self, urlrequest, data):
        Logger.error(str(data))
        self.valid = False
        self.failure_callback(self)

    def create_key(self, success_callback, failure_callback,  **kwargs):
        self.success_callback = success_callback
        self.failure_callback = failure_callback
        url = self.service.URL + "get_key"
        payload = json.dumps({
            "instance_code": kwargs.get("instance_code"),
            "instance_type": kwargs.get("instance_type"),
            "auth_code": kwargs.get("auth_code"),
            "auth_type": kwargs.get("auth_type"),
            "product_id": self.service.product_id
        })
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
        return
    
    def get(self, auth_code: str):
        if not os.path.exists(Path(user_data_dir(self.service.product, self.service.org))):
            os.makedirs(Path(user_data_dir(self.service.product, self.service.org)))        
        file: Path = Path(user_data_dir(self.service.product, self.service.org)).joinpath(auth_code)
        if os.path.exists(file):
            with open(file, "r") as f:
                try:
                    details = json.load(f)
                except Exception as e:
                    Logger.error(str(e))
                    self.loaded = False
                    return
                Logger.info("opened file : " + str(file))
                self.token = details.get('token')
                self.signature = details.get('signature')
                rsa.verify(self.token.encode(), b64decode(self.signature.encode()),
                           rsa.PublicKey.load_pkcs1(self.service.pub_key))
                if self.service.product_id == self.product:
                    self.loaded = True
                
    def put(self, auth_code: str):
        file: Path = Path(user_data_dir(self.service.product, self.service.org)).joinpath(auth_code)
        with open(file, "w") as f:
            json.dump({
                "signature": self.signature,
                "token": self.token
                }, f)
    
    @property        
    def licence(self) -> str:
        return str(json.loads(self.token).get('licence_key', '') or '')
    
    @property
    def product(self) -> int:
        return json.loads(self.token).get('product_id', '') or ''
