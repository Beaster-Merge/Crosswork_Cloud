#!/usr/bin/env python3

#
# Copyright 2019 Cisco Systems Inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import binascii
import datetime
import hashlib
import hmac
import json
from typing import Dict, Any

import requests
import rfc3339
import sys
import urllib

from string import Template
from urllib.parse import urlparse


class Signature(object):
    # The order and white space usage is very important. Any change
    # can alter the signature and cause the request to fail.
    SIGNATURE_TEMPLATE = Template("""\
$param_method
$param_uri
$param_query_parameters
$param_key_id
$param_timestamp
$param_signature_version
$param_content_sha256
$param_content_type
$param_content_length""")

    def __init__(self, exrest):
        self.exrest = exrest

    def sign(self):
        exrest = self.exrest

        string_to_sign = self.SIGNATURE_TEMPLATE.substitute({
            "param_method": exrest.method.upper(),
            "param_uri": exrest.url_encoded_uri,
            "param_query_parameters": exrest.url_encoded_query_parameters,
            "param_key_id": exrest.key_id,
            "param_timestamp": exrest.timestamp,
            "param_signature_version": exrest.signature_version,
            "param_content_sha256": exrest.content_sha256,
            "param_content_type": exrest.content_type,
            "param_content_length": exrest.content_length
        })

        # Decode the key and create the signature.
        secret_key_data = binascii.unhexlify(exrest.key)
        hasher = hmac.new(secret_key_data, msg=string_to_sign.encode('utf-8'), digestmod=hashlib.sha256)
        signature = binascii.hexlify(hasher.digest())
        return signature.decode('utf-8')


class ExRest(object):
    SIGNATURE_VERSION = "1.0"
    CONTENT_TYPE = "application/json"

    HEADER_CONTENT_TYPE = "Content-Type"
    HEADER_CONTENT_LENGTH = "Content-Length"
    HEADER_SIGNATURE_VERSION = "X-Cisco-Crosswork-Cloud-Signature-Version"
    HEADER_TIMESTAMP = "Timestamp"
    HEADER_AUTHORIZATION = "Authorization"

    def __init__(self):
        # Input arguments to the script.
        self.uri = None
        self.payload = None
        self.method = None
        self.host = None
        self.port = None
        self.key = None
        self.key_id = None

        # Values used to calculate the signature.
        self.url_encoded_uri = None
        self.url_encoded_query_parameters = None
        self.timestamp = None
        self.content_sha256 = None
        self.content_length = 0
        self.content_type = self.CONTENT_TYPE
        self.signature_version = self.SIGNATURE_VERSION

    def run(self):
        # Calculate the full URI to be run.
        uri = self.uri[1:] if self.uri.startswith("/") else self.uri
        self.uri = f"https://{self.host}:{self.port}/{uri}"

        # The url encoded uri is used when calculating the request signature.
        parsed_uri = urlparse(self.uri)
        self.url_encoded_uri = urllib.parse.quote(parsed_uri.path, safe="")
        self.url_encoded_query_parameters = urllib.parse.quote(parsed_uri.query)

        # Calculate the rfc3339 timestamp for the request.
        now = datetime.datetime.now()
        self.timestamp = rfc3339.rfc3339(now)

        # Calculate the SHA256 of the body of the request, even if the body is empty.
        self.content_sha256, self.content_length, payload_contents = self.calculate_content_sha256(self.payload)

        # Calculate a signature for the request.
        signer = Signature(self)
        request_signature_b64 = signer.sign()

        # Create the request object and set the required http headers.
        headers = dict()

        headers[self.HEADER_AUTHORIZATION] = "hmac {}:{}".format(self.key_id, request_signature_b64)
        headers[self.HEADER_TIMESTAMP] = self.timestamp
        headers[self.HEADER_CONTENT_TYPE] = self.content_type
        headers[self.HEADER_SIGNATURE_VERSION] = self.SIGNATURE_VERSION

        session = requests.Session()

        response = session.request(self.method, self.uri, data=payload_contents, headers=headers)

        parsed_response: Dict[str, Any] = dict()
        if len(response.content) > 0:
            content = response.content.decode('utf-8')
            try:
                parsed_response = json.loads(content)
            except ValueError:
                parsed_response = dict()
                parsed_response["Message"] = content.strip()

        if response.status_code != 200:
            parsed_response["HttpStatus"] = response.status_code

        print(json.dumps(parsed_response, indent=2))

    def calculate_content_sha256(self, payload):
        if payload:
            try:
                with open(payload) as fd:
                    payload_contents = fd.read()
            except Exception as error:
                raise Exception(f'Cannot read payload file {payload}: {error}')
        else:
            payload_contents = ""

        hasher = hashlib.sha256()
        hasher.update(payload_contents.encode('utf-8'))

        content_sha256 = binascii.hexlify(hasher.digest())

        return content_sha256.decode('utf-8'), len(payload_contents), payload_contents


def main():
    parser = argparse.ArgumentParser(description="Exercise the REST API.")

    parser.add_argument("--uri", default="/api/beta/truefalse/1/200",
                        help="The URI to run")

    parser.add_argument("--key", required=True,
                        help="A Cisco Crosswork Network Insights API Key")

    parser.add_argument("--keyid", required=True,
                        help="A Cisco Crosswork Network Insights API Key ID")

    parser.add_argument("--payload",
                        help="The name of a file containing JSON data for POST API requests")

    parser.add_argument("--method", choices=["GET", "POST"], default="GET",
                        help="The HTTP method for the request")

    parser.add_argument("--host", default="crosswork.cisco.com",
                        help="The Cisco Crosswork Network Insights URL")

    parser.add_argument("--port", type=int, default=443,
                        help="The Cisco Crosswork Network Insights port number")

    # Parse the arguments
    args = parser.parse_args()

    exrest = ExRest()

    exrest.uri = args.uri
    exrest.payload = args.payload
    exrest.method = args.method
    exrest.host = args.host
    exrest.port = args.port
    exrest.key = args.key
    exrest.key_id = args.keyid

    exrest.run()


if __name__ == "__main__":
    sys.exit(main())