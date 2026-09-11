import json
import os
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = "http://127.0.0.1:4566"
CHALLENGE_API = "http://127.0.0.1:8055"
EVENTS = "/var/lib/route53-dns-proxy/events"

def local_name(element):
    return element.tag.rsplit("}", 1)[-1]

def child_text(element, name):
    for child in element:
        if local_name(child) == name:
            return child.text or ""
    return ""

def challenge_request(path, payload):
    request = urllib.request.Request(
        CHALLENGE_API + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        response.read()

def sync_challenges(body):
    root = ET.fromstring(body)
    for change in (node for node in root.iter() if local_name(node) == "Change"):
        action = child_text(change, "Action")
        record_set = next(
            (node for node in change if local_name(node) == "ResourceRecordSet"),
            None,
        )
        if record_set is None or child_text(record_set, "Type") != "TXT":
            continue
        host = child_text(record_set, "Name")
        if action == "DELETE":
            challenge_request("/clear-txt", {"host": host})
            continue
        for record in (
            node for node in record_set.iter() if local_name(node) == "ResourceRecord"
        ):
            value = child_text(record, "Value").strip('"')
            challenge_request("/set-txt", {"host": host, "value": value})
            with open(EVENTS, "a", encoding="ascii") as events:
                events.write(host + " " + value + "\n")

class Handler(BaseHTTPRequestHandler):
    def proxy(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        headers = {
            key: value for key, value in self.headers.items()
            if key.lower() not in {"host", "content-length"}
        }
        request = urllib.request.Request(
            UPSTREAM + self.path,
            data=body if self.command == "POST" else None,
            headers=headers,
            method=self.command,
        )
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as error:
            response = error
        response_body = response.read()

        if self.command == "POST" and "/rrset" in self.path and response.status < 300:
            sync_challenges(body)

        self.send_response(response.status)
        for key, value in response.headers.items():
            if key.lower() not in {"content-length", "transfer-encoding", "connection"}:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    do_GET = proxy
    do_POST = proxy

    def log_message(self, format, *args):
        return

os.makedirs(os.path.dirname(EVENTS), exist_ok=True)
ThreadingHTTPServer(("0.0.0.0", 4570), Handler).serve_forever()
