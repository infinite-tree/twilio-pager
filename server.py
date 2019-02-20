#!/usr/bin/env python3
"""
HTML server to bridge grafana webhook notifications to twilio flows
for paging multiple people in case of an incident
"""
import configparser
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import logging.handlers
import os
import requests
import sys
from urllib.parse import urlparse

TWILIO_FLOW_URL = "https://studio.twilio.com/v1/Flows/{sid}/Executions"

CONFIG_FILE = "/etc/twilio-pager/twilio-pager.ini"
if "TWILIO_PAGER_CONFIG" in os.environ:
    CONFIG_FILE = os.environ["TWILIO_PAGER_CONFIG"]

LOG_FILE = "/var/log/twilio-pager/twilio-pager.log"
if "TWILIO_PAGER_LOG" in os.environ:
    LOG_FILE = os.environ["TWILIO_PAGER_LOG"]


class Bridge(BaseHTTPRequestHandler):
    twilio_sid = None
    twilio_auth_token = None
    log = None
    config = None

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def _respond(self, code, message):
        self.send_response(code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write("<html><body>"+message+"</body></html>")
        self.finish()

    def do_POST(self):
        log.info("POST received: " + self.path)
        path = urlparse.urlparse(self.path)
        parts = os.path.split(path.path)
        log.info("Parts: %s"%str(parts))
        if len(parts) != 2:
            log.info("Invalid path length: %s"%path.path)
            self._respond(400, "Invalid path")
            return

        if parts[0] not in ("/twilio", "twilio"):
            log.info("Not a twilio request: %s"%path.path)
            self._respond(404, "not a twilio path")
            return

        # reload config
        self.config = configparser.ConfigParser()
        self.config.read(CONFIG_FILE)

        flow = parts[1]
        flow_data = {}
        if flow in self.config:
            self.log.info("Alert received for flow '%s'" % flow)
            if all(k in self.config[flow] for k in ("sid", "From")):
                flow_data["sid"] = self.config[flow]["sid"]
                flow_data["From"] = self.config[flow]["From"]
            else:
                self.log.error("Flow '%s' is missing parameters in the config"%flow)
                self._respond(500, "flow is missing parameters in the server config")
                return
        else:
            self.log.info("Alert recieved for unknown flow '%s'"%flow)
            self._respond(404, "unknown flow")
            return

        # At this point there is a valid populated twilio flow
        twilio_url = TWILIO_FLOW_URL.format(**flow_data)
        self.log.info("Trigger Twilio flow: %s"%twilio_url)
        content_length = int(self.headers['Content-Length'])
        post_data_str = self.rfile.read(content_length)
        post_data = json.loads(post_data_str)
        if "evalMatches" in post_data:
            del(post_data["evalMatches"])

        r = requests.post("https://api.keyvalue.xyz/new/%s"%flow)
        if r.status_code != 200:
            self.log.error("Keyvalue create failed: %d, %s" %
                           (r.status_code, r.reason))
            self._respond(500, "keyvalue creation failed: " + r.reason)
            return

        post_data["status_path"] = r.content.strip().replace(
                "https://api.keyvalue.xyz/", "")

        r = requests.post("https://api.keyvalue.xyz/%s/%s"%(post_data["status_path"], "pending"))
        if r.status_code != 200:
            self.log.error("Keyvalue set failed: %d, %s" %
                           (r.status_code, r.reason))
            self._respond(500, "keyvalue set: " + r.reason)
            return

        recipient_conf = flow+".recipients"
        if not recipient_conf in self.config:
            self.log.error(
                "Flow '%s' is missing the .recipients in the config" % flow)
            self._respond(500, "flow has no recipients")
            return

        for name, number in self.config[recipient_conf].items():
            post_data["person"] = name
            params = {"To": number, "From": flow_data["From"], "Parameters": json.dumps(post_data)}
            self.log.info("Parameters: %s" % str(params))
            resp = requests.post(twilio_url, data=params, auth=(self.twilio_sid, self.twilio_auth_token))
            self.log.info("URL: %s"%(resp.url))
            if resp.status_code != 200:
                self.log.error("Twilio POST failed: %d, %s"%(resp.status_code, resp.reason))
                self._respond(500, "Twilio post failed: " + resp.reason)
                return

        # All done
        self.log.info("Twilio POST SUCCEEDED!")
        self.respond(200, "success")
        return

def run(log, port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, Bridge)
    log.info('Starting httpd...')
    httpd.serve_forever()

if __name__ == "__main__":
    from sys import argv

    log = logging.getLogger('GRAFANA-TO-TWILIO')
    log.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
    log_file = os.path.realpath(os.path.expanduser(LOG_FILE))
    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=500000, backupCount=5)
    handler.setFormatter(formatter)
    log.addHandler(handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    log.addHandler(stream_handler)
    Bridge.log = log

    # load config vars
    log.info("Loading Config...")
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    Bridge.twilio_sid = config['twilio']['sid']
    Bridge.twilio_auth_token = config['twilio']['auth_token']
    Bridge.config = config

    if len(argv) == 2:
        run(log, port=int(argv[1]))
    else:
        run(log)
