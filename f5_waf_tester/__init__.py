import re
import sys
import ssl
import json
import socket
import logging
import requests
from os import path
from getpass import getpass
from collections import defaultdict
from multiprocessing.pool import ThreadPool
from requests.compat import urlparse, urljoin, quote_plus
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

from f5_waf_tester.bigip import ASM

__version__ = "0.1.1b"
__folder__ = path.abspath(path.dirname(__file__))
__app_name__ = path.basename(__folder__)

CONFIG_TEMPLATE = {
    "big-ip": {
        "host": "",
        "username": "",
        "password": ""
    },
    "asm_policy_name": "",
    "virtual_server_url": "",
    "blocking_regex": "<br>Your support ID is: (?P<id>\\d+)<br>",
    "threads": 25,
    "filters": {
        "include": {
            "id": [],
            "system": [],
            "attack_type": []
        },
        "exclude": {
            "id": [],
            "system": [],
            "attack_type": []
        }
    }
}


class F5WAFTester(object):
    def __init__(self, configuration_path=path.join(__folder__, "config", "config.json"),
                 tests_path=path.join(__folder__, "config", "tests.json")):
        self.logger = logging.getLogger(__name__)

        if not path.exists(configuration_path):
            raise Exception("Configuration not found, you can initialize the default configuration.")

        with open(configuration_path) as cf:
            self.config = json.load(cf)

        with open(tests_path) as tf:
            self.tests = json.load(tf)

        self.pool = ThreadPool(self.config.get("threads"))
        self.asm = ASM(
            host=self.config["big-ip"]["host"],
            username=self.config["big-ip"]["username"],
            password=self.config["big-ip"]["password"]
        )
        self.policy = self.asm.policy_by_name(self.config.get("asm_policy_name"))
        self.report = None

    def generate_tests(self):
        include = self.config["filters"]["include"]
        exclude = self.config["filters"]["exclude"]

        for test in self.tests:
            if (include["id"] and test["id"] not in include["id"]) or \
                    (include["system"] and test["system"] not in include["system"]) or \
                    (include["attack_type"] and test["attack_type"] not in include["attack_type"]):
                continue

            if test["id"] in exclude["id"] or \
                    test["system"] in exclude["system"] or \
                    test["attack_type"] in exclude["attack_type"]:
                continue

            vectors = test.pop("vectors")
            for vector in vectors:
                expected_result = vector.pop("expected_result")
                yield {
                    "url": self.config["virtual_server_url"],
                    "test": test,
                    "vector": vector,
                    "expected_result": expected_result
                }

    def test_vector(self, url, test, vector, expected_result):
        res = ""
        res_encoding = "utf-8"
        error = None
        user_agent = "%s %s" % (__app_name__, __version__)
        try:
            if vector["applies_to"] == "request":
                url_parsed = urlparse(url)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                port = url_parsed.port
                if not port:
                    if url_parsed.scheme == "http":
                        port = 80
                    elif url_parsed.scheme == "https":
                        port = 443

                if url_parsed.scheme == "https":
                    s = ssl.wrap_socket(s)
                s.connect((url_parsed.hostname, port))
                req = vector["payload"].format(
                    hostname=url_parsed.hostname,
                    user_agent=user_agent,
                    appname=__app_name__
                ).encode('utf-8')
                s.sendall(req)
                res = s.recv(4096)
                if res.endswith(b"\r\n\r\n"):
                    res += s.recv(4096)
                s.close()
            else:
                request_args = {
                    "verify": False,
                    "method": vector.get("method", "GET"),
                    "url": urljoin(url, "/%s/" % __app_name__),
                    "params": {},
                    "headers": {
                        "User-Agent": user_agent
                    }
                }
                if vector["applies_to"] == "parameter":
                    request_args["params"] = {
                        vector.get("key", "%s_%s" % (__app_name__, vector["applies_to"])): vector["payload"]
                    }
                elif vector["applies_to"] == "header":
                    request_args["headers"] = {
                        vector.get("key", "%s_%s" % (__app_name__, vector["applies_to"])): vector["payload"]
                    }
                elif vector["applies_to"] == "url":
                    request_args["url"] = urljoin(request_args["url"], quote_plus(vector["payload"], safe='/'))

                res = requests.request(**request_args).content
        except Exception as ex:
            error = ex
            print(error)

        re_res = re.search(self.config['blocking_regex'].encode(res_encoding), res)
        result = {
            "test": test,
            "vector": vector,
            "error": error,
            "expected_result": expected_result,
            "result": re_res.group('id').decode(res_encoding) if re_res else None
        }

        self.logger.info("Test {id}/{applies_to} {result}".format(
            id=test['id'], applies_to=vector["applies_to"],
            result="pass" if re_res else "failed"

        ))
        return result

    def _get_report_without_reasons(self):
        report = {
            "summary": {
                "fail": 0,
                "pass": 0,
            },
            "details": defaultdict(dict)
        }

        for res in self.pool.imap_unordered(lambda t: self.test_vector(**t), self.generate_tests()):
            test_id = res["test"]["id"]
            test_applies_to = res["vector"]["applies_to"]

            report["details"][test_id]["CVE"] = res["test"]["CVE"]
            report["details"][test_id]["name"] = res["test"]["name"]
            report["details"][test_id]["system"] = res["test"]["system"]
            report["details"][test_id]["attack_type"] = res["test"]["attack_type"]

            if not report["details"][test_id].get("results"):
                report["details"][test_id]["results"] = defaultdict(dict)

            report["details"][test_id]["results"][test_applies_to]["reason"] = ""
            report["details"][test_id]["results"][test_applies_to]["support_id"] = ""
            report["details"][test_id]["results"][test_applies_to]["expected_result"] = res["expected_result"]

            if not res["result"]:
                report["details"][test_id]["results"][test_applies_to]["pass"] = False
                report["summary"]["fail"] += 1
                continue

            report["details"][test_id]["results"][test_applies_to]["support_id"] = res["result"]
            report["details"][test_id]["results"][test_applies_to]["pass"] = True
            report["summary"]["pass"] += 1
            if not self.policy:
                event = self.asm.events(res["result"], select=["requestPolicyReference"])
                self.policy = self.asm.policy(path.basename(urlparse(event["requestPolicyReference"]["link"]).path))

        return report

    def _get_global_reasons(self):
        reasons = {
            "signature": {
                "url": "",
                "header": "",
                "parameter": "",
                "request": ""
            },
            "evasion": {
                "url": "",
                "header": "",
                "parameter": "",
                "request": ""
            },
            "violation": {
                "url": "",
                "header": "",
                "parameter": "",
                "request": ""
            }
        }

        # All Tests Failed And No Policy Found
        if not self.policy:
            for typ in reasons:
                for applies_to in reasons[typ]:
                    reasons[typ][applies_to] = "Unknown, Maybe ASM Policy is not in blocking mode"
            return reasons

        # Policy In Transparent Mode
        if self.policy.enforcement_mode != "blocking":
            for typ in reasons:
                for applies_to in reasons[typ]:
                    reasons[typ][applies_to] = "ASM Policy is not in blocking mode"
            return reasons

        # Check Header * WildCard
        header_wildcard = self.policy.get(
            "headers",
            filter="name eq '*'",
            select=["checkSignatures", "signatureOverrides", "type", "name"]
        )["items"][0]
        if not header_wildcard["checkSignatures"]:
            reasons["signature"]["header"] = "Header * Does not check signatures"

        # Check Parameter * WildCard
        parameter_wildcard = self.policy.get(
            "parameters",
            filter="name eq '*'",
            select=["attackSignaturesCheck", "signatureOverrides", "performStaging", "type", "name"]
        )["items"][0]
        if parameter_wildcard["performStaging"]:
            for typ in reasons:
                reasons[typ]["parameter"] = "Parameter * is in staging"
        elif not parameter_wildcard["attackSignaturesCheck"]:
            reasons["signature"]["parameter"] = "Parameter * Does not check signatures"

        # Check If Blocking Evasions
        if not self.policy.get(
                "blocking-settings/violations",
                filter="description eq 'Evasion technique detected'",
                select=["block", "description"])["items"][0]["block"]:
            for applies_to in reasons["evasion"]:
                reasons["evasion"][applies_to] = "Evasion technique is not in blocking mode"

        return reasons

    def get_report(self):
        report = self._get_report_without_reasons()
        if not report["summary"]["fail"]:
            return report

        global_reasons = self._get_global_reasons()

        signatures = {}
        evasions = {}
        violations = {}
        if self.policy:
            signature_staging = self.policy.get("signature-settings", select="signatureStaging")["signatureStaging"]

            signatures = {
                path.basename(urlparse(item["signatureReference"]["link"]).path): {
                    "enabled": item.get("enabled", False),
                    "block": item.get("block", False),
                    "exists": True,
                    "staging": signature_staging and item.get("performStaging", False)
                } for item in
                self.policy.get(
                    "signatures",
                    select=["enabled", "block", "signatureReference/link", "performStaging"]
                )["items"]
            }

            signatures = {
                str(item["signatureId"]): signatures.get(item["id"], {
                    "enabled": False,
                    "block": False,
                    "staging": False,
                    "exists": False
                }) for item in
                self.asm.get("signatures", filter="signatureType eq request", select=["id", "signatureId"])["items"]
            }

            evasions = {
                item["description"]: item.get("enabled", False) for item in
                self.policy.get("blocking-settings/evasions", select=["enabled", "description"])["items"]
            }

            violations = {
                item["description"]: item.get("block", False) for item in
                self.policy.get("blocking-settings/violations", select=["block", "description"])["items"]
            }

        report_details = report["details"]
        for test_id, details in report_details.items():
            for applies_to, result in details["results"].items():
                expected_result = result.get("expected_result")
                if result["pass"]:
                    continue

                typ = expected_result["type"]
                if global_reasons[typ][applies_to]:
                    result["reason"] = global_reasons[typ][applies_to]
                    continue

                if not self.policy:
                    continue

                if typ == "signature":
                    if expected_result["value"] not in signatures:
                        reason = "Attack Signatures are not up to date"
                        result["reason"] = reason
                        continue

                    if not signatures[expected_result["value"]]["exists"]:
                        reason = "Attack Signature is not in the ASM Policy"
                        result["reason"] = reason
                        continue

                    if not signatures[expected_result["value"]]["enabled"]:
                        reason = "Attack Signature disabled"
                        result["reason"] = reason
                        continue

                    if not signatures[expected_result["value"]]["block"]:
                        reason = "Attack Signature is not blocking"
                        result["reason"] = reason
                        continue

                    if signatures[expected_result["value"]]["staging"]:
                        reason = "Attack Signature is in staging"
                        result["reason"] = reason
                        continue

                if typ == "evasion":
                    if not evasions.get(expected_result["value"]):
                        reason = "Evasion disabled"
                        result["reason"] = reason
                        continue

                if typ == "violation":
                    if not violations.get(expected_result["value"]):
                        reason = "Violation disabled"
                        result["reason"] = reason
                        continue

                # Check URL * WildCard
                url_wildcard = self.policy.get(
                    "urls",
                    filter="name eq '*'",
                    select=["attackSignaturesCheck", "signatureOverrides", "performStaging", "type", "name"]
                )["items"][0]
                if url_wildcard["performStaging"]:
                    reason = "URL * is in staging"
                    result["reason"] = reason
                elif not url_wildcard["attackSignaturesCheck"]:
                    reason = "URL * Does not check signatures"
                    result["reason"] = reason

                if not result["reason"]:
                    reason = "Unknown fail reason"
                    result["reason"] = reason

        return report

    def start(self, report_path='report.json'):
        self.report = self.get_report()
        report = json.dumps(self.report, indent=2, sort_keys=True)
        with open(report_path, 'w') as f:
            f.write(report)
            f.flush()
        print(report)
        return self.report["summary"]["fail"]

    @staticmethod
    def init(configuration_path=path.join(__folder__, "config", "config.json")):
        config = CONFIG_TEMPLATE
        if path.exists(configuration_path):
            with open(configuration_path) as config_file:
                config = json.load(config_file)

        config["big-ip"]["host"] = prompt("[BIG-IP] Host", default=config["big-ip"]["host"])
        config["big-ip"]["username"] = prompt("[BIG-IP] Username", default=config["big-ip"]["username"])
        config["big-ip"]["password"] = prompt("[BIG-IP] Password", default=config["big-ip"]["password"], password=True)

        config["asm_policy_name"] = prompt("ASM Policy Name", default=config["asm_policy_name"])
        config["virtual_server_url"] = prompt("Virtual Server URL", default=config["virtual_server_url"])
        config["blocking_regex"] = prompt("Blocking Regular Expression Pattern", default=config["blocking_regex"])
        config["threads"] = int(prompt("Number OF Threads", default=config["threads"]) or 1)

        config["filters"]["include"]["id"] = prompt(
            "[Filters] Test IDs to include (Separated by ',')",
            default=config["filters"]["include"]["id"]
        )
        config["filters"]["include"]["system"] = prompt(
            "[Filters] Test Systems to include (Separated by ',')",
            default=config["filters"]["include"]["system"]
        )
        config["filters"]["include"]["attack_type"] = prompt(
            "[Filters] Test Attack Types to include (Separated by ',')",
            default=config["filters"]["include"]["attack_type"]
        )

        config["filters"]["exclude"]["id"] = prompt(
            "[Filters] Test IDs to exclude (Separated by ',')",
            default=config["filters"]["exclude"]["id"]
        )
        config["filters"]["exclude"]["system"] = prompt(
            "[Filters] Test Systems to exclude (Separated by ',')",
            default=config["filters"]["exclude"]["system"]
        )
        config["filters"]["exclude"]["attack_type"] = prompt(
            "[Filters] Test Attack Types to exclude (Separated by ',')",
            default=config["filters"]["exclude"]["attack_type"]
        )

        with open(configuration_path, 'w') as cf:
            json.dump(config, cf, indent=2)


def prompt(msg, default="", password=False):
    try:
        prompt_func = raw_input
    except NameError:
        prompt_func = input
    default_msg = str(default)

    if password:
        prompt_func = getpass
        default_msg = "*" * len(default)

    if isinstance(default, list):
        default_msg = ",".join(map(str, default))
        res = prompt_func("%s [%s]: " % (msg, default_msg)).strip()
        if res:
            if res.lower() == 'null':
                return []
            res = map(lambda s: s.strip(), res.split(','))
        return list(res) or default

    res = prompt_func("%s [%s]: " % (msg, default_msg)).strip()
    if res.lower() == 'null':
        return ""
    return res or default


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("-v", "--version", action="version", version="%(prog)s {ver}".format(ver=__version__))

    parser.add_argument("-i", "--init",
                        help="Initialize Configuration.",
                        action='store_true')

    parser.add_argument("-c", "--config",
                        help="Configuration File Path.",
                        default=path.join(__folder__, "config", "config.json"))
    parser.add_argument("-t", "--tests",
                        help="Tests File Path.",
                        default=path.join(__folder__, "config", "tests.json"))
    parser.add_argument("-r", "--report",
                        help="Report File Save Path.",
                        default="report.json")

    sys_args = vars(parser.parse_args(args=args))

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%d-%m-%y %H:%M:%S")
    logging.getLogger("requests.packages.urllib3.connectionpool").disabled = True

    if sys_args['init']:
        return F5WAFTester.init(configuration_path=sys_args['config'])

    sys.exit(F5WAFTester(
        configuration_path=sys_args['config'], tests_path=sys_args['tests']
    ).start(report_path=sys_args['report']))
