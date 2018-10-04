__author__ = 'Aaron Weaver'

from dojo.models import Endpoint, Finding
from datetime import datetime
from jinja2 import Template
from .utils import detail_definitions
import json


class SSLlabsParser(object):


    def __init__(self, filename, test):
        data = json.load(filename)
        with open("template.description.j2") as f:
            description_template = Template(f.read())

        find_date = datetime.now()
        dupes = {}

        # helpers
        # Version 2 of SSL Labs API is deprecated
        def versioncheck(endpoints):
            if "cert" in endpoints["endpoints"]["details"]:
                return "v2"
            elif "certChains" in endpoints["endpoints"]["details"]:
                return "v3"

        def suite_info(suite_list):
            suite_data = ""
            for suites in suite_list:
                suite_list += suites["name"] + "\n"
                suite_list += "Cipher Strength: " + str(suites["cipherStrength"]) + "\n"
                if "ecdhBits" in suites:
                    suite_list += "ecdhBits: " + str(suites["ecdhBits"]) + "\n"
                if "ecdhStrength" in suites:
                    suite_list += "ecdhStrength: " + str(suites["ecdhStrength"])
                suite_list += "\n\n"
                suite_data += suite_list
            return suite_data


        def finding_builder(endpoints):
            pass

        def description_builder(**endpoint_data):
            return description_template.render(**endpoint_data)

        # parser
        for host in data:
            if "endpoints" in host:
                ssl_endpoints = host["endpoints"]
                for endpoints in ssl_endpoints:
                    version = versioncheck(endpoints)
                    categories = ''
                    language = ''
                    mitigation = 'N/A'
                    impact = 'N/A'
                    references = ''
                    findingdetail = ''
                    title = ''
                    group = ''
                    status = ''
                    port = ''
                    hostName = ''
                    ipAddress = ''
                    protocol = ''

                    endpoint_data = {}
                    # Basics
                    endpoint_data["version"] = version
                    endpoint_data["grade"] = endpoints.get("grade", None)
                    endpoint_data["hostname"] = host.get("host", None)
                    endpoint_data["port"] = host.get("port", None)
                    endpoint_data["ipaddress"] = endpoints.get("ipAddress", None)
                    endpoint_data["protocol"] = host.get("protocol", None)

                    # Cert Information / Collection
                    if "cert" in endpoints["details"]:
                        endpoint_data["cert"] = endpoints["details"].pop("cert", None)
                    elif "certs" in endpoints:
                        endpoint_data["certs"] = endpoints.get("certs", None)

                    if version == "v2":
                        details = endpoints["details"]
                        endpoint_data["key"] = details.pop("key")
                        endpoint_data["protocols"] = details.pop("protocols")
                        endpoint_data["suites"] = details.pop("suites")
                        endpoint_data["hostStartTime"] = details.pop("hostStartTime")
                        endpoint_data["sims"] = details.pop("sims")
                        endpoint_data["dhPrimes"] = details.pop("dhPrimes")
                        endpoint_data["hstsPolicy"] = details.pop("hstsPolicy")
                        endpoint_data["hstsPreloads"] = details.pop("hstsPreloads")
                        endpoint_data["hpkpPolicy"] = details.pop("hpkpPolicy")
                        endpoint_data["hpkpRoPolicy"] = details.pop("hpkpRoPolicy")
                        endpoint_data["drownHosts"] = details.pop("drownHosts")
                        endpoint_data["vulnInfo"] = details

                        for key, value in endpoint_data["vulnInfo"]:
                            if key.upper() in detail_definitions:
                                endpoint_data[key] = detail_definitions[value]


                        pass
                    if version == "v3":
                        pass
                    # v2 cert information


                    # Severity

                    endpoint_data["severity"] = self.getcriticalityrating(endpoints.get("grade"))

                    # Build Ticket Information
                    description = description_builder()



                    dupe_key = hostName + grade

                    # checking for duplicate findings
                    if dupe_key in dupes:
                        find = dupes[dupe_key]
                        if description is not None:
                            find.description += description
                    else:
                        find = Finding(title=title,
                                       cwe=310,  # Cryptographic Issues
                                       test=test,
                                       active=False,
                                       verified=False,
                                       description=description,
                                       severity=sev,
                                       numerical_severity=Finding.get_numerical_severity(sev),
                                       mitigation=mitigation,
                                       impact=impact,
                                       references=references,
                                       url=host,
                                       date=find_date,
                                       dynamic_finding=True)
                        dupes[dupe_key] = find
                        find.unsaved_endpoints = list()

                    find.unsaved_endpoints.append(Endpoint(host=ipAddress, fqdn=hostName, port=port, protocol=protocol))

            self.items = dupes.values()

    # Criticality rating
    # Grades: https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
    # A - Info, B - Medium, C - High, D/F/M/T - Critical
    @staticmethod
    def getcriticalityrating(rating):
        criticality = "Info"
        if "A" in rating:
            criticality = "Info"
        elif "B" in rating:
            criticality = "Medium"
        elif "C" in rating:
            criticality = "High"
        elif "D" in rating or "F" in rating or "M" in rating or "T" in rating:
            criticality = "Critical"

        return criticality
