__version__ = "1.0"
__appname__ = "fmc_policy_viewer"
__author__ = "Cesar Barrientos"
__description__ = "Script to visualize the rules from a ACP"

# imports
from fireREST import FMC
import json
import pandas as pd

print("-----" * 10)
print("Welcome")
print("-----" * 10)

management_center = {
    "ip_address": "10.48.26.181",
    "username": "admin",
    "password": "Admin123",
    "domain": "Global",
    "acp": "FTD"
}


def main(management_center):
    print("Getting access to the FMC")
    fmc = FMC(hostname=management_center['ip_address'], username=management_center['username'],
              password=management_center['password'], domain=management_center['domain'])

    # Getting the ACP.
    print("-----" * 10)
    print(f"Reading rules from the ACP {management_center['acp']}")
    acp = fmc.policy.accesspolicy.accessrule.get(container_name=management_center['acp'])
    print(f"Finished - Read {len(acp)} rules")
    print("-----" * 10)

    print("Collecting objects...")
    print("-----" * 10)
    # Format:
    # {'links': {'self': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts/0050568D-B7BF-0ed3-0000-025769805013', 'parent': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkaddresses'}, 'type': 'Host', 'value': '4.25.98.109', 'overridable': False, 'description': 'Object Created With Firestorm: Your Honor, I Object', 'name': '4.25.98.109', 'id': '0050568D-B7BF-0ed3-0000-025769805013', 'metadata': {'timestamp': 1560849585793, 'lastUser': {'name': 'admin'}, 'domain': {'name': 'Global', 'id': 'e276abec-e0f2-11e3-8169-6d9ed49b625f', 'type': 'Domain'}, 'ipType': 'V_4', 'parentType': 'NetworkAddress'}}
    print("Getting Object Host")
    obj_host = fmc.object.host.get()
    _obj_host = {}
    for host in obj_host:
        _obj_host.update({host["name"]: host["value"]})

    # Getting the Objects
    # Format:
    # {'links': {'self': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networks/cb7116e8-66a6-480b-8f9b-295191a0940a', 'parent': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkaddresses'}, 'type': 'Network', 'value': '0.0.0.0/0', 'overridable': False, 'description': ' ', 'name': 'any-ipv4', 'id': 'cb7116e8-66a6-480b-8f9b-295191a0940a', 'metadata': {'readOnly': {'state': True, 'reason': 'SYSTEM'}, 'timestamp': 1542324027916, 'lastUser': {'name': 'admin'}, 'domain': {'name': 'Global', 'id': 'e276abec-e0f2-11e3-8169-6d9ed49b625f', 'type': 'Domain'}, 'ipType': 'V_4', 'parentType': 'NetworkAddress'}}
    print("Getting Object Networks")
    obj_networks = fmc.object.network.get()
    _obj_networks = {}
    for networks in obj_networks:
        _obj_networks.update({networks["name"]: networks["value"]})

    # Format
    # {'links': {'self': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/69fa2a3a-4487-4e3c-816f-4098f684826e'}, 'type': 'NetworkGroup', 'literals': [{'type': 'Network', 'value': '::/0'}, {'type': 'Network', 'value': '0.0.0.0/0'}], 'overridable': False, 'description': ' ', 'name': 'any', 'id': '69fa2a3a-4487-4e3c-816f-4098f684826e', 'metadata': {'readOnly': {'state': True, 'reason': 'SYSTEM'}, 'timestamp': 1542324027916, 'lastUser': {'name': 'admin'}, 'domain': {'name': 'Global', 'id': 'e276abec-e0f2-11e3-8169-6d9ed49b625f', 'type': 'Domain'}}}
    print("Getting Group Networks")
    obj_grp_networks = fmc.object.networkgroup.get()
    _obj_grp_networks = {}
    for group in obj_grp_networks:
        _obj_grp_networks.update({group['name']: {}})
    for group in obj_grp_networks:
        if "literals" in group.keys():
            for inside in group["literals"]:
                _obj_grp_networks[group["name"]].update({inside["value"]: inside["value"]})
        elif "objects" in group.keys():
            for inside in group["objects"]:
                if "Host" in inside["type"]:
                    _obj_grp_networks[group['name']].update({inside['name']: _obj_host[inside['name']]})
                elif "NetworkGroup" in inside["type"]:
                    _obj_grp_networks[group['name']].update(
                        {inside["name"]: {"values": _obj_grp_networks[inside["name"]]}})
                elif "Network" in inside["type"]:
                    _obj_grp_networks[group['name']].update({inside["name"]: _obj_networks[inside["name"]]})

    # Format:
    # {'links': {'self': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ranges/0050568D-B7BF-0ed3-0000-197568497455', 'parent': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkaddresses'}, 'type': 'Range', 'value': '1.1.1.1-1.1.1.5', 'overridable': False, 'description': ' ', 'name': 'New_range', 'id': '0050568D-B7BF-0ed3-0000-197568497455', 'metadata': {'timestamp': 1644593771633, 'lastUser': {'name': 'admin'}, 'domain': {'name': 'Global', 'id': 'e276abec-e0f2-11e3-8169-6d9ed49b625f', 'type': 'Domain'}, 'ipType': 'V_4', 'parentType': 'NetworkAddress'}}
    print("Getting ranges")
    obj_range = fmc.object.range.get()
    _obj_range = {}
    for ran in obj_range:
        _obj_range.update({ran["name"]: ran["value"]})

    # Format:
    # {'links': {'self': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/fqdns/0050568D-B7BF-0ed3-0000-047244640335', 'parent': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkaddresses'}, 'type': 'FQDN', 'value': 'google.com', 'dnsResolution': 'IPV4_AND_IPV6', 'overridable': False, 'description': ' ', 'name': 'Google', 'id': '0050568D-B7BF-0ed3-0000-047244640335', 'metadata': {'timestamp': 1562082356530, 'lastUser': {'name': 'admin'}, 'domain': {'name': 'Global', 'id': 'e276abec-e0f2-11e3-8169-6d9ed49b625f', 'type': 'Domain'}, 'parentType': 'NetworkAddress'}}
    print("Getting fqdn")
    obj_fqdn = fmc.object.fqdn.get()
    _obj_fqdn = {}
    for fqdn in obj_fqdn:
        _obj_fqdn.update({fqdn["name"]: fqdn["value"]})

    # Format:
    # {'metadata': {'readOnly': {'state': True, 'reason': 'SYSTEM'}, 'timestamp': 1542324028063, 'lastUser': {'name': 'admin'}, 'domain': {'name': 'Global', 'id': 'e276abec-e0f2-11e3-8169-6d9ed49b625f', 'type': 'Domain'}, 'parentType': 'Port'}, 'links': {'self': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/protocolportobjects/1834d812-38bb-11e2-86aa-62f0c593a59a', 'parent': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ports'}, 'type': 'ProtocolPortObject', 'port': '5190', 'protocol': 'TCP', 'overridable': False, 'description': ' ', 'name': 'AOL', 'id': '1834d812-38bb-11e2-86aa-62f0c593a59a'}
    print("Getting port")
    obj_port = fmc.object.port.get()
    _obj_port = {}
    for port in obj_port:
        if "ProtocolPortObject" in port["type"]:
            _obj_port.update(
                {port["name"]: {'Protocol': port["protocol"], 'Port': port["port"] if "port" in port.keys() else ""}})
        elif "ICMPV4Object" in port["type"]:
            _obj_port.update({port["name"]: {'icmpType': port["icmpType"]}})
    # Format:
    # {'metadata': {'timestamp': 1646738725403, 'lastUser': {'name': 'admin'}, 'domain': {'name': 'Global', 'id': 'e276abec-e0f2-11e3-8169-6d9ed49b625f', 'type': 'Domain'}, 'parentType': 'Port'}, 'links': {'self': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/portobjectgroups/0050568D-B7BF-0ed3-0000-197568506698', 'parent': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ports'}, 'type': 'PortObjectGroup', 'objects': [{'type': 'ProtocolPortObject', 'port': '53', 'overridable': False, 'name': 'DNS_over_TCP', 'id': '1834e712-38bb-11e2-86aa-62f0c593a59a'}, {'type': 'ProtocolPortObject', 'port': '53', 'overridable': False, 'name': 'DNS_over_UDP', 'id': '1834e8ca-38bb-11e2-86aa-62f0c593a59a'}], 'overridable': False, 'description': ' ', 'name': 'Group_DNS', 'id': '0050568D-B7BF-0ed3-0000-197568506698'}
    print("Getting port object group")
    obj_grp_port = fmc.object.portobjectgroup.get()
    _obj_grp_port = {}
    for grp_port in obj_grp_port:
        _obj_grp_port.update({grp_port['name']: {}})
        for obj in grp_port["objects"]:
            if "ProtocolPortObject" in obj["type"]:
                _obj_grp_port[grp_port["name"]].update(
                    {obj["name"]: {"Protocol": _obj_port[obj["name"]]["Protocol"],
                                   "Port": _obj_port[obj["name"]]["Port"]}})
            elif "ICMPV4Object" in obj["type"]:
                _obj_grp_port[grp_port["name"]].update(
                    {obj["name"]: {"icmpType": _obj_port[obj["name"]]["icmpType"],
                                   "Port": _obj_port[obj["name"]]["Port"] if "Port" in port.keys() else ""}})
    # Format:
    # {'metadata': {'readOnly': {'state': True, 'reason': 'SYSTEM'}, 'timestamp': 1542324028063, 'lastUser': {'name': 'admin'}, 'domain': {'name': 'Global', 'id': 'e276abec-e0f2-11e3-8169-6d9ed49b625f', 'type': 'Domain'}, 'parentType': 'Port'}, 'links': {'self': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/protocolportobjects/1834d812-38bb-11e2-86aa-62f0c593a59a', 'parent': 'https://10.48.26.181/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ports'}, 'type': 'ProtocolPortObject', 'port': '5190', 'protocol': 'TCP', 'overridable': False, 'description': ' ', 'name': 'AOL', 'id': '1834d812-38bb-11e2-86aa-62f0c593a59a'}
    print("Getting protocol port object")
    obj_prot_port = fmc.object.protocolportobject.get()

    print("-----" * 10)
    print("Building the ACP output...")

    # Building the new information
    def select_network(object):
        if "objects" in object.keys():
            return expand_networks(object["objects"])
        elif "literals" in object.keys():
            answer = {}
            answer.update({"literals": {}})
            lits = []
            # [{'type': 'Host', 'value': '10.28.24.211'}, {'type': 'Host', 'value': '10.28.24.212'}]
            for literal in object["literals"]:
                lits.append([{"value": literal["value"]}])
                answer["literals"].update({"values": lits})
            return answer

    def expand_networks(object):
        answer = {}
        for network in object:
            answer.update({network["name"]: {}})
            if "NetworkGroup" in network["type"]:
                answer[network["name"]].update({"networks": _obj_grp_networks[network["name"]]})
            elif "Network" in network["type"]:
                answer[network["name"]].update({"networks": _obj_networks[network["name"]]})
            elif "Range" in network["type"]:
                answer[network["name"]].update({"range": _obj_range[network["name"]]})
            elif "Host" in network["type"]:
                answer[network["name"]].update({"value": _obj_host[network["name"]]})
            elif "FQDN" in network["type"]:
                answer[network["name"]].update({"value": _obj_fqdn[network["name"]]})
            elif "Continent" in network["type"]:
                answer[network["name"]].update({network["type"]: network["name"]})
        return answer

    def select_port(object):
        if "objects" in object.keys():
            return expand_port(object["objects"])
        elif "literals" in object.keys():
            answer = {}
            answer.update({"literals": {}})
            lits = []
            # {'literals': [{'type': 'PortLiteral', 'port': '53', 'protocol': '6'}, {'type': 'PortLiteral', 'port': '53', 'protocol': '17'}]}
            for literal in object["literals"]:
                if 'ICMPv4PortLiteral' in literal["type"]:
                    answer["literals"].update({"icmpType": literal["icmpType"], "protocol": literal["protocol"]})
                elif 'PortLiteral' in literal["type"]:
                    lits.append([{"protocol": literal["protocol"], "port": literal["port"] if "port" in rule.keys() else "none"}])
                    answer["literals"].update({"literals": lits})
                else:
                    answer["literals"].update({"port": literal["port"], "protocol": literal["protocol"]})
            return answer

    def expand_port(object):
        answer = {}
        for port in object:
            answer.update({port["name"]: {}})
            if "ProtocolPortObject" in port["type"]:
                answer[port["name"]].update({"value": _obj_port[port["name"]]})
            if "PortObjectGroup" in port["type"]:
                answer[port["name"]].update({"value": _obj_grp_port[port["name"]]})
        return answer

    output = {}
    for rule in acp:
        output.update({rule["name"]: {}})
        data = {
            "index": rule["metadata"]["ruleIndex"],
            "section": rule["metadata"]["section"],
            "name": rule["name"],
            "action": rule["action"],
            "srcZone": rule["sourceZones"]["objects"][0]["name"] if "sourceZones" in rule.keys() else "any",
            "dstZone": rule["destinationZones"]["objects"][0]["name"] if "destinationZones" in rule.keys() else "any",
            "srcNetwork": select_network(
                rule["sourceNetworks"]) if "sourceNetworks" in rule.keys() else "any",
            "dstNetwork": select_network(
                rule["destinationNetworks"]) if "destinationNetworks" in rule.keys() else "any",
            "srcPorts": select_port(rule["sourcePorts"]) if "sourcePorts" in rule.keys() else "any",
            "dstPort": select_port(rule["destinationPorts"]) if "destinationPorts" in rule.keys() else "any",
            "ipsPolicy": rule["ipsPolicy"]["name"] if "ipsPolicy" in rule.keys() else "None",
            "variableSet": rule["variableSet"]["name"],
            "filePolicy": rule["filePolicy"]["name"] if "filePolicy" in rule.keys() else "None",
            "logBegin": rule["logBegin"],
            "logEnd": rule["logEnd"],
            "eventsOnFMC": rule["sendEventsToFMC"],
            "syslogConfig": rule["enableSyslog"],
            "enabled": rule["enabled"]
        }
        output[rule["name"]].update(data)

    print("Finished...")
    print("-----" * 10)
    print("Creating CSV file")
    toCSV = json.dumps(output)
    df = pd.read_json(toCSV)
    df.transpose().to_csv(f"{management_center['acp']}.csv")
    print(f"Done, CSV file \"{management_center['acp']}.csv\" has been created")


main(management_center)
