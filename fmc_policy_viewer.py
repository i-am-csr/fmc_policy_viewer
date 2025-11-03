__version__ = "1.0.1"
__appname__ = "fmc_policy_viewer"
__author__ = "Cesar Barrientos"
__description__ = "Script to visualize the rules from a ACP"

# imports
from fireREST import FMC
import json
import pandas as pd
import os
import argparse
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

logger.info("-----" * 10)
logger.info("Welcome")
logger.info("-----" * 10)

# Default management center values (can be overridden via env or CLI)
DEFAULTS = {
    "ip_address": os.environ.get("FMC_IP", "10.48.26.181"),
    "username": os.environ.get("FMC_USER", "admin"),
    "password": os.environ.get("FMC_PASS", "Admin123"),
    "domain": os.environ.get("FMC_DOMAIN", "Global"),
    "acp": os.environ.get("FMC_ACP", "FTD"),
}


# Simple retry helper for transient API errors
def call_with_retries(func, description=None, retries=3, backoff=1.0):
    """Call `func()` with retries and exponential backoff on exception.

    func: a zero-argument callable that performs the API call and returns the result.
    description: short text used in logs.
    retries: number of attempts.
    backoff: base sleep interval in seconds, multiplied by attempt number.
    """
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            return func()
        except Exception as e:
            last_exc = e
            logger.warning("Attempt %d/%d failed to %s: %s", attempt, retries, description or getattr(func, '__name__', str(func)), e)
            if attempt == retries:
                logger.error("All %d attempts failed for: %s", retries, description or getattr(func, '__name__', str(func)))
                raise
            sleep_time = backoff * attempt
            logger.info("Sleeping %.1fs before retrying...", sleep_time)
            time.sleep(sleep_time)
    # Shouldn't reach here
    raise last_exc


# Helper functions moved to module level so they don't depend on closure scope.
# They receive the object maps created in `main` as explicit parameters so functionality is preserved.

def expand_networks(obj, obj_grp_networks, obj_networks, obj_range, obj_host, obj_fqdn):
    """Expand a list of network/object descriptors into a dictionary using the provided maps."""
    answer = {}
    for network in obj:
        answer.update({network["name"]: {}})
        if "NetworkGroup" in network["type"]:
            answer[network["name"]].update({"networks": obj_grp_networks[network["name"]]})
        elif "Network" in network["type"]:
            answer[network["name"]].update({"networks": obj_networks[network["name"]]})
        elif "Range" in network["type"]:
            answer[network["name"]].update({"range": obj_range[network["name"]]})
        elif "Host" in network["type"]:
            answer[network["name"]].update({"value": obj_host[network["name"]]})
        elif "FQDN" in network["type"]:
            answer[network["name"]].update({"value": obj_fqdn[network["name"]]})
        elif "Continent" in network["type"]:
            answer[network["name"]].update({network["type"]: network["name"]})
    return answer


def select_network(obj, obj_grp_networks, obj_networks, obj_range, obj_host, obj_fqdn):
    """Select network(s) from an object descriptor; returns expanded result using provided maps."""
    if "objects" in obj.keys():
        return expand_networks(obj["objects"], obj_grp_networks, obj_networks, obj_range, obj_host, obj_fqdn)
    elif "literals" in obj.keys():
        answer = {"literals": {}}
        lits = []
        for literal in obj["literals"]:
            lits.append([{"value": literal["value"]}])
        answer["literals"].update({"values": lits})
        return answer


def expand_port(obj, obj_port, obj_grp_port):
    """Expand a list of port/object descriptors into a dictionary using the provided maps."""
    answer = {}
    for port in obj:
        answer.update({port["name"]: {}})
        if "ProtocolPortObject" in port["type"]:
            answer[port["name"]].update({"value": obj_port[port["name"]]})
        if "PortObjectGroup" in port["type"]:
            answer[port["name"]].update({"value": obj_grp_port[port["name"]]})
        if "ICMPV4Object" in port["type"]:
            answer[port["name"]].update({"value": obj_port[port["name"]]})
    return answer


def select_port(obj, obj_port, obj_grp_port):
    """Select port(s) from an object descriptor; returns expanded result using provided maps."""
    full_answer = {}
    if "objects" in obj.keys():
        full_answer.update({"objects": expand_port(obj["objects"], obj_port, obj_grp_port)})
    if "literals" in obj.keys():
        answer = {"literals": {}}
        lits = []
        for literal in obj["literals"]:
            if 'ICMPv4PortLiteral' in literal["type"]:
                answer["literals"].update({"icmpType": literal["icmpType"], "protocol": literal["protocol"]})
            elif 'PortLiteral' in literal["type"]:
                lits.append([{"protocol": literal["protocol"], "port": literal["port"] if "port" in literal.keys() else "none"}])
                answer["literals"].update({"literals": lits})
            else:
                answer["literals"].update({"port": literal.get("port"), "protocol": literal.get("protocol")})
        full_answer.update(answer)
    return full_answer


def collect_objects(fmc):
    """Collect and return the various object maps used by the exporter.

    Returns a tuple: (_obj_host, _obj_networks, _obj_grp_networks, _obj_range,
                       _obj_fqdn, _obj_port, _obj_grp_port, obj_prot_port)
    """
    logger.info("Collecting objects inside collect_objects()...")

    logger.info("Getting Object Host")
    obj_host = call_with_retries(lambda: fmc.object.host.get(), description="get object host")
    _obj_host = {}
    for host in obj_host:
        _obj_host[host["name"]] = host.get("value")

    logger.info("Getting Object Networks")
    obj_networks = call_with_retries(lambda: fmc.object.network.get(), description="get object networks")
    _obj_networks = {net["name"]: net.get("value") for net in obj_networks}

    logger.info("Getting Group Networks")
    obj_grp_networks = call_with_retries(lambda: fmc.object.networkgroup.get(), description="get object network groups")
    _obj_grp_networks = {group['name']: {} for group in obj_grp_networks}
    for group in obj_grp_networks:
        if "literals" in group:
            for inside in group["literals"]:
                _obj_grp_networks[group["name"]][inside["value"]] = inside["value"]
        elif "objects" in group:
            for inside in group["objects"]:
                if "Host" in inside.get("type", ""):
                    _obj_grp_networks[group['name']][inside['name']] = _obj_host.get(inside['name'])
                elif "NetworkGroup" in inside.get("type", ""):
                    _obj_grp_networks[group['name']][inside["name"]] = {"values": _obj_grp_networks.get(inside["name"], {})}
                elif "Network" in inside.get("type", ""):
                    _obj_grp_networks[group['name']][inside["name"]] = _obj_networks.get(inside["name"])

    logger.info("Getting ranges")
    obj_range = call_with_retries(lambda: fmc.object.range.get(), description="get object ranges")
    _obj_range = {ran["name"]: ran.get("value") for ran in obj_range}

    logger.info("Getting fqdn")
    obj_fqdn = call_with_retries(lambda: fmc.object.fqdn.get(), description="get object fqdn")
    _obj_fqdn = {fqdn["name"]: fqdn.get("value") for fqdn in obj_fqdn}

    logger.info("Getting port")
    obj_port = call_with_retries(lambda: fmc.object.port.get(), description="get object port")
    _obj_port = {}
    for port in obj_port:
        if "ProtocolPortObject" in port.get("type", ""):
            _obj_port[port["name"]] = {'Protocol': port.get("protocol"), 'Port': port.get("port", "")}
        elif "ICMPV4Object" in port.get("type", ""):
            _obj_port[port["name"]] = {'icmpType': port.get("icmpType", 'Any')}

    logger.info("Getting port object group")
    obj_grp_port = call_with_retries(lambda: fmc.object.portobjectgroup.get(), description="get object port groups")
    _obj_grp_port = {grp_port['name']: {} for grp_port in obj_grp_port}
    for grp_port in obj_grp_port:
        for obj in grp_port.get("objects", []):
            if "ProtocolPortObject" in obj.get("type", ""):
                entry = _obj_port.get(obj["name"], {})
                _obj_grp_port[grp_port["name"]][obj["name"]] = {"Protocol": entry.get("Protocol"), "Port": entry.get("Port", "")}
            elif "ICMPV4Object" in obj.get("type", ""):
                entry = _obj_port.get(obj["name"], {})
                _obj_grp_port[grp_port["name"]][obj["name"]] = {"icmpType": entry.get("icmpType"), "Port": entry.get("Port", "")}

    logger.info("Getting protocol port object")
    obj_prot_port = call_with_retries(lambda: fmc.object.protocolportobject.get(), description="get protocol port object")

    return (_obj_host, _obj_networks, _obj_grp_networks, _obj_range, _obj_fqdn, _obj_port, _obj_grp_port, obj_prot_port)


def main(management_center):
    """
    Main entry point for the script.

    This function takes a dictionary of management center settings and reads the rules from the specified ACP.
    It then collects the objects referenced in the ACP and builds a dictionary of rule data.
    The dictionary is then converted to a pandas DataFrame and written to a CSV file.

    :param management_center: A dictionary containing the settings for the management center.
    :returns: None
    """
    logger.info("Getting access to the FMC")
    try:
        fmc = FMC(hostname=management_center['ip_address'], username=management_center['username'],
                  password=management_center['password'], domain=management_center['domain'])
    except Exception as e:
        logger.exception("Failed to create FMC client: %s", e)
        return

    # Getting the ACP.
    logger.info("-----" * 10)
    logger.info(f"Reading rules from the ACP {management_center['acp']}")
    try:
        acp = call_with_retries(lambda: fmc.policy.accesspolicy.accessrule.get(container_name=management_center['acp']),
                                description=f"fetch ACP {management_center['acp']}")
    except Exception as e:
        logger.exception("Failed to fetch ACP '%s' after retries: %s", management_center['acp'], e)
        return
    logger.info(f"Finished - Read {len(acp)} rules")
    logger.info("-----" * 10)

    # Collect objects via helper
    (_obj_host, _obj_networks, _obj_grp_networks, _obj_range, _obj_fqdn, _obj_port, _obj_grp_port, obj_prot_port) = collect_objects(fmc)

    logger.info("-----" * 10)
    logger.info("Building the ACP output...")

    # Note: helper functions were moved to module level to avoid relying on closure variables.

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
                rule["sourceNetworks"], _obj_grp_networks, _obj_networks, _obj_range, _obj_host, _obj_fqdn) if "sourceNetworks" in rule.keys() else "any",
            "dstNetwork": select_network(
                rule["destinationNetworks"], _obj_grp_networks, _obj_networks, _obj_range, _obj_host, _obj_fqdn) if "destinationNetworks" in rule.keys() else "any",
            "srcPorts": select_port(rule["sourcePorts"], _obj_port, _obj_grp_port) if "sourcePorts" in rule.keys() else "any",
            "dstPort": select_port(rule["destinationPorts"], _obj_port, _obj_grp_port) if "destinationPorts" in rule.keys() else "any",
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

    logger.info("Finished...")
    logger.info("-----" * 10)
    logger.info("Creating CSV file")
    # Convert a few nested columns to JSON strings so the CSV is readable
    nested_keys = ["srcNetwork", "dstNetwork", "srcPorts", "dstPort"]
    for rname, row in output.items():
        for k in nested_keys:
            if k in row and isinstance(row[k], (dict, list)):
                row[k] = json.dumps(row[k])

    # Use pandas directly to build the DataFrame -- output keys are rule names
    df = pd.DataFrame.from_dict(output, orient='index')
    # Default output filename if not provided via CLI
    out_filename = management_center.get("output") or f"{management_center['acp']}.csv"
    start = time.time()
    try:
        df.to_csv(os.path.expanduser(out_filename))
    except Exception as e:
        logger.exception("Failed to write CSV '%s': %s", out_filename, e)
        return
    elapsed = time.time() - start
    logger.info(f"Done, CSV file \"{out_filename}\" has been created (written in {elapsed:.2f}s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export FMC ACP to CSV")
    parser.add_argument("--ip", default=DEFAULTS["ip_address"], help="FMC IP address")
    parser.add_argument("--user", default=DEFAULTS["username"], help="FMC username")
    parser.add_argument("--pass", dest="password", default=DEFAULTS["password"], help="FMC password")
    parser.add_argument("--domain", default=DEFAULTS["domain"], help="FMC domain")
    parser.add_argument("--acp", default=DEFAULTS["acp"], help="Access control policy name")
    parser.add_argument("--output", default=None, help="Path to output CSV file (defaults to <acp>.csv)")
    args = parser.parse_args()

    management_center = {
        "ip_address": args.ip,
        "username": args.user,
        "password": args.password,
        "domain": args.domain,
        "acp": args.acp,
        "output": args.output,
    }

    main(management_center)
