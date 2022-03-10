![python3](https://img.shields.io/badge/python-3.7+-blue.svg)
![status](https://img.shields.io/badge/status-beta-blue.svg)
![license](https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg)

# FMC Policy Viewer
A script to collect the rules within an Access Control Policy, it will return a CSV file with the information about the rules also expanding all the objects within that rule.
It uses the [fireREST](https://github.com/kaisero/fireREST) library to collect the data from the FMC.

## Requirements
* fireREST==1.0.10
* pandas==1.4.1
* requests==2.27.1

## Usage
For now, modify in the script the variable `management_center` with the information from your environment.
i.e.
```python
management_center = {
    “ip_address”: “192.168.1.200”,
    “username”: “admin”,
    “password”: “Admin123”,
    “domain”: “Global”
}
```

If there is a need to use a child domain, add a `/` (forward slash) after the word Global.

## Execution
The command to execute the script is:
```
python3 fmc_policy_viewer.py
--------------------------------------------------
Welcome
--------------------------------------------------
Getting access to the FMC
--------------------------------------------------
Reading rules from the ACP FTD
Finished - Read 6 rules
--------------------------------------------------
Collecting objects...
--------------------------------------------------
Getting Object Host
Getting Object Networks
Getting Group Networks
Getting ranges
Getting fqdn
Getting port
Getting port object group
Getting protocol port object
--------------------------------------------------
Building the ACP output...
Finished...
--------------------------------------------------
Creating CSV file
Done, CSV file "FTD.csv" has been created
```

## Upcoming features
In the next stage, we will see:
* HTML output with the ACP information

## Authors
Cesar Barrientos (i-am-csr@outlook.com)

## License

GNU General Public License v3.0 or later.

See [LICENSE](https://github.com/i-am-csr/fmc_policy_viewer/blob/main/LICENSE) for the full text.