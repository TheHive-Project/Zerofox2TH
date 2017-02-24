# Zerofox2TH
Import ZeroFOX alert to TheHive

- `ZeroFOX/api.py` : main lib to get ZeroFOX alerts
- `ds2markdown.py` : converting ZeroFOX alert in markdown for TheHive (used in TheHive tasklog)
- `zf2th.py` : main program, get ZeroFOX alert and create a case in TheHive with a task containing all information.
- `config.py.template` : contains all the necessary information to connect to ZeroFOX API and TheHive API. All information is required.

## Prerequisite

Copy `config.py.template` into `config.py` and fill all connection information needed to connect to ZeroFOX API and TheHive API.

## Usage

Identify an interesting alert on ZeroFOX website you want to import un TheHive. Note the alert id number and run the following command on the system it sits :

```
$ zf2th.py -i <alertIdentifier>
```
