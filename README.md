# Zerofox2TH

Downloads Opened ZeroFOX alerts and creates Alerts into TheHive 

- `ZeroFOX/api.py` : main lib to get ZeroFOX alerts
- `ds2markdown.py` : converting ZeroFOX alert in markdown for TheHive (used in TheHive tasklog)
- `zf2th.py` : main program, get ZeroFOX alert and create a case in TheHive with a task containing all information.
- `config.py.template` : contains all the necessary information to connect to ZeroFOX API and TheHive API. All information is required.

## Prerequisite

Copy `config.py.template` into `config.py` and fill all connection information needed to connect to ZeroFOX API and TheHive API.

## Usage

Get alerts opened in last <time> minutes :

```
$ zf2th.py -t  <time>
```
