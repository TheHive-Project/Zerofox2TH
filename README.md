# Zerofox2TH

Downloads Opened ZeroFOX alerts and creates Alerts into TheHive

- `ZeroFOX/api.py` : main lib to get ZeroFOX api key and alerts
- `ds2markdown.py` : converting ZeroFOX alert in markdown for TheHive (used in TheHive alerts)
- `zf2th.py` : main program, get ZeroFOX alerts and create an alerts into TheHive with description containing all information and observables if any.
- `config.py.template` : contains all the necessary information to connect to ZeroFOX API and TheHive API. All information is required.

## Prerequisite

Copy `config.py.template` into `config.py` and fill all connection information needed to connect to ZeroFOX API and TheHive API.
__Important notice__: running the program a first time is needed to get the API key.


## Usage


```
./zf2th.py -h
usage: zf2th.py [-h] [-d] {api,alerts,find} ...

Retreive Zerofox alerts and create alerts in TheHive

positional arguments:
  {api,alerts,find}  subcommand help
    api              Get your api key
    alerts           fetch alerts by ID
    find             find opened alerts

optional arguments:
  -h, --help         show this help message and exit
  -d, --debug        generate a log file and active debug logging
```

- The program comes with 3 main commands:
    - `api` to get the api key from your login/password
    - `alerts` to process Zerofox alerts specified by their ID
    - `find` to find opened Zerofox alerts during last [M] minutes.
- add `-d` switch to get `debug` information in `zf2th.log file`


### Get the API key

```
./zf2th.py api
Zerofox Username[]:
Zerofox Password:

Key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Add this to your config.py file to start requesting alerts
```

Now update your `config.py` file with the `key`.


### Retreive alerts spedified by ID - use the `alerts` command


```
./zf2th.py alerts -h
usage: zf2th.py alerts [-h] ID [ID ...]

positional arguments:
  ID          Get ZF alerts by ID

optional arguments:
  -h, --help  show this help message and exit
```

- `./zf2th.py alerts 123456 234567` : fetch alerts with IDs _123456_ and _234567_.


### Retreive alerts opened during last `M` minutes - use the `find` command

```
./zf2th.py find -h  
usage: zf2th.py find [-h] -l M [-m]

optional arguments:
  -h, --help      show this help message and exit
  -l M, --last M  Get all alerts during last [M] minutes
  -m, --monitor   active monitoring

```

### Use cases

- Check for new open alerts every 10 minutes (`-l 15` is used to be sure to retrieve all alerts created in the last 10 minutes) :

```
*/10    *   *   *   * /path/to/zf2th.py find -l 15
```

- Enable monitoring :

```
*/10    *   *   *   * /path/to/zf2th.py find -l 15 -m
```

- Enable logging :

```
*/10    *   *   *   * /path/to/zf2th.py -d find -l 15
```

When enabled, logs are written in the program's folder, in file named `zf2th.log`.
