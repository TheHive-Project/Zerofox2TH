# Zerofox2TH: ZeroFOX Alert Feeder for TheHive
[ZeroFOX](https://www.zerofox.com/) is a commercial social media monitoring 
provider. It allows businesses to monitor several social media networks and 
apply policies to detect infringing and fraudulent content such as fake 
profiles and pages.

For a fee, the service offers an API which can be leveraged to consume this 
type of information and programmatically feed it as alerts to [TheHive](https://github.com/CERT-BDF/TheHive), a popular free and open source 
Security Incident Response Platform designed to make life easier for SOCs, CSIRTs, CERTs and any information security practitioner dealing with security incidents that need to be investigated and acted upon swiftly.

Zerofox2TH is a free, open source ZeroFOX alert feeder for TheHive. You can 
use it to feed
ZeroFOX alerts into TheHive, where they can be previewed and 
transformed into new cases using pre-defined incident response templates or 
added into existing ones.

Zerofox2TH is written in Python 3 by TheHive Project.

## Overview
Zerofox2TH is made of several parts:

- `Zerofox/api.py` : the main library to interact with the ZeroFOX platform 
and fetch alerts.
- `zf2markdown.py` : a program which converts Zerofox data
 into Markdown as used by alerts in TheHive.
 - `config.py.template` : a configuration template which contains all the 
necessary information to connect to the APIs of ZeroFOX and TheHive. 
All information is required.
- `zf2th.py` : the main program. It gets Zerofox alerts and feed them to 
TheHive with a description containing all relevant information, and observables if any.

## Prerequisites
You'll need Python 3, the `requests` and `pillow` libraries as well as 
[TheHive4py](https://github.com/CERT-BDF/TheHive4py), a Python client for TheHive.

Clone the repository then copy the `config.py.template` file as `config.py` 
and fill in the blanks: proxies if applicable, API keys, URLs, accounts 
pertaining to your ZeroFOX subscription and your instance of TheHive.  At 
this time, you probably won't have the API key associated with your 
 ZeroFOX account. Complete the installation steps and run `zf2th.py` with the
  `api` option to retrieve it as shown [below](#get-the-api-key) and add it 
  to `config.py`.

**Note**: you need a valid API subscription to the ZeroFOX platform as 
well as TheHive 2.13 or better and an account with the ability to create alerts.

Then install the Python requirements:

`$ pip3 install -r requirements.txt`


## Usage
Once your configuration file `config.py` is ready, use the main program to 
fetch or find ZeroFOX alerts:


```
./zf2th.py -h
usage: zf2th.py [-h] [-d] {api,alerts,find} ...

Retrieve ZeroFOX alerts and nd feed them to TheHive

positional arguments:
  {api,alerts,find}  subcommand help
    api              get your API key
    alerts           fetch alerts by ID
    find             find open alerts

optional arguments:
  -h, --help         show this help message and exit
  -d, --debug        generate a log file and active debug logging
```

The program has 3 options:
- `api` to get the ZeroFOX API key associated with your account.
- `alerts` to process ZeroFOX alerts specified by their ID.
- `find` to fetch alerts published during the last M minutes.

If you need debugging information, add the `d`switch and the program will 
create a file called `zf2th.log`. It will be created in the same folder as the 
main program.

### Get the API key
The first step consist of retrieving the ZeroFOX API key associated with your
 account.

```
./zf2th.py api
ZeroFOX username[]:
ZeroFOX password:

Key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Add this to your config.py file to start fetchingsoon alerts
```

Now update your `config.py` file with the `key`.


### Retrieve alerts specified by their ID

```
./zf2th.py alerts -h
usage: zf2th.py alerts [-h] ID [ID ...]

positional arguments:
  ID          get ZF alerts by ID

optional arguments:
  -h, --help  show this help message and exit
```

- `./zf2th.py alerts 123456 234567` : fetch alerts with IDs _123456_ and _234567_.


### Retrieve alerts published during the last `M` minutes

```
./zf2th.py find -h  
usage: zf2th.py find [-h] -l M [-m]

optional arguments:
  -h, --help      show this help message and exit
  -l M, --last M  get all alerts published during the last [M] minutes
  -m, --monitor   active monitoring

```
- `./zf2th.py find -l 20` retrieves alerts published during the last 20 minutes.
- `m` is a switch that creates a `zf2th.status` file. This is useful if you 
want to add the program as a cron job and monitor it. 

### Use cases

- Add a cron job to check for newly published alerts every 10 minutes (`-l 15`
is used to be sure to retrieve all alerts created in the last 10 minutes):

```
*/10    *   *   *   * /path/to/zf2th.py find -l 15
```

- Enable monitoring:

```
*/10    *   *   *   * /path/to/zf2th.py find -l 15 -m
```

- Enable logging:

```
*/10    *   *   *   * /path/to/zf2th.py -d find -l 15
```

When enabled, logs are written in the program's folder, in a file named `zf2th.log`.

# License
Zerofox2TH is an open source and free software released under the 
[AGPL](LICENSE) 
(Affero General Public License). We, TheHive Project, are committed to ensure
that Zerofox2TH will remain a free and open source project on the 
long-run.

# Updates
Information, news and updates are regularly posted on [TheHive Project Twitter account](https://twitter.com/thehive_project) and on [the blog](https://blog.thehive-project.org/).

# Contributing
Please see our [Code of conduct](code_of_conduct.md). We welcome your 
contributions. Please feel free to fork the code, play with it, make some 
patches and send us pull requests via [issues](https://github.com/CERT-BDF/Zerofox2TH/issues).

# Support
Please [open an issue on GitHub](https://github.com/CERT-BDF/Zerofox2TH/issues)
 if you'd like to report a bug or request a feature. We are also available on [Gitter](https://gitter.im/TheHive-Project/TheHive) to help you out.

If you need to contact the project team, send an email to <support@thehive-project.org>.

**Important Note**:

- If you have problems with [TheHive](https://github.com/CERT-BDF/TheHive), please [open an issue on its dedicated repository](https://github.com/CERT-BDF/TheHive/issues/new).

# Community Discussions
We have set up a Google forum at <https://groups.google.com/a/thehive-project.org/d/forum/users>. To request access, you need a Google account. You may create one [using a Gmail address](https://accounts.google.com/SignUp?hl=en) or [without it](https://accounts.google.com/SignUpWithoutGmail?hl=en).

# Website
<https://thehive-project.org/>