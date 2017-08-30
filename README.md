# Zerofox2TH

Downloads Opened ZeroFOX alerts and creates Alerts into TheHive

- `ZeroFOX/api.py` : main lib to get ZeroFOX alerts
- `ds2markdown.py` : converting ZeroFOX alert in markdown for TheHive (used in case description and observables)
- `zf2th.py` : main program, get ZeroFOX alert and create an alert in TheHive containing all information.
- `config.py.template` : contains all the necessary information to connect to ZeroFOX API and TheHive API. All information is required.

## Prerequisite

Copy `config.py.template` into `config.py` and fill all connection information needed to connect to ZeroFOX API and TheHive API.

## Usage

- first run, get your Zerofox API token:
Enter your `Username` and `Password` in the config.py file and :

```
./zf2th.py -a
```

Now update your `config.py` file with the `key`. You can also delete your `Username` and `Password` information.

- Get alerts opened in last \<time\> minutes :

```
$ zf2th.py -t  <time>
```

- Check for new open alerts every 10 minutes (`-t 15` is used to be sure to retrieve all alerts created in the last 10 minutes) :

```
*/10    *   *   *   * /path/to/zf2th.py -t 15
```

- Enable logging and add INFO logs :

```
*/10    *   *   *   * /path/to/zf2th.py -t 15 --log=INFO
```

- Enable logging and add DEBUG logs :

```
*/10    *   *   *   * /path/to/zf2th.py -t 15 --log=DEBUG
```

When enabled, logs are written in the program's folder, in file named `zf2th.log`.
