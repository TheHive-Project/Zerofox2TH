#!/usr/bin/env python3
# coding: utf-8

import sys
import os
import json
import logging
import getpass
import argparse
import base64
from PIL import Image
from io import BytesIO

from Zerofox.api import ZerofoxApi
from config import Zerofox, TheHive
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact
from zf2markdown import th_title, th_case_description


class monitoring():

    def __init__(self, file):
        self.monitoring_file = file

    def touch(self):

        """
        touch status file when successfully terminated
        """

        if os.path.exists(self.monitoring_file):
            os.remove(self.monitoring_file)
        open(self.monitoring_file, 'a').close()


def add_tags(tags, content):

    """
    add tag to tags

    :param tags: existing tags
    :type tags: list
    :param content: string, mainly like taxonomy
    :type content: string
    """
    t = tags
    for newtag in content:
        t.append("ZF:{}".format(newtag))
    return t


def th_severity(sev):

    """
    convert ZeroFOX severity in TH severity

    :param sev: ZF severity
    :type sev: string
    :return TH severity
    :rtype: int
    """

    severities = {
        'NONE': 1,
        1: 1,
        2: 1,
        3: 2,
        4: 3
    }
    return severities[sev]


def add_alert_artefact(artefacts, dataType, data, tags, tlp):
    """
    :param artefacts: array
    :param dataType: string
    :param data: string
    :param tags: array
    :param tlp: int
    :return: array
    :rtype: array
    """

    return artefacts.append(AlertArtifact(tags=tags,
                                          dataType=dataType,
                                          data=data,
                                          message="From Zerofox",
                                          tlp=tlp)
                            )


def init_artefact_tags(content):
    """
    param content:
    type content:
    return: list of tags
    rtype: array
    """

    return ["src:ZEROFOX",
            "ZF:Perpetrator",
            "Network:{}".format(content.get('network', 'None'))
            ]


def prepare_artefacts(content):
    """
    param content: Zerofox alert
    type content: dict
    return: list AlertArtifact
    rtype: array
    """
    artifacts = []
    if content.get('perpetrator'):
        perpetrator = content.get('perpetrator')
        add_alert_artefact(artifacts, 'other', perpetrator.get('display_name',
                                                               None),
                           add_tags(init_artefact_tags(content),
                                    ['{}=\"Display Name\"'.format(
                                        perpetrator.get('network', None))]),
                           2)
        add_alert_artefact(artifacts, 'url', perpetrator.get('url', None),
                           init_artefact_tags(content),
                           2)

        add_alert_artefact(artifacts, 'other',
                           perpetrator.get('account_number', "None"),
                           add_tags(init_artefact_tags(content),
                                    ['{}=\"Account Number\"'.format(
                                        perpetrator.get('network', 'None'))]),
                           2)

        add_alert_artefact(artifacts, 'other',
                           '{}'.format(perpetrator.get('id', "None")),
                           add_tags(init_artefact_tags(content),
                                    ['{}=\"id\"'.
                                    format(perpetrator.get('network'))]),
                           2)
        if perpetrator.get('username') != '':
            add_alert_artefact(artifacts, 'other',
                               perpetrator.get('username', "None"),
                               add_tags(init_artefact_tags(content),
                                        ['{}=\"Username\"'.format(
                                            perpetrator.get(
                                                'network', 'None'))]),
                               2)
        try:
            if json.loads(content.get('metadata')).get('occurrences'):
                add_alert_artefact(artifacts, 'other', '{}'.format(
                                     json.loads(content.get('metadata')).get(
                                         'occurrences', 'None')[0].get(
                                             'text', 'None')),
                                   add_tags(init_artefact_tags(content),
                                   ['type=\"{}\"'.format(perpetrator.get(
                                       'type'))]),
                                   2)

        except json.decoder.JSONDecodeError:
            pass

    return artifacts


def prepare_alert(content, thumbnails):
    """
    convert a ZeroFOX alert into a TheHive alert

    :param incident: Zerofox Alert
    :type incident: dict
    :type thumbnails: dict
    :return: Thehive alert
    :rtype: thehive4py.models Alerts
    """
    
    case_tags = ["src:ZEROFOX"]
    case_tags = add_tags(case_tags, [
        "Type={}".format(content.get("alert_type")),
        "Network={}".format(content.get("network")),
        "Entity={}".format(content.get("entity", {}).get("name", "-")),
        "Id={}".format(content.get('id'))
    ])

    alert = Alert(title=th_title(content),
                  tlp=2,
                  tags=case_tags,
                  severity=th_severity(content.get('severity', "3")),
                  description=th_case_description(content, thumbnails),
                  type='{}'.format(content.get('alert_type')),
                  source='Zerofox',
                  caseTemplate=TheHive['template'],
                  sourceRef=str(content.get('id')),
                  artifacts=prepare_artefacts(content))

    logging.debug("prepare_alert: alert built for \
        ZF id #{}".format(content.get('id')))
    return alert


def create_th_alerts(config, alerts):
    """
    :param config: TheHive config
    :type config: dict
    :param alerts: List of alerts
    :type alerts: list
    :return: create TH alert
    """
    thapi = TheHiveApi(config.get('url', None),
                       config.get('key'),
                       config.get('password', None),
                       config.get('proxies'))
    for a in alerts:
        response = thapi.create_alert(a)
        logging.debug('API TheHive - status code: {}'.format(
            response.status_code))
        if response.status_code > 299:
            logging.debug('API TheHive - raw error output: {}'.format(
                response.raw.read()))


def get_alerts(zfapi, id_list):

    """
    :type zfapi: Zerofox.api.ZerofoxApi
    :param id_list: list of alert id
    :type id_list: array
    :return: TheHive alert
    :rtype: thehive4py.models Alert
    """
    while id_list:
        id = id_list.pop()
        response = zfapi.get_alerts(id)
        if response.get('status') == "success":
            data = response.get('data').get('alert')
            logging.debug('get_alerts(): {} ZF alert(s)\
                downloaded'.format(data.get('id')))

            entity_image_url = data.get('entity', None).get('image', None)
            perpetrator_image_url = data.get('perpetrator', None).get(
                'image', None)
            thumbnails = build_thumbnails(zfapi, entity_image_url,
                                          perpetrator_image_url)
            yield prepare_alert(data, thumbnails)
        else:
            logging.debug("get_alerts(): Error while \
                fetching alert #{}: {}".format(id, response.get('data')))
            sys.exit("get_alerts(): Error while \
                fetching alert #{}: {}".format(id, response.get('data')))

def find_alerts(zfapi, last):
    """
    :type zfapi: Zerofox.api.ZerofoxApi
    :param id_list: list of alert id
    :type id_list: array
    :return: TheHive alert
    :rtype: thehive4py.models Alert
    """
    response = zfapi.find_alerts(last)
    if response.get('status') == "success":
            data = response.get('data').get('alerts')
            logging.debug('find_alerts(): {} ZF alert(s)\
                downloaded'.format(response.get('data').get('count')))
            for a in data:
                logging.debug('find_alerts(): building alert {}\
                downloaded'.format(a.get('id')))
                entity_image_url = a.get("entity", None).get("image", None)
                perpetrator_image_url = a.get('perpetrator', None).get(
                    'image', None)
                thumbnails = build_thumbnails(zfapi, entity_image_url,
                                              perpetrator_image_url)
                yield prepare_alert(a, thumbnails)

def base64_image(content, width):
    """
    :param content: raw image
    :type content: raw
    :param width: size of the return image
    :type width: int
    :return: base64 encoded image
    :rtype: string
    """
    try:
        fd = BytesIO(content)

        image = Image.open(fd)
        ft = image.format
        # basewidth = width
        wpercent = (width / float(image.size[0]))
        if image.size[0] > width:
            hsize = int(float(image.size[1]) * float(wpercent))
            image = image.resize((width, hsize), Image.ANTIALIAS)
        ImgByteArr = BytesIO()
        image.save(ImgByteArr, format=ft)
        ImgByteArr = ImgByteArr.getvalue()
        with BytesIO(ImgByteArr) as bytes:
            encoded = base64.b64encode(bytes.read())
            base64_image = encoded.decode()
        return base64_image

    except Exception as e:
        return "No image"

def build_thumbnails(zfapi, entity_image_url, perpetrator_image_url):
    """
    :param zfapi:
    :type zfapi:
    :param entity_image_url:
    :type entity_image_url: string
    :param perpetrator_image_url:
    :type perpetrator_image_url: string
    :return: base64 encoded images ready to be added in markdown
    :rtype: dict
    """

    if entity_image_url is not None:
        resp_entity_image = zfapi.get_image(entity_image_url)
        entity_image = "data:{};base64,{}".format(
            resp_entity_image.headers['Content-Type'],
            base64_image(resp_entity_image.content, 400))
    else:
        entity_image = "no image"

    perpetrator_image = "no image"

    if perpetrator_image_url is not None:
        resp_perpetrator_image = zfapi.get_image(perpetrator_image_url)
        if resp_perpetrator_image is not None:
            perpetrator_image = "data:{};base64,{}".format(
                resp_perpetrator_image.headers['Content-Type'],
                base64_image(resp_perpetrator_image.content, 400))

    return {
        "entity_image": entity_image,
        "perpetrator_image": perpetrator_image
        }


def run():

    """
        Download ZeroFOX alerts and create a new alert in TheHive
    """

    def get_api(args):
        if "password" not in Zerofox:
            Zerofox['username'] = input("ZeroFOX username"
                                        "[%s]: " % getpass.getuser())
            Zerofox['password'] = getpass.getpass("ZeroFOX password: ")
            zfapi = ZerofoxApi(Zerofox)
            t = zfapi.getApiKey()
            if t.get("status") == "success":
                print("Key = {}\n"
                    "Add this to your config.py file to "
                    "start fetching alerts".format(t.get("data")['token']))
            sys.exit(0)
        else:
            print(t.get("content"))
            sys.exit(1)

    def alerts(args):
        zfapi = ZerofoxApi(Zerofox)
        alerts = get_alerts(zfapi, args.id)
        create_th_alerts(TheHive, alerts)

    def find(args):
        last = args.last.pop()
        zfapi = ZerofoxApi(Zerofox)
        alerts = find_alerts(zfapi, last)
        create_th_alerts(TheHive, alerts)
        if args.monitor:
            mon = monitoring("{}/zf2th.status".format(
                os.path.dirname(os.path.realpath(__file__))))
            mon.touch()

    parser = argparse.ArgumentParser(description="Retrieve ZeroFOX \
                                     alerts and feed them to TheHive")
    parser.add_argument("-d", "--debug",
                        action='store_true',
                        default=False,
                        help="generate a log file and active \
                              debug logging")
    subparsers = parser.add_subparsers(help="subcommand help")
    parser_api = subparsers.add_parser("api", help="get your API key")
    parser_api.set_defaults(func=get_api)
    parser_alert = subparsers.add_parser('alerts', help="fetch alerts by ID")
    parser_alert.add_argument("id",
                              metavar="ID",
                              action='store',
                              type=int,
                              nargs='+',
                              help="get ZF alerts by ID")
    parser_alert.set_defaults(func=alerts)
    parser_find = subparsers.add_parser('find',
                                        help="find open alerts")
    parser_find.add_argument("-l", "--last",
                             metavar="M",
                             nargs=1,
                             type=int,
                             required=True,
                             help="get all alerts published during the last [M] minutes")
    parser_find.add_argument("-m", "--monitor",
                             action='store_true',
                             default=False,
                             help="active monitoring")
    parser_find.set_defaults(func=find)

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(filename='{}/zf2th.log'.format(
                                os.path.dirname(os.path.realpath(__file__))),
                            level='DEBUG', format='%(asctime)s\
                                                   %(levelname)s\
                                                   %(message)s')
    args.func(args)


if __name__ == '__main__':
    run()
