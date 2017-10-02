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
        f = open(file, 'a')
        os.utime(file, None)
        f.close()


def add_tags(tags, content):

    """
        add tag to tags

        :param tags is list
        :param content is list
    """
    t = tags
    for newtag in content:
        t.append("ZF:{}".format(newtag))
    return t


def th_severity(sev):

    """
        convert Zerofox severity in TH severity
        :type sev: string
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
    """

    return artefacts.append(AlertArtifact(tags=tags,
                                          dataType=dataType,
                                          data=data,
                                          message="From Zerofox",
                                          tlp=tlp)
                            )


def init_artefact_tags(content):
    return ["src:ZEROFOX",
            "ZF:Perpetrator",
            "Network:{}".format(content.get('network', 'None'))
            ]


def prepare_artefacts(content):
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
    convert Zerofox alert in a TheHive Alert

    :return: alert object
    """

    c = content
    case_tags = ["src:ZEROFOX"]
    case_tags = add_tags(case_tags, [
        "Type={}".format(c.get("alert_type")),
        "Network={}".format(c.get("network")),
        "Entity={}".format(c.get("entity", {}).get("name", "-")),
        "Id={}".format(c.get('id'))
    ])

    alert = Alert(title=th_title(c),
                  tlp=2,
                  tags=case_tags,
                  severity=th_severity(c.get('severity', "3")),
                  description=th_case_description(c, thumbnails),
                  type='{}'.format(c.get('alert_type')),
                  source='Zerofox',
                  caseTemplate=TheHive['template'],
                  sourceRef=str(c.get('id')),
                  artifacts=prepare_artefacts(content))
    return alert


def create_th_alerts(config, alerts):
    """
    Convert Zerofox alerts and import them in TheHive Alerts
    :param config:
    :param alerts:
    :type alerts: dict
    :param response: dict response from Zerofox
    :rtype: the case created in the alert api of HheHive
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
    :return: list of TH Alerts
    :rtype: list
    """
    while id_list:
        id = id_list.pop()
        response = zfapi.get_alerts(id)
        if response.get('status') == "success":
            data = response.get('data').get('alerts')

            entity_image_url = data.get('entity', None).get('image', None)
            perpetrator_image_url = data.get('perpetrator', None).get(
                'image', None)
            thumbnails = build_thumbnails(zfapi, entity_image_url,
                                          perpetrator_image_url)
            yield prepare_alert(data, thumbnails)


def find_alerts(zfapi, since):
    """
    :return: list of TH Alerts
    :rtype: list
    """
    response = zfapi.find_alerts(since)
    if response.get('status') == "success":
            data = response.get('data').get('alerts')
            for a in data:
                entity_image_url = a.get("entity", None).get("image", None)
                perpetrator_image_url = a.get('perpetrator', None).get(
                    'image', None)
                thumbnails = build_thumbnails(zfapi, entity_image_url,
                                              perpetrator_image_url)
                yield prepare_alert(a, thumbnails)


def base64_image(content, width):
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


def build_thumbnails(zfapi, entity_image_url, perpetrator_image_url):
    if entity_image_url is not None:
        resp_entity_image = zfapi.get_image(entity_image_url)
        entity_image = "data:{};base64,{}".format(
            resp_entity_image.headers['Content-Type'],
            base64_image(resp_entity_image.content, 400))
    else:
        resp_entity_image = None
        entity_image = "no image"

    if perpetrator_image_url is not None:
        resp_perpetrator_image = zfapi.get_image(perpetrator_image_url)
        perpetrator_image = "data:{};base64,{}".format(
            resp_perpetrator_image.headers['Content-Type'],
            base64_image(resp_perpetrator_image.content, 400))
    else:
        perpetrator_image = "no image"

    return {
        "entity_image": entity_image,
        "perpetrator_image": perpetrator_image
        }


def run():

    """
        Download Zerofox alerts and create a new Case in TheHive
    """

    def get_api(args):
        if "password" not in Zerofox:
            Zerofox['username'] = input("Zerofox Username \
                                        [%s]: " % getpass.getuser())
            Zerofox['password'] = getpass.getpass("Zerofox Password: ")
            zfapi = ZerofoxApi(Zerofox)
            t = zfapi.getApiKey()
            if t.get("status") == "success":
                print("Token = {}\n \
                    Add this to your config.py file to \
                    start requesting alerts".format(t.get("data")['token']))
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
            mon = monitoring("{}/ds2th.status".format(
                os.path.dirname(os.path.realpath(__file__))))
            mon.touch()

    parser = argparse.ArgumentParser(description="Get ZF \
                                     alerts and create alerts in TheHive")
    parser.add_argument("-d", "--debug",
                        action='store_true',
                        default=False,
                        help="generate a log file and and active \
                              debug logging")
    subparsers = parser.add_subparsers(help="subcommand help")
    parser_api = subparsers.add_parser("api", help="Get your api key")
    parser_api.set_defaults(func=get_api)
    parser_alert = subparsers.add_parser('alerts', help="fetch alerts by ID")
    parser_alert.add_argument("id",
                              metavar="ID",
                              action='store',
                              type=int,
                              nargs='+',
                              help="Get ZF alerts by ID")
    parser_alert.set_defaults(func=alerts)
    parser_find = subparsers.add_parser('find',
                                        help="find incidents and \
                                            intel-incidents in time")
    parser_find.add_argument("-l", "--last",
                             metavar="M",
                             nargs=1,
                             type=int,
                             required=True,
                             help="Get all alerts since last [M] minutes")
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
        logging.basicConfig(filename='{}/ds2th.log'.format(
                                os.path.dirname(os.path.realpath(__file__))),
                            level='DEBUG', format='%(asctime)s\
                                                   %(levelname)s\
                                                   %(message)s')
    args.func(args)


if __name__ == '__main__':
    run()
