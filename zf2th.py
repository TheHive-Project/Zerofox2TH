#!/usr/bin/env python3
# coding: utf-8

import sys
import os
import getopt
import json
import requests
import logging


from Zerofox.api import ZerofoxApi
from config import Zerofox, TheHive
from thehive4py.api import TheHiveApi
from thehive4py.models import Case,CaseTask,CaseTaskLog,CaseObservable, Alert, AlertArtifact
from zf2markdown import zf2markdown, th_title, th_case_description


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
        convert DigitalShadows severity in TH severity
        :sev string
    """

    severities = {
        'NONE':1,
        1:1,
        2:1,
        3:2,
        4:3
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
        "Network:{}".format(content.get('network', 'None'))]

def prepare_artefacts(content):

    artifact_tags = init_artefact_tags(content)

    artifacts = []

    if content.get('perpetrator'):
        perpetrator = content.get('perpetrator')


        add_alert_artefact(artifacts, 'other', perpetrator.get('display_name', "None"),
                         add_tags(init_artefact_tags(content), ['{}=\"Display Name\"'.format(perpetrator.get('network', 'None'))]),
                         2)
        add_alert_artefact(artifacts, 'url', perpetrator.get('url', "None"),
                         init_artefact_tags(content),
                         2)

        add_alert_artefact(artifacts, 'other', perpetrator.get('account_number', "None"),
                         add_tags(init_artefact_tags(content), ['{}=\"Account Number\"'.format(perpetrator.get('network', 'None'))]),
                         2)

        add_alert_artefact(artifacts, 'other', '{}'.format(perpetrator.get('id', "None")),
                         add_tags(init_artefact_tags(content), ['{}=\"id\"'.format(perpetrator.get('network'))]),
                         2)

        if perpetrator.get('username') != '':
            add_alert_artefact(artifacts, 'other', perpetrator.get('username', "None"),
                             add_tags(init_artefact_tags(content), ['{}=\"Username\"'.format(perpetrator.get('network', 'None'))]),
                             2)
        if json.loads(content.get('metadata')).get('occurrences'):
            add_alert_artefact(artifacts, 'other',
                             '{}'.format(
                                 json.loads(content.get('metadata')).get('occurrences', 'None')[0].get('text', 'None')),
                             add_tags(init_artefact_tags(content), ['type=\"{}\"'.format(perpetrator.get('type'))]),
                             2)
    return artifacts



def prepare_alert(content):
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
                  severity=th_severity(c.get('severity',"3")),
                  description=th_case_description(c),
                  type='{}'.format(c.get('alert_type')),
                  source='Zerofox',
                  caseTemplate=TheHive['template'],
                  sourceRef=str(c.get('id')),
                  artifacts=prepare_artefacts(content))
    return alert


def create_th_alerts(thapi, response):
    """
    Convert Zerofox alerts and import them in TheHive Alerts
    :param thapi:
    :param response: dict response from Zerofox
    :return: the case created in the alert api of HheHive
    """
    for a in response.get('alerts'):
        alert = prepare_alert(a)
        response = thapi.create_alert(alert)
        logging.debug('API TheHive - status code: {}'.format(response.status_code))
        if response.status_code > 299:
            logging.debug('API TheHive - raw error output: {}'.format(response.text))

def usage():
    print("Get opened alerts in last <minutes> minutes : {} -t <minutes>\n"
          "Get Zerofox API token : {} -a".format(__file__, __file__))


def run(argv):

    """
        Download Zerofox incident and create a new Case in TheHive
        :argv
    """

    # l = Logging(Logging)
    # print(l.loggingfile)
    # print(l.logginglevel)
    # logging.basicConfig(filename=l.loggingfile, level='DEBUG')

    try:
        opts,args = getopt.getopt(argv, 'lht:a',["log=","help", "time=", "api"])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    for opt,arg in opts:
        if opt in ('-l','--log'):
            logging.basicConfig(filename='{}/zf2th.log'.format(os.path.dirname(os.path.realpath(__file__))
        ), level=arg, format='%(asctime)s %(levelname)s     %(message)s')
            logging.debug('logging enabled')

    for opt,arg in opts:
        if opt in ('-a', '--api'):
            zfapi = ZerofoxApi(Zerofox)
            api = zfapi.getApiKey()
            print("Token = {}\n"
                  "Add it in the config.py file to start requesting alerts".format(api.json()['token']))
            sys.exit(0)

        elif opt in ('-t','--time'):
            logging.info('zf2th.py started')
            zfapi = ZerofoxApi(Zerofox)
            response = zfapi.getOpenAlerts(int(arg))
            logging.debug('API Zerofox - status code : {}'.format(response.status_code))
            logging.debug('Zerofox: {} alert(s) downloaded'.format(response.json()['count']))

            if response.json()['count'] > 0:
                thapi = TheHiveApi(TheHive['url'], TheHive['username'],
                        TheHive['password'], TheHive['proxies'])
                logging.debug('API TheHive - status code: {}'.format(response.status_code))
                create_th_alerts(thapi, response.json())

            logging.debug('zf2th.py ended')

        elif opt == opt in ('-l','--log'):
            pass
        elif opt == '-h':
            usage()
            sys.exit()
        else:
            assert False, "unhandled option"


if __name__ == '__main__':
    if len(sys.argv[1:]) > 0:
        run(sys.argv[1:])
    else:
        usage()
