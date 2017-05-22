#!/usr/bin/env python3
# -*- coding: utf-8 -*-



from __future__ import print_function
from __future__ import unicode_literals

import sys
import os
import getopt
import json
import getpass
import magic
import mimetypes
import requests
import shutil


from Zerofox.api import ZeroFoxApi
from config import Zerofox, TheHive
from thehive4py.api import TheHiveApi
from thehive4py.models import Case,CaseTask,CaseTaskLog,CaseObservable, Alert, AlertArtifact
from zf2markdown import zf2markdown, thTitle, thCaseDescription






def addTags(tags, content):

    """
        add tag to tags

        :param tags is list
        :param content is list
    """

    for newtag in content:
        tags.append("ZF:{}".format(newtag))
    return tags



def thSeverity(sev):

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


def convertDs2ThCase(content):

    """
        convert Zerofox alert in a TheHive Case

        :content dict object
    """
    if content.get('alert'):
        c = content.get('alert')
    else:
        return "Can't open alert"
        sys.exit(1)

    tasks = []
    tags = ["src:ZeroFOX"]
    tags = addTags(tags,[
        c.get("alert_type"),
        c.get("network"),
        c.get("entity",{}).get("name","-"),
        "id={}".format(c.get('id'))
        ])

    case = Case(
            title=thTitle(c),
            tlp=2,
            severity=thSeverity(c.get('severity',"3")),
            flag=False,
            tags=tags,
            description = thCaseDescription(c)
    )

    return case

def prepareAlert(content):
    """
    convert Zerofox alert in a TheHive Alert

    :return: alert object
    """
    # print(content)

    # if content.get('alerts'):
    #     c = content.get('alert')
    # else:
    #     return "Can't open alert"
    #     sys.exit(1)
    c = content
    tags = ["src:ZeroFOX"]
    tags = addTags(tags, [
        c.get("alert_type"),
        c.get("network"),
        c.get("entity", {}).get("name", "-"),
        "id={}".format(c.get('id'))
    ])
    artifacts = []
    alert = Alert(title=thTitle(c),
                  tlp=2,
                  tags=tags,
                  description=thCaseDescription(c),
                  type='external',
                  source='Zerofox',
                  sourceRef=str(c.get('id')),
                  artifacts=artifacts)

    # print(alert)
    return alert

def caseAddTask(thapi, caseId, content):
    """

    :param thapi: requests session
    :param caseId: text  is id of the task
    :param c: json as Zerofox content(alert)
    :return:
    """
    if content.get('alert'):
        c = content.get('alert')
    else:
        return "Can't open alert"
        sys.exit(1)

    task = CaseTask(
        title="Alert #{} imported from Zerofox".format(c.get('id')),
        description="Incident from Zerofox"
    )


    thresponse = thapi.create_case_task(caseId, task)
    r = thresponse.json()

    m = zf2markdown(c).metadata
    log = CaseTaskLog(message=m)
    thresponse = thapi.create_task_log(r['id'], log)
    m = zf2markdown(c).perpetratorInfo
    if c.get('perpetrator').get('image'):
        url = c.get('perpetrator').get('image')
        response = requests.get(url, stream=True)
        tmppath = '/tmp/zfperpetrator_image'
        with open(tmppath , 'wb') as outfile:
            shutil.copyfileobj(response.raw, outfile)
            outfile.close()
            ext = mimetypes.guess_extension(magic.Magic(mime=True).from_file(tmppath))
            os.rename(tmppath, tmppath+ext)
        log = CaseTaskLog(message=m, file=tmppath+ext)
        thresponse = thapi.create_task_log(r['id'], log)
        os.remove(tmppath+ext)

    m = zf2markdown(c).entityInfo
    log = CaseTaskLog(message=m)
    thresponse = thapi.create_task_log(r['id'], log)
    m = zf2markdown(c).generalInfo
    log = CaseTaskLog(message=m)
    thresponse = thapi.create_task_log(r['id'], log)



def caseAddObservable(thapi, caseId, content):
    """
    :param thapi: requests session
    :param caseId: text  is id of the task
    :param content : json as Zerofox content(alert)
    :return:
    """

    if content.get('alert'):
        c = content.get('alert')
    else:
        return "Can't open alert"
        sys.exit(1)

    observable = CaseObservable(
        data = [c.get('offending_content_url')],
        dataType ="url",
        tags = ["src:Zerofox=offending_content"],
        message = "Offending content",
        tlp = 1,
        ioc = False
    )
    thresponse = thapi.create_case_observable(caseId, observable)


def import2th(thapi, response):

    """
        Convert Zerofox response and import it in TheHive
        Call convertDs2ThCase
        Return the case fully created in TheHive

        :response  dict Response from Zerofox
    """

    case = convertDs2ThCase(response)
    thresponse = thapi.create_case(case)
    r = thresponse.json()
    caseAddTask(thapi, r['id'], response)
    caseAddObservable(thapi, r['id'], response)


def createThAlerts(thapi, response):
    """
    Convert Zerofox alerts and import them in TheHive Alerts
    :param thapi:
    :param response: dict response from Zerofox
    :return: the case created in the alert api of HheHive
    """

    for a in response.get('alerts'):
        alert = prepareAlert(a)
        print(type(alert))
        thresponse = thapi.create_alert(alert)






def run(argv):

    """
        Download Zerofox incident and create a new Case in TheHive

        :argv incident number
    """

    incidentId = ''

    # get options
    try:
        opts, args = getopt.getopt(argv, 'ahi:',["id="])
    except getopt.GetoptError:
        print(__file__ + " -i <alertId> -a")
        sys.exit(2)
    for opt,arg in opts:
        if opt == '-h':
            print(__file__ + " -i <alertId> -a")
            sys.exit()
        elif opt in ('-a', '--api'):
            zfapi = ZeroFoxApi(Zerofox)
            api = zfapi.getApiKey()
            print(api.json())
            sys.exit(0)
        elif opt in ('-i','--id'):
            alertId = arg



    # get username and password for TheHive
    if not TheHive['username'] and not TheHive['password']:
        TheHive['username'] = input("TheHive Username [%s]: " % getpass.getuser())
        TheHive['password'] = getpass.getpass("TheHive Password: ")

    thapi = TheHiveApi(TheHive['url'],TheHive['username'],
                        TheHive['password'], TheHive['proxies'])



    # Create Zerofox session
    zfapi = ZeroFoxApi(Zerofox)
    #response = zfapi.getAlertId(alertId)
    response = zfapi.getOpenAlerts()
    # if(response.status_code == 200):
    #     import2th(thapi, response.json())
    # else:
    #     print('ko: {}/{}'.format(response.status_code, response.text))
    #     sys.exit(0)
    if (response.status_code == 200):
            createThAlerts(thapi, response.json())
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))
        sys.exit(0)


if __name__ == '__main__':
    if len(sys.argv[1:]) > 0:
        run(sys.argv[1:])
    else:
        print(__file__ + " -i <AlertId>")
        print(__file__ + " -a")
        sys.exit(2)
