#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from PIL import Image
from io import BytesIO
from config import Zerofox
import base64
import logging
import requests
import sys


class zf2markdown():

    def __init__(self, c):

        self.generalInfo = "### General Information\n\n" \
                           "***\n\n" \
                           "- **Alert type**: {0}\n\n" \
                           "- **Date**: {1}\n\n" \
                           "- **Target name:** {2}\n\n" \
                           "- **network:** {3}\n\n" \
                           "- **rule name:** {4}\n\n" \
                           "- **Suspicious content:** {5}\n\n".format(
                c.get('alert_type'),
                c.get('timestamp'),
                c.get('entity').get('name'),
                c.get('network', None),
                c.get('rule_name', None),
                c.get('offending_content_url', None)
            )

        self.entityInfo = "### Entity Information\n\n" \
                          "***\n\n" \
                          "{}\n\n".format(self.entity(c.get('entity')))

        self.perpetratorInfo = "### Perpetrator Information\n\n" \
                               "***\n\n" \
                               "{}\n\n".format(self.perpetrator(c.get('perpetrator')))

        self.metadataInfo = "### Metadata\n\n" \
                        "***\n\n" \
                        "```\n\n" \
                        "{}\n\n" \
                        "```\n\n".format(self.metadata(c.get('metadata')))




        self.description = "{0}{1}{2}{3}".format(
            self.generalInfo,
            self.entityInfo,
            self.perpetratorInfo,
            self.metadataInfo,
        )


    def entity(self, c):
        entity_image = get_image(c)
        return "- **Entity Name**:  {0}\n\n" \
               "- **Entity Id**: {1}\n\n" \
               "- **Entity Image (resized)**: ![][entity]\n\n[entity]: {2}\n\n".format(
                c.get('name'),
                c.get('id'),
                entity_image
        )


    def perpetrator(self,c):
        perpetrator_image = get_image(c)

        return "- **Username**: {0}\n\n" \
               "- **Display Name**: {1}\n\n" \
               "- **Account Number**: {2}\n\n" \
               "- **URL**: {3}\n\n" \
               "- **Date**: {4}\n\n" \
               "- **Image (resized)**: ![][perpetrator]\n\n[perpetrator]: {5}\n\n" \
               "- **Type**: {6}\n\n" \
               "- **Id**: {7}\n\n" \
               "- **Network**: {8}\n\n".format(
                     c.get('username',"None"),
                     c.get('display_name',"None"),
                     c.get('account_number',"None"),
                     c.get('url',"None"),
                     c.get('timestamp',"None"),
                     perpetrator_image,
                     c.get('type',"None"),
                     c.get('id',"None"),
                     c.get('network', "None")
                 )


    def asset(self,c):
        asset_image = get_image(c)
        return "- **Entity Name**: {0}\n\n" \
               "- **Entity Id**: {1}\n\n" \
               "- **Entity Image**: ![][asset]\n\n[asset]: {2}\n\n".format(
                c.get('name'),
                c.get('id'),
                asset_image
            )

    def addData(self, title, content, key):
        if content and content.get(key):
            return "**{}:**\ {}\n\n".format(title, content[key])
        else:
            return ""


    def metadata(self,c):
        try:
            raw = json.loads(c, strict=False).get('content_raw_data', None)
        except json.decoder.JSONDecodeError:
            raw = None
            pass
        if raw:
            return json.dumps(raw, indent=4, sort_keys=True)
        else:
            return "None"

def get_image(c):
    try:
        # response = get_image(c.get('image'))
        response = requests.get(c.get('image'), proxies=Zerofox.get('proxies'), verify=Zerofox.get('verify'))
        logging.debug("get_image status code: {}".format(response.status_code))
        fd = BytesIO(response.content)
        image = Image.open(fd)
        ft = image.format
        basewidth = 400
        wpercent = (basewidth / float(image.size[0]))
        if image.size[0] > basewidth:
            hsize = int(float(image.size[1]) * float(wpercent))
            image = image.resize((basewidth, hsize), Image.ANTIALIAS)
        ImgByteArr = BytesIO()
        image.save(ImgByteArr, format=ft)
        ImgByteArr = ImgByteArr.getvalue()
        with BytesIO(ImgByteArr) as bytes:
            encoded = base64.b64encode(bytes.read())
            b64_image = encoded.decode()
            return  "data:{};base64,{}".format(response.headers['Content-Type'], b64_image)
    except:
        return "None"

def th_case_description(c):

    """
        Build Case summary

        :param is dict content(alert)
    """

    description = "{}".format(
        zf2markdown(c).description
    )

    return description


def th_title(c):
    return "[Zerofox] {0} in {1} for entity: {2}".format(
        c.get("alert_type","-"),
        c.get("network", "-"),
        c.get("entity",{}).get("name","-")
        )
