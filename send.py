#!/usr/bin/env python3

from email.parser import Parser
from email.utils import parseaddr, getaddresses
from os.path import expanduser
from configparser import ConfigParser
from collections import namedtuple
import sys
import argparse
import smtplib
import urllib
import urllib.request
import json
import base64

CONFIG_PATH = "~/.sendpyrc"
Oauth = namedtuple(
    "Oauth", "request_url, client_id, client_secret, username, user_refresh_token"
)
Account = namedtuple(
    "Account", "username, refresh_token, address, port, use_ssl, use_tls"
)


def main(argv):
    parser = argparse.ArgumentParser(description="Mail using XOAUTH2")
    parser.add_argument(
        "toaddrs",
        metavar="address",
        type=str,
        nargs="*",
        help="Mail address to be sent to",
    )
    parser.add_argument(
        "-f", dest="fromaddr", type=str, help="Mail address to be sent from"
    )
    parser.add_argument(
        "--readfrommsg",
        action="store_true",
        help="Read the mail to determine the sender and recievers",
    )
    parser.add_argument("--debug", action="store_true", help="Debug mode")

    args = parser.parse_args()

    if args.debug:
        print(argv)

    # TODO: set defaults
    config = ConfigParser()
    config.read(expanduser(CONFIG_PATH))

    request_url = config.get("oauth2", "request_url")
    client_id = config.get("oauth2", "client_id")
    client_secret = config.get("oauth2", "client_secret")

    accounts = build_accounts(config)

    fromaddr = None
    toaddrs = list()

    body = sys.stdin.read()
    email_parser = Parser()
    msg = email_parser.parsestr(body)

    tos = list()
    ccs = list()
    bccs = list()

    if args.readfrommsg:
        fromaddr = parseaddr(msg["from"])[1]

        # email!
        tos = getaddresses(msg.get_all("to", []))
        ccs = getaddresses(msg.get_all("cc", []))
        bccs = getaddresses(msg.get_all("bcc", []))
        resent_tos = getaddresses(msg.get_all("resent-to", []))
        resent_ccs = getaddresses(msg.get_all("resent-cc", []))
        resent_bccs = getaddresses(msg.get_all("resent-bcc", []))

        tos = [x[1] for x in tos + resent_tos]
        ccs = [x[1] for x in ccs + resent_ccs]
        bccs = [x[1] for x in bccs + resent_bccs]
    else:
        fromaddr = args.fromaddr
        tos = args.toaddrs
        msg.replace_header("from", fromaddr)
        msg.replace_header("to", ", ".join(tos))

    if msg.get_all("bcc", False):
        msg.replace_header("bcc", None)  # wipe out from message

    if fromaddr in accounts:
        acct = accounts[fromaddr]
        oauth = Oauth(
            request_url, client_id, client_secret, acct.username, acct.refresh_token
        )
        if args.debug:
            print("Sending from:", fromaddr)
            print("Sending to:", toaddrs)
        sender(fromaddr, tos + ccs + bccs, msg, oauth, acct, args.debug)
    else:
        raise KeyError("Configuration file has no section for: ", fromaddr)


def build_accounts(config):
    accts = dict()
    acct_sections = [x for x in config.sections() if x.startswith("account ")]
    for section in acct_sections:
        username = config.get(section, "username")
        refresh_token = config.get(section, "refresh_token")
        address = config.get(section, "address")
        port = config.getint(section, "port")
        use_ssl = config.getboolean(section, "use_ssl")
        use_tls = config.getboolean(section, "use_tls")

        accts[username] = Account(
            username, refresh_token, address, port, use_ssl, use_tls
        )

    return accts


def oauth_handler(oauth):
    params = dict()
    params["client_id"] = oauth.client_id
    params["client_secret"] = oauth.client_secret
    params["refresh_token"] = oauth.user_refresh_token
    params["grant_type"] = "refresh_token"

    response = urllib.request.urlopen(
        oauth.request_url, urllib.parse.urlencode(params).encode("utf-8")
    ).read()
    resp = json.loads(response)
    access_token = resp["access_token"]

    auth_string = "user=%s\1auth=Bearer %s\1\1" % (oauth.username, access_token)
    auth_string = str(base64.b64encode(auth_string.encode("utf-8")), "utf-8")
    return auth_string


def sender(fromaddr, toaddrs, msg, oauth, acct, debug=False):
    if acct.use_ssl:
        server = smtplib.SMTP_SSL(host=acct.address, port=acct.port)
    else:
        server = smtplib.SMTP(host=acct.address, port=acct.port)

    server.set_debuglevel(debug)

    if acct.use_tls:
        server.starttls()

    server.ehlo_or_helo_if_needed()

    auth = oauth_handler(oauth)
    server.docmd("AUTH", "XOAUTH2 %s" % auth)

    server.sendmail(fromaddr, toaddrs, msg.as_string())

    server.quit()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
