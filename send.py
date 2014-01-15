#!/usr/bin/env python2
from os.path import expanduser
from ConfigParser import ConfigParser
from collections import namedtuple
import argparse
import smtplib
import urllib
import json
import base64

CONFIG_PATH = '~/.sendpyrc'
Oauth = namedtuple('Oauth',
    'request_url, client_id, client_secret, username, user_refresh_token')
Account = namedtuple('Account',
    'username, refresh_token, address, port, use_ssl, use_tls')

def main(argv):
    parser = argparse.ArgumentParser(description='Mail using XOAUTH2')
    parser.add_argument('toaddrs', metavar='address', type=str, nargs='+',
            help='Mail address to be sent to')
    parser.add_argument('-f', dest='fromaddr', type=str,
            help='Mail address to be sent from')

    args = parser.parse_args()

    # TODO: set defaults
    config = ConfigParser()
    config.read(expanduser(CONFIG_PATH))

    request_url = config.get('oauth2', 'request_url')
    client_id = config.get('oauth2', 'client_id')
    client_secret = config.get('oauth2', 'client_secret')

    accounts = build_accounts(config)

    body = sys.stdin.read()

    if args.fromaddr in accounts:
        acct = accounts[args.fromaddr]
        oauth = Oauth(request_url, client_id, client_secret,
                acct.username, acct.refresh_token)
        sender(args.fromaddr, args.toaddrs, body, oauth, acct)
    else:
        raise KeyError('Configuration file has no section for: ', addr)

def build_accounts(config):
    accts = dict()
    acct_sections = [x for x in config.sections() if x.startswith('account ')]
    for section in acct_sections:
        username = config.get(section, 'username')
        refresh_token = config.get(section, 'refresh_token')
        address = config.get(section, 'address')
        port = config.getint(section, 'port')
        use_ssl = config.getboolean(section, 'use_ssl')
        use_tls = config.getboolean(section, 'use_tls')

        accts[username] = Account(username, refresh_token, address,
                port, use_ssl, use_tls)

    return accts

def oauth_handler(oauth):
    params = dict()
    params['client_id'] = oauth.client_id
    params['client_secret'] = oauth.client_secret
    params['refresh_token'] = oauth.user_refresh_token
    params['grant_type'] = 'refresh_token'

    response = urllib.urlopen(oauth.request_url, urllib.urlencode(params)).read()
    resp = json.loads(response)
    access_token = resp['access_token']

    auth_string = 'user=%s\1auth=Bearer %s\1\1' % (oauth.username, access_token)
    auth_string = base64.b64encode(auth_string)
    return auth_string


def sender(fromaddr, toaddrs, body, oauth, acct, debug=False):
    if acct.use_ssl:
        server = smtplib.SMTP_SSL(host=acct.address, port=acct.port)
    else:
        server = smtplib.SMTP(host=acct.address, port=acct.port)

    server.set_debuglevel(debug)

    if acct.use_tls:
        server.starttls()

    server.ehlo_or_helo_if_needed()

    auth = oauth_handler(oauth)
    server.docmd('AUTH', 'XOAUTH2 %s' % auth)

    server.sendmail(fromaddr, toaddrs, body)
    server.quit()


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
