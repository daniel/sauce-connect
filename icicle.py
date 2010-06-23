#!/usr/bin/env python
# encoding: utf-8
from __future__ import with_statement

import os
import re
import optparse
import subprocess
import httplib
import urllib2
from contextlib import closing

try:
    import json
except ImportError:
    import simplejson  # Python 2.5 externel dependency

from pprint import pprint


class TunnelREST(object):

    _host_search = re.compile("//([^/]+)").search

    def __init__(self, rest_url, user, password):
        self.user = user
        self.base_url = "{0[rest_url]}/{0[user]}/tunnels".format(locals())

        match = self._host_search(rest_url)
        self.host = match.group(1)

        auth_enc = "{0[user]}:{0[password]}".format(locals()).encode("base64")
        self.auth_header = dict(Authorization="Basic %s" % auth_enc)

        # make http auth support Just Work (for GET/POST)
        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(realm=None, uri=rest_url,
                                  user=user, passwd=password)
        auth_handler = urllib2.HTTPBasicAuthHandler(password_mgr)
        opener = urllib2.build_opener(auth_handler)
        urllib2.install_opener(opener)

    def _create(self, url, domains):
        json_header = {"Content-Type": "application/json"}
        data = json.dumps(dict(DomainNames=domains))
        req = urllib2.Request(url=url, headers=json_header, data=data)
        with closing(urllib2.urlopen(req)) as resp:
            return json.loads(resp.read())

    # TODO: ?? add a flag for or keep these connections persistent?
    def _read(self, url):
        with closing(urllib2.urlopen(url)) as resp:
            return json.loads(resp.read())

    def _delete(self, url):
        if self.base_url.startswith("https"):
            make_conn = httplib.HTTPSConnection
        else:
            make_conn = httplib.HTTPConnection
        with closing(make_conn(self.host)) as conn:
            conn.request(method="DELETE", url=url, headers=self.auth_header)
            resp = conn.getresponse()
            return json.loads(resp.read())

    def start_tunnel(self, domains):
        return self._create(self.base_url, domains)

    def get_tunnels(self, tunnel_id=None):
        url = self.base_url
        if tunnel_id:
            url += "/%s" % tunnel_id
        return self._read(url)

    def shutdown_tunnel(self, tunnel_id):
        url = self.base_url + "/%s" % tunnel_id
        return self._delete(url)


def get_expect_script(options):
    return ";".join("""set timeout -1
spawn ssh-keygen -R {0.remote_host}
spawn ssh -p 22 -N -R 0.0.0.0:{0.remote_port}:{0.host}:{0.port} {0.remote_host}
expect \\"Are you sure you want to continue connecting (yes/no)?\\"
send -- yes\\r
expect *password:
send -- {0.api_key}\\r
interact
""".format(options).split("\n"))


def get_options():
    # TODO: use option groups to separate the "advanced" options
    op = optparse.OptionParser()
    op.add_option("-u", "--user", "--username")
    op.add_option("-k", "--api-key")
    op.add_option("-s", "--host", default="localhost",
                  help="default: %default")
    op.add_option("-p", "--port", default="5000",
                  help="default: %default")
    op.add_option("-r", "--remote-port", default="80",
                  help="default: %default")
    op.add_option("-d", "--domain", action="append", dest="domains",
                  help="Requests for these will go through the tunnel."
                       " Example: -d example.test -d '*.example.test'")
    op.add_option("--rest-url", default="https://saucelabs.com/rest",
                  help="default: %default")

    (options, args) = op.parse_args()
    options.remote_host = "maki4201.miso.saucelabs.com"
    for opt in ["user", "api_key", "host", "port", "domains"]:
        if not hasattr(options, opt) or not getattr(options, opt):
            op.error("Missing required argument(s)!")

    return options

# https://saucelabs.com/rest/brainsik/tunnels/507622006f19f4d8b87dd6d9eff56ab1
# https://{0.user}:{0.api_key}@

def main():
    options = get_options()
    rest = TunnelREST(options.rest_url, options.user, options.api_key)

    pprint(rest.get_tunnels())
    pprint(rest.start_tunnel(options.domains))

    raise SystemExit()
    script = get_expect_script(options)
    subprocess.call('exec expect -c "%s"' % script, shell=True,
                    stdout=open(os.devnull))


if __name__ == '__main__':
    main()