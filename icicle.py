#!/usr/bin/env python
# encoding: utf-8
from __future__ import with_statement

# BUG: !! accidentally used Python 2.6 str.format all over :-/

import os
import re
import optparse
import subprocess
import httplib
import urllib2
import time
from contextlib import closing

try:
    import json
except ImportError:
    import simplejson  # Python 2.5 externel dependency

from pprint import pprint


class TunnelMachine(object):

    _host_search = re.compile("//([^/]+)").search

    def __init__(self, rest_url, user, password, domains):
        self.user = user
        self.domains = set(domains)
        self.base_url = "{0[rest_url]}/{0[user]}/tunnels".format(locals())
        self.rest_host = self._host_search(rest_url).group(1)
        self.auth_header = dict(Authorization="Basic " + "{0}:{1}"
                                "".format(user,password).encode("base64"))
        self._set_urlopen(rest_url, user, password)
        self._start_tunnel()

    def _set_urlopen(self, url, user, password):
        # make http auth support Just Work for GET/POST
        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(realm=None, uri=url,
                                  user=user, passwd=password)
        auth_handler = urllib2.HTTPBasicAuthHandler(password_mgr)
        opener = urllib2.build_opener(auth_handler)
        self.urlopen = opener.open

    def _get_doc(self, url_or_req):
        with closing(self.urlopen(url_or_req)) as resp:
            # TODO: handle this error
            assert resp.msg == "OK"
            return json.loads(resp.read())

    def _get_delete_doc(self, url):
        if self.base_url.startswith("https"):
            make_conn = httplib.HTTPSConnection
        else:
            make_conn = httplib.HTTPConnection
        with closing(make_conn(self.rest_host)) as conn:
            conn.request(method="DELETE", url=url, headers=self.auth_header)
            # TODO: check HTTP OK
            resp = conn.getresponse()
            return json.loads(resp.read())

    def _start_tunnel(self):
        # Shutdown any tunnel using a requested domain
        kill_list = set()
        for doc in self._get_doc(self.base_url):
            if not doc.get('DomainNames'):
                continue
            if set(doc['DomainNames']) & self.domains:
                kill_list.add(doc['id'])
        if kill_list:
            print "Killing running tunnel(s) using requested domains:"
        for tunnel_id in kill_list:
            print "  Shutting down tunnel: %s" % tunnel_id
            url = "%s/%s" % (self.base_url, tunnel_id)
            doc = self._get_delete_doc(url)
            assert doc.get('ok')  # TODO: handle error

        # Request a tunnel machine
        headers = {"Content-Type": "application/json"}
        data = json.dumps(dict(DomainNames=list(self.domains)))
        req = urllib2.Request(url=self.base_url, headers=headers, data=data)
        doc = self._get_doc(req)
        # TODO: handle this error
        assert doc.get('ok')
        self.id = doc['id']  # TODO: handle this not existing (fail)
        self.url = "%s/%s" % (self.base_url, self.id)

        # Wait for the machine to start running
        while True:
            doc = self._get_doc(self.url)
            status = doc.get('Status')
            # TODO: error on halting, terminated, etc.
            if status == "running":
                break
            print u"Tunnel is %s …" % status
            time.sleep(5)
        self.host = doc['Host']
        print "Tunnel is running on %s!" % self.host

    def shutdown(self):
        doc = self._get_delete_doc(self.url)
        assert doc.get('ok')
        while True:
            doc = self._get_doc(self.url)
            status = doc.get('Status')
            if status == "terminated":
                break
            print u"Tunnel is %s …" % status
            time.sleep(5)
        print "Tunnel is shutdown!"


def get_expect_script(options, remote_host):
    return ";".join("""set timeout -1
spawn ssh-keygen -R {1}
spawn ssh -p 22 -N -R 0.0.0.0:{0.remote_port}:{0.host}:{0.port} {1}
expect \\"Are you sure you want to continue connecting (yes/no)?\\"
send -- yes\\r
expect *password:
send -- {0.api_key}\\r
interact
""".format(options, remote_host).split("\n"))


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
    for opt in ["user", "api_key", "host", "port", "domains"]:
        if not hasattr(options, opt) or not getattr(options, opt):
            op.error("Missing required argument(s)!")

    return options

# https://saucelabs.com/rest/brainsik/tunnels/507622006f19f4d8b87dd6d9eff56ab1
# https://{0.user}:{0.api_key}@

def main():
    options = get_options()
    tunnel = TunnelMachine(options.rest_url, options.user, options.api_key,
                           options.domains)
    script = get_expect_script(options, tunnel.host)
    subprocess.call('exec expect -c "%s"' % script, shell=True,
                    stdout=open(os.devnull))


if __name__ == '__main__':
    main()