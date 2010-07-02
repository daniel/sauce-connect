#!/usr/bin/env python
# encoding: utf-8
from __future__ import with_statement

# TODO:
#   * Logging/timestamps
#   * Health checks
#     * user's network can get to host being forwarded to
#     * SSH connection to tunnel VM is up
#   * REST checks
#     * Tunnel is still running (may be shutdown by someone else)
#     * Renew lease (not implemented)

try:
    import json
except ImportError:
    import simplejson as json  # Python 2.5 external dependency

import platform
import optparse
import re
import subprocess
import signal
import httplib
import urllib2
import time
from contextlib import closing

REST_POLL_WAIT = 3


class RESTConnectionError(Exception):

    def __init__(self, e):
        self.e = e

    def __repr__(self):
        return "Failed to connect to REST interface: %s" % str(self.e)

    def __str__(self):
        return repr(self)


class TunnelMachine(object):

    _host_search = re.compile("//([^/]+)").search

    def __init__(self, rest_url, user, password, domains):
        self.user = user
        self.domains = set(domains)
        self.base_url = "%(rest_url)s/%(user)s/tunnels" % locals()
        self.rest_host = self._host_search(rest_url).group(1)
        self.basic_auth_header = {"Authorization": "Basic %s" %
                                 ("%s:%s" % (user, password)).encode("base64")}
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
        try:
            with closing(self.urlopen(url_or_req)) as resp:
                # TODO: handle this error
                assert resp.msg == "OK"
                return json.loads(resp.read())
        except urllib2.URLError, e:
            raise RESTConnectionError(e)

    def _get_delete_doc(self, url):
        if self.base_url.startswith("https"):
            make_conn = httplib.HTTPSConnection
        else:
            make_conn = httplib.HTTPConnection
        with closing(make_conn(self.rest_host)) as conn:
            try:
                conn.request(
                    method="DELETE", url=url, headers=self.basic_auth_header)
            except socket.gaiaerror, e:
                raise RESTConnectionError(e)

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
        # TODO: handle 'id' not existing — fail
        self.id = doc['id']
        self.url = "%s/%s" % (self.base_url, self.id)
        print "Provisioned tunnel: %s" % self.id

    def ready_wait(self):
        """Wait for the machine to reach the 'running' state."""
        previous_status = None
        while True:
            doc = self._get_doc(self.url)
            status = doc.get('Status')
            # TODO: error on halting, terminated, etc.
            if status == "running":
                break
            if status != previous_status:
                print u"Tunnel is %s .." % status
            previous_status = status
            time.sleep(REST_POLL_WAIT)
        self.host = doc['Host']
        print "Tunnel is running on %s!" % self.host

    def shutdown(self):
        print "Shutting down tunnel: %s" % self.id
        doc = self._get_delete_doc(self.url)
        assert doc.get('ok')

        previous_status = None
        while True:
            doc = self._get_doc(self.url)
            status = doc.get('Status')
            if status == "terminated":
                break
            if status != previous_status:
                print u"Tunnel is %s .." % status
            previous_status = status
            time.sleep(REST_POLL_WAIT)
        print "Tunnel is shutdown!"

    close = shutdown


def get_plink_command(options, remote_host):
    options.remote_host = remote_host
    return "plink -l %(user)s -pw %(api_key)s -N -R 0.0.0.0:%(remote_port)s:%(host)s:%(port)s %(remote_host)s" % options


def get_expect_script(options, remote_host):
    options.remote_host = remote_host
    return ";".join((("""set timeout -1
spawn ssh-keygen -R %(remote_host)s
spawn ssh -p 22 -l %(user)s -N -R 0.0.0.0:%(remote_port)s:%(host)s:%(port)s %(remote_host)s
expect \\"Are you sure you want to continue connecting (yes/no)?\\"
send -- yes\\r
expect *password:
send -- %(api_key)s\\r
interact
""" % options)).split("\n"))


def setup_signal_handler(tunnel):

    def signal_handler(signum, frame):
        print "Received signal %s." % signum
        tunnel.shutdown()
        print "Goodbye."
        raise SystemExit()

    for sig in ["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM"]:
        signal.signal(getattr(signal, sig), signal_handler)


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

    # let us use a mapping key in the string interpolations
    def getitem(key):
        try:
            return getattr(options, key)
        except AttributeError:
            raise KeyError
    options.__getitem__ = getitem

    return options


def main():
    is_windows = platform.system().lower() == "windows"
    options = get_options()

    tunnel = TunnelMachine(options.rest_url, options.user, options.api_key,
                           options.domains)
    if not is_windows:
        setup_signal_handler(tunnel)
    tunnel.ready_wait()

    if is_windows:
        cmd = "echo 'n' | %s" % get_plink_command(options, tunnel.host)
    else:
        cmd = 'expect -c "%s"' % get_expect_script(options, tunnel.host)

    print "Setting up reverse SSH connection"
    print "cmd: %s" % cmd
    reverse_ssh = subprocess.Popen(cmd, shell=True)
    while reverse_ssh.poll() is None:
        time.sleep(1)
    if reverse_ssh.returncode != 0:
        print "SSH tunnel exited with error code %d" % reverse_ssh.returncode
    else:
        print "SSH tunnel process exited"
    tunnel.shutdown()


if __name__ == '__main__':
    try:
        main()
    except RESTConnectionError, e:
        print e
