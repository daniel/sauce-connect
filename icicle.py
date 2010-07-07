#!/usr/bin/env python
# encoding: utf-8
from __future__ import with_statement

# TODO minimum:
#   * Error handling and retry
#   * Package with dependencies and licenses
#   * Developer docs for how to build Windows .exe
#   * Version check
#
# TODO minimum - problematic:
#   * Daemonizing
#     * os.fork() not on Windows
#     * can't send file descriptors to null or Expect script fails
#   * Stats reporting via REST
#     * reporting via the REST interface requires backend work to provide an
#       updateable field; backoff to UserAgent instead?
#
# TODO later:
#   * Usage message
#   * REST checks
#     * Tunnel is still running (may be shutdown by something else)
#     * Renew lease (not implemented)
#
# TODO much later:
#   * Close ssh-keygen process after use
#

import os
import sys
import re
import optparse
import logging
import logging.handlers
import signal
import httplib
import urllib2
import subprocess
import socket
import time
import platform
from contextlib import closing
from collections import defaultdict

try:
    import json
except ImportError:
    import simplejson as json  # Python 2.5 dependency

NAME = __name__
VERSION = "dev"

REST_POLL_WAIT = 3
HEALTH_CHECK_INTERVAL = 30
HEALTH_CHECK_FAIL = 5 * 60  # no good check after this amount of time == fail

is_windows = platform.system().lower() == "windows"
logger = logging.getLogger(NAME)


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

        self.is_shutdown = False
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
        # urllib2 doesn support the DELETE method (lame), so we build our own
        if self.base_url.startswith("https"):
            make_conn = httplib.HTTPSConnection
        else:
            make_conn = httplib.HTTPConnection
        with closing(make_conn(self.rest_host)) as conn:
            try:
                conn.request(
                    method="DELETE", url=url, headers=self.basic_auth_header)
            except (socket.gaierror, socket.error), e:
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
            logger.info("Killing running tunnel(s) using requested domains:")
        for tunnel_id in kill_list:
            logger.info("  Shutting down tunnel: %s" % tunnel_id)
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
        logger.debug("Provisioned tunnel: %s" % self.id)

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
                logger.info("Tunnel is %s .." % status)
            previous_status = status
            time.sleep(REST_POLL_WAIT)
        self.host = doc['Host']
        logger.info("Tunnel is running on %s!" % self.host)

    def shutdown(self):
        if self.is_shutdown:
            return

        logger.info("Shutting down tunnel")
        logger.debug("Tunnel ID: %s" % self.id)

        doc = self._get_delete_doc(self.url)
        assert doc.get('ok')

        previous_status = None
        while True:
            doc = self._get_doc(self.url)
            status = doc.get('Status')
            if status == "terminated":
                break
            if status != previous_status:
                logger.info("Tunnel is %s .." % status)
            previous_status = status
            time.sleep(REST_POLL_WAIT)
        logger.info("Tunnel is shutdown!")
        self.is_shutdown = True

    # Make us usable with contextlib.closing
    close = shutdown


class HealthCheckFail(Exception):
    pass


class HealthChecker(object):

    def __init__(self, host, ports, tunnel_host):
        # check ports we are forwarding to
        checklist = [(host, int(port)) for port in ports]
        # also check tunnel host SSH port
        checklist.append((tunnel_host, 22))
        self.checklist = frozenset(checklist)
        self.last_tcp_connect = defaultdict(time.time)

    def _tcp_connected(self, host, port):
        with closing(socket.socket()) as sock:
            logger.debug("Trying TCP connection to %s:%s" % (host, port))
            try:
                sock.connect((host, port))
            except (socket.gaierror, socket.error), e:
                logger.warning("Your network can't connect to %s:%s - %s",
                               host, port, str(e))
                logger.warning(
                    "Your tests may be affected by poor network connectivity.")
                return False
            return True

    def check(self):
        for pair in self.checklist:
            if self._tcp_connected(*pair):
                self.last_tcp_connect[pair] = time.time()
            elif time.time() - self.last_tcp_connect[pair] > HEALTH_CHECK_FAIL:
                raise HealthCheckFail("Could not connect to %s:%s" % pair +
                                      " for %s seconds" % HEALTH_CHECK_FAIL)


def _get_ssh_dash_Rs(options):
    dash_Rs = ""
    for port, remote_port in zip(options.ports, options.remote_ports):
        dash_Rs += "-R 0.0.0.0:%s:%s:%s " % (remote_port, options.host, port)
    return dash_Rs


def get_plink_command(options, tunnel_host):
    options.tunnel_host = tunnel_host
    return ("plink -v -l %s -pw %s -N " % (options.user, options.api_key) +
            _get_ssh_dash_Rs(options) +
            "%s" % tunnel_host)


def get_expect_script(options, tunnel_host):
    options.tunnel_host = tunnel_host
    return (
        "set timeout -1;"
        "spawn ssh-keygen -q -R %s;" % tunnel_host +
        "spawn ssh -q -p 22 -l %s -N %s %s;"
            % (options.user, _get_ssh_dash_Rs(options), tunnel_host) +
        'expect \\"Are you sure you want to continue connecting'
        ' (yes/no)?\\";send -- yes\\r;'
        "expect *password:;send -- %s\\r;" % options.api_key +
        "interact")


def shutdown_and_exit(tunnel):
    tunnel.shutdown()
    logger.info("Exiting.")
    raise SystemExit()


def run_reverse_ssh(options, tunnel):
    logger.info("Starting SSH process ..")
    if is_windows:
        cmd = "echo 'n' | %s" % get_plink_command(options, tunnel.host)
    else:
        cmd = 'expect -c "%s"' % get_expect_script(options, tunnel.host)

    with open(os.devnull) as devnull:
        stdout = devnull  # if not options.debug else None
        logger.debug("running cmd: %s" % cmd)
        reverse_ssh = subprocess.Popen("exec %s" % cmd, shell=True,
                                       stdout=stdout)

    # ssh process is running
    announced_running = False
    health = HealthChecker(options.host, options.ports, tunnel.host)
    start_time = int(time.time())
    while reverse_ssh.poll() is None:
        if (int(time.time()) - start_time) % HEALTH_CHECK_INTERVAL == 0:
            try:
                health.check()
            except HealthCheckFail, e:
                logger.error(e)
                shutdown_and_exit(tunnel)

        if not announced_running:
            logger.info("SSH is running. You may start your tests.")
            announced_running = True
        time.sleep(1)

    # ssh process has exited
    if reverse_ssh.returncode != 0:
        logger.warning("SSH tunnel exited with error code %d",
                       reverse_ssh.returncode)
    else:
        logger.info("SSH tunnel process exited with success code")


def setup_signal_handler(tunnel):

    def sig_handler(signum, frame):
        logger.info("Received signal %d" % signum)
        shutdown_and_exit(tunnel)

    # TODO: remove SIGTERM when we implement tunnel leases
    if is_windows:
        # TODO: What do these Windows signals mean?
        supported_signals = ["SIGABRT", "SIGBREAK", "SIGINT", "SIGTERM"]
    else:
        supported_signals = ["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM"]
    for sig in supported_signals:
        signal.signal(getattr(signal, sig), sig_handler)


def get_options():
    # defaults we need to set outside of optparse
    port = "80"
    remote_port = "80"
    #logfile = "%s.log" % NAME

    op = optparse.OptionParser()
    op.add_option("-u", "--user", "--username")
    op.add_option("-k", "--api-key")
    op.add_option("-s", "--host", default="localhost",
                  help="[default: %default]")
    op.add_option("-p", "--port", action="append", dest="ports", default=[],
                  help="[default: %s]" % port)
    op.add_option("-d", "--domain", action="append", dest="domains",
                  help="Requests for these will go through the tunnel."
                       " Example: -d example.test -d '*.example.test'")
    op.add_option("-q", "--quiet", "-l", "--log",
                  action="store_true", default=False,
                  help="Sends output to a logfile instead of stdout.")
    #op.add_option("--daemonize", action="store_true", default=False)

    og = optparse.OptionGroup(op, "Advanced options")
    og.add_option("-r", "--remote-port",
        action="append", dest="remote_ports", default=[],
        help="The port your tests expect to hit when they run."
             " By default, we use port %s, the standard webserver port."
             " If you know for sure _all_ your tests use something like"
             " http://site.test:8080/ then set this 8080." % remote_port)
    #og.add_option("--pidfile", default="%s.pid" % NAME,
    #      help="Name of the pidfile to drop when the --daemonize option is"
    #           "used. [default: %default]")
    og.add_option("--logfile", default="%s.log" % NAME,
          help="Name of the logfile to write to. [default: %default]")
    op.add_option_group(og)

    og = optparse.OptionGroup(op, "Script debugging options")
    og.add_option("--debug", action="store_true", default=False,
                  help="Spews extra info into ")
    og.add_option("--rest-url", default="https://saucelabs.com/rest",
                  help="[default: %default]")
    op.add_option_group(og)

    (options, args) = op.parse_args()

    # manually set these defaults
    if options.ports == []:
        options.ports.append(port)
    if options.remote_ports == []:
        options.remote_ports.append(remote_port)
    #if options.daemonize:
    #    options.logfile = options.logfile or logfile

    if len(options.ports) != len(options.remote_ports):
        op.error("Each port (-p) being forwarded to requires a corresponding "
                 "remote port (-r) being forwarded from. For example: -p 5000 "
                 "-r 80 -p 5001 -r 443")

    # check for required options without defaults
    for opt in ["user", "api_key", "host", "domains"]:
        if not hasattr(options, opt) or not getattr(options, opt):
            op.error("Missing required argument(s)!")

    return options


def setup_logging(logfile=None, quiet=False, debug=False):
    logger.setLevel(logging.DEBUG)

    if not quiet:
        stdout = logging.StreamHandler(sys.stdout)
        stdout.setLevel(logging.INFO)
        stdout.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        logger.addHandler(stdout)

    if logfile:
        if debug and not quiet:
            print "Debug messages will be sent to %s" % logfile
        fileout = logging.handlers.RotatingFileHandler(
            filename=logfile, maxBytes=256 * 1024 ** 2, backupCount=8)
        fileout.setLevel((logging.INFO, logging.DEBUG)[bool(debug)])
        fileout.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s"))
        logger.addHandler(fileout)


def main():
    os.umask(0077)
    options = get_options()
    setup_logging(options.logfile, options.quiet, options.debug)
    logger.info("Starting.")

    try:
        with closing(TunnelMachine(
                options.rest_url, options.user,
                options.api_key, options.domains)) as tunnel:
            setup_signal_handler(tunnel)
            tunnel.ready_wait()
            run_reverse_ssh(options, tunnel)
    except RESTConnectionError, e:
        logger.error(e)
    logger.info("Exiting.")


if __name__ == '__main__':
    NAME = os.path.basename(__file__).rpartition(".py")[0]
    main()
