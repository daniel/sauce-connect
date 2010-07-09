#!/usr/bin/env python
# encoding: utf-8
from __future__ import with_statement

# TODO minimum:
#   * Error handling and retry
#   * Package with dependencies and licenses
#   * Developer docs for how to build Windows .exe
#   * Fix scary Windows plink.exe coming after useful log messages
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
#   * unix: Close ssh-keygen process after use
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
import tempfile
from contextlib import closing
from collections import defaultdict

try:
    import json
except ImportError:
    import simplejson as json  # Python 2.5 dependency

NAME = __name__
VERSION = 0
VERSIONS_URL = "http://saucelabs.com/versions.json"
DOWNLOAD_URL = "???"

REST_POLL_WAIT = 3
HEALTH_CHECK_INTERVAL = 30
HEALTH_CHECK_FAIL = 5 * 60  # no good check after this amount of time == fail

is_windows = platform.system().lower() == "windows"
logger = logging.getLogger(NAME)


class RESTConnectionError(Exception):

    def __init__(self, e):
        self.e = e

    def __str__(self):
        return "Failed to contact Sauce Labs REST API (%s)" % str(self.e)


class TunnelMachineError(Exception):
    pass


class TunnelMachine(object):

    REST_RETRY_WAIT = 5
    REST_RETRY_MAX = 6

    _host_search = re.compile("//([^/]+)").search

    def __init__(self, rest_url, user, password, domains):
        self.user = user
        self.password = password
        self.domains = set(domains)

        self.is_shutdown = False
        self.base_url = "%(rest_url)s/%(user)s/tunnels" % locals()
        self.rest_host = self._host_search(rest_url).group(1)
        self.basic_auth_header = {"Authorization": "Basic %s" %
                                 ("%s:%s" % (user, password)).encode("base64")}

        self._set_urlopen(rest_url, user, password)

        for attempt in xrange(1, self.REST_RETRY_MAX + 1):
            try:
                self._start_tunnel()
                break
            except RESTConnectionError, e:
                logger.error(e)
                if attempt == self.REST_RETRY_MAX:
                    raise TunnelMachineError("Failed to start tunnel machine "
                                             "after %d tries" % attempt)
                logger.info("Retrying in %ds", self.REST_RETRY_WAIT)
                time.sleep(self.REST_RETRY_WAIT)

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
            logger.info(
                "Shutting down other tunnels using requested domains")
        for tunnel_id in kill_list:
            logger.debug("Shutting down old tunnel: %s" % tunnel_id)
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
        logger.info("Tunnel is running on %s" % self.host)

    def shutdown(self):
        if self.is_shutdown:
            return

        logger.info("Shutting down tunnel (please wait)")
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
        logger.info("Tunnel is shutdown")
        self.is_shutdown = True

    # Make us usable with contextlib.closing
    close = shutdown


class HealthCheckFail(Exception):
    pass


class HealthChecker(object):

    def __init__(self, host, ports, fail_msg=None):
        """fail_msg can include '%(host)s' and '%(port)d'"""
        self.host = host
        self.fail_msg = fail_msg
        if not self.fail_msg:
            self.fail_msg = ("!! Your tests will fail while your network "
                             "can not get to %(host)s:%(port)d.")
        self.ports = frozenset(int(p) for p in ports)
        self.last_tcp_connect = defaultdict(time.time)

    def _tcp_connected(self, port):
        with closing(socket.socket()) as sock:
            logger.debug("Trying TCP connection to %s:%s" % (self.host, port))
            try:
                sock.connect((self.host, port))
                return True
            except (socket.gaierror, socket.error), e:
                logger.warning("Could not connect to %s:%s (%s)",
                               self.host, port, str(e))
                return False

    def check(self):
        for port in self.ports:
            if self._tcp_connected(port):
                self.last_tcp_connect[port] = time.time()
                continue
            # TCP connection failed
            logger.warning(self.fail_msg % dict(host=self.host, port=port))
            if time.time() - self.last_tcp_connect[port] > HEALTH_CHECK_FAIL:
                raise HealthCheckFail(
                    "Could not connect to %s:%s for %s seconds"
                    % (self.host, port, HEALTH_CHECK_FAIL))


class ReverseSSHError(Exception):
    pass


class ReverseSSH(object):

    RETRY_SSH_MAX = 3

    def __init__(self, tunnel, host, ports, tunnel_ports):
        self.tunnel = tunnel
        self.host = host
        self.ports = ports
        self.tunnel_ports = tunnel_ports

    @property
    def _dash_Rs(self):
        dash_Rs = ""
        for port, tunnel_port in zip(self.ports, self.tunnel_ports):
            dash_Rs += "-R 0.0.0.0:%s:%s:%s " % (tunnel_port, self.host, port)
        return dash_Rs

    def get_plink_command(self):
        return ("plink -l %s -pw %s -N %s %s"
                % (self.tunnel.user, self.tunnel.password,
                   self._dash_Rs, self.tunnel.host))

    def get_expect_script(self):
        return (
            "set timeout -1;"
            "spawn ssh-keygen -q -R %s;" % self.tunnel.host +
            "spawn ssh -q -p 22 -l %s -N %s %s;"
                % (self.tunnel.user, self._dash_Rs, self.tunnel.host) +
            'expect \\"Are you sure you want to continue connecting'
            ' (yes/no)?\\";send -- yes\\r;'
            "expect *password:;send -- %s\\r;" % self.tunnel.password +
            "interact")

    def _start_reverse_ssh(self):
        logger.info("Starting SSH process ..")
        if is_windows:
            cmd = "echo 'n' | %s" % self.get_plink_command()
        else:
            cmd = 'expect -c "%s"' % self.get_expect_script()

        # start ssh process
        devnull = open(os.devnull)
        stderr_tmp = tempfile.TemporaryFile()
        logger.debug("running cmd: %s" % cmd)
        reverse_ssh = subprocess.Popen(
            cmd, shell=True, stdout=devnull, stderr=stderr_tmp)

        # ssh process is running
        announced_running = False
        forwarded_health = HealthChecker(self.host, self.ports)
        tunnel_health = HealthChecker(host=self.tunnel.host, ports=[22],
                fail_msg="!! Your tests may fail because your network"
                         " can not get to the tunnel host.")
        start_time = int(time.time())
        while reverse_ssh.poll() is None:
            now = int(time.time())
            if (now - start_time) % HEALTH_CHECK_INTERVAL == 0:
                try:
                    forwarded_health.check()
                    tunnel_health.check()
                except HealthCheckFail, e:
                    raise ReverseSSHError(e)
            if not announced_running:
                logger.info("SSH is running. You may start your tests.")
                announced_running = True
            time.sleep(1)

        # ssh process has exited
        devnull.close()
        stderr_tmp.seek(0)
        reverse_ssh_stderr = stderr_tmp.read()
        stderr_tmp.close()
        if reverse_ssh.returncode != 0:
            logger.warning("SSH process exited with error code %d",
                           reverse_ssh.returncode)
        else:
            logger.info("SSH process exited")
        if reverse_ssh_stderr:
            logger.warning("SSH stderr was: '%s'" % reverse_ssh_stderr)

        return reverse_ssh.returncode

    def run(self):
        for attempt in xrange(1, self.RETRY_SSH_MAX + 1):
            # if clean exit, then bail (e.g., process receives SIGINT)
            if self._start_reverse_ssh() == 0:
                return
        raise ReverseSSHError("SSH process errored %d times" % attempt)


def shutdown_and_exit(tunnel):
    tunnel.shutdown()
    logger.info("\ Exiting /")
    raise SystemExit()


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


def check_version():
    failed_msg = "Skipping version check"
    logger.debug("Checking version")
    try:
        with closing(urllib2.urlopen(VERSIONS_URL)) as resp:
            assert resp.msg == "OK", "Got HTTP response %s" % resp.msg
            version_doc = json.loads(resp.read())
    except (urllib2.URLError, AssertionError), e:
        logger.debug("Could not check version: %s", str(e))
        logger.info(failed_msg)
        return
    try:
        latest = version_doc[u'Sauce Tunnel'][u'version']
    except KeyError, e:
        logger.debug("Bad version doc, missing key: %s", str(e))
        logger.info(failed_msg)
        return

    if VERSION < latest:
        logger.warning("** Please update Sauce Tunnel: %s" % DOWNLOAD_URL)
    return latest


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


def get_options():
    # defaults we need to set outside of optparse
    def_port = "80"
    def_tunnel_port = "80"
    #logfile = "%s.log" % NAME

    op = optparse.OptionParser()
    op.add_option("-u", "--user", "--username")
    op.add_option("-k", "--api-key")
    op.add_option("-s", "--host", default="localhost",
                  help="[default: %default]")
    op.add_option("-p", "--port", action="append", dest="ports", default=[],
                  help="[default: %s]" % def_port)
    op.add_option("-d", "--domain", action="append", dest="domains",
                  help="Requests for these will go through the tunnel."
                       " Example: -d example.test -d '*.example.test'")
    op.add_option("-q", "--quiet", "-l", "--log",
                  action="store_true", default=False,
                  help="Sends output to a logfile instead of stdout.")
    #op.add_option("--daemonize", action="store_true", default=False)

    og = optparse.OptionGroup(op, "Advanced options")
    og.add_option("-r", "--tunnel-port",
        action="append", dest="tunnel_ports", default=[],
        help="The port your tests expect to hit when they run."
             " By default, we use port %s, the standard webserver port."
             " If you know for sure _all_ your tests use something like"
             " http://site.test:8080/ then set this 8080." % def_tunnel_port)
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
        options.ports.append(def_port)
    if options.tunnel_ports == []:
        options.tunnel_ports.append(def_tunnel_port)
    #if options.daemonize:
    #    options.logfile = options.logfile or logfile

    if len(options.ports) != len(options.tunnel_ports):
        op.error("Each port (-p) being forwarded to requires a corresponding "
                 "remote port (-r) being forwarded from. For example: -p 5000 "
                 "-r 80 -p 5001 -r 443")

    # check for required options without defaults
    for opt in ["user", "api_key", "host", "domains"]:
        if not hasattr(options, opt) or not getattr(options, opt):
            op.error("Missing required argument(s)!")

    return options


def main():
    os.umask(0077)
    options = get_options()
    setup_logging(options.logfile, options.quiet, options.debug)

    logger.info("/ Starting \\")
    check_version()

    # Initial check of forwarded ports
    fail_msg = ("!! Are you sure your web server is on host '%(host)s' "
                "listening on port %(port)d? Your tests will fail while the "
                "server is unavailable.")
    HealthChecker(options.host, options.ports, fail_msg=fail_msg).check()

    try:
        tunnel = TunnelMachine(options.rest_url, options.user,
                               options.api_key, options.domains)
        setup_signal_handler(tunnel)
        tunnel.ready_wait()
    except TunnelMachineError, e:
        logger.error(e)
        logger.info("\\ Exiting /")
        raise SystemExit()

    ssh = ReverseSSH(tunnel, options.host, options.ports, options.tunnel_ports)
    try:
        ssh.run()
    except ReverseSSHError, e:
        logger.error(e)
    shutdown_and_exit(tunnel)


if __name__ == '__main__':
    NAME = os.path.basename(__file__).rpartition(".py")[0]
    main()
