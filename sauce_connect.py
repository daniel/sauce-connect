#!/usr/bin/env python
# encoding: utf-8
from __future__ import with_statement

# TODO:
#   * Move to REST API v1
#   * windows: SSH link healthcheck (PuTTY session file hack?)
#   * Daemonizing
#     * issue: windows: no os.fork()
#     * issue: unix: null file descriptors causes Expect script to fail
#   * Renew tunnel lease (backend not implemented)
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
from collections import defaultdict
from contextlib import closing
from functools import wraps

try:
    import json
except ImportError:
    import simplejson as json  # Python 2.5 dependency

NAME = "sauce_connect"
RELEASE = 15
DISPLAY_VERSION = "%s release %s" % (NAME, RELEASE)
PRODUCT_NAME = u"Sauce Connect"
VERSIONS_URL = "http://saucelabs.com/versions.json"

RETRY_PROVISION_MAX = 4
RETRY_BOOT_MAX = 4
RETRY_REST_WAIT = 5
RETRY_REST_MAX = 6
REST_POLL_WAIT = 3
RETRY_SSH_MAX = 4
HEALTH_CHECK_INTERVAL = 15
HEALTH_CHECK_FAIL = 5 * 60  # no good check after this amount of time == fail
SIGNALS_RECV_MAX = 4  # used with --allow-unclean-exit

is_windows = platform.system().lower() == "windows"
is_openbsd = platform.system().lower() == "openbsd"
logger = logging.getLogger(NAME)


class HTTPResponseError(Exception):

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "HTTP server responded with '%s' (expected 'OK')" % self.msg


class TunnelMachineError(Exception):
    pass


class TunnelMachineProvisionError(TunnelMachineError):
    pass


class TunnelMachineBootError(TunnelMachineError):
    pass


class TunnelMachine(object):

    _host_search = re.compile("//([^/]+)").search

    def __init__(self, rest_url, user, password, domains, metadata=None):
        self.user = user
        self.password = password
        self.domains = set(domains)
        self.metadata = metadata or dict()

        self.reverse_ssh = None
        self.is_shutdown = False
        self.base_url = "%(rest_url)s/%(user)s/tunnels" % locals()
        self.rest_host = self._host_search(rest_url).group(1)
        self.basic_auth_header = {"Authorization": "Basic %s" %
            ("%s:%s" % (user, password)).encode("base64").strip()}

        self._set_urlopen(user, password)

        for attempt in xrange(1, RETRY_PROVISION_MAX):
            try:
                self._provision_tunnel()
                break
            except TunnelMachineProvisionError, e:
                logger.warning(e)
                if attempt == RETRY_PROVISION_MAX:
                    raise TunnelMachineError(
                        "!! Could not provision tunnel host. Please contact "
                        "help@saucelabs.com.")

    def _set_urlopen(self, user, password):
        # always send Basic Auth header for GET and POST
        # NOTE: we directly construct the header because it is more reliable
        #   and more efficient than HTTPBasicAuthHandler and we always need it
        opener = urllib2.build_opener()
        opener.addheaders = self.basic_auth_header.items()
        self.urlopen = opener.open

    # decorator
    def _retry_rest_api(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            previous_failed = False
            for attempt in xrange(1, RETRY_REST_MAX + 1):
                try:
                    result = f(*args, **kwargs)
                    if previous_failed:
                        logger.info(
                            "Connection succeeded")
                    return result
                except (HTTPResponseError,
                        urllib2.URLError, httplib.HTTPException,
                        socket.gaierror, socket.error), e:
                    logger.warning("Problem connecting to Sauce Labs REST API "
                                   "(%s)", str(e))
                    if attempt == RETRY_REST_MAX:
                        raise TunnelMachineError(
                            "Could not reach Sauce Labs REST API after %d "
                            "tries. Is your network down or firewalled?"
                            % attempt)
                    previous_failed = True
                    logger.debug("Retrying in %ds", RETRY_REST_WAIT)
                    time.sleep(RETRY_REST_WAIT)
        return wrapper

    @_retry_rest_api
    def _get_doc(self, url_or_req):
        with closing(self.urlopen(url_or_req)) as resp:
            if resp.msg != "OK":
                raise HTTPResponseError(resp.msg)
            return json.loads(resp.read())

    @_retry_rest_api
    def _get_delete_doc(self, url):
        # urllib2 doesn support the DELETE method (lame), so we build our own
        if self.base_url.startswith("https"):
            make_conn = httplib.HTTPSConnection
        else:
            make_conn = httplib.HTTPConnection
        with closing(make_conn(self.rest_host)) as conn:
            conn.request(method="DELETE", url=url,
                         headers=self.basic_auth_header)
            resp = conn.getresponse()
            if resp.reason != "OK":
                raise HTTPResponseError(resp.reason)
            return json.loads(resp.read())

    def _provision_tunnel(self):
        # Shutdown any tunnel using a requested domain
        kill_list = set()
        for doc in self._get_doc(self.base_url):
            if not doc.get('DomainNames'):
                continue
            if set(doc['DomainNames']) & self.domains:
                kill_list.add(doc['id'])
        if kill_list:
            logger.info(
                "Shutting down other tunnel hosts using requested domains")
            for tunnel_id in kill_list:
                for attempt in xrange(1, 4):  # try a few times, then bail
                    logger.debug(
                        "Shutting down old tunnel host: %s" % tunnel_id)
                    url = "%s/%s" % (self.base_url, tunnel_id)
                    doc = self._get_delete_doc(url)
                    if not doc.get('ok'):
                        logger.warning("Old tunnel host failed to shutdown?")
                        continue
                    doc = self._get_doc(url)
                    while doc.get('Status') not in ["halting", "terminated"]:
                        logger.debug(
                            "Waiting for old tunnel host to start halting")
                        time.sleep(REST_POLL_WAIT)
                        doc = self._get_doc(url)
                    break

        # Request a tunnel machine
        headers = {"Content-Type": "application/json"}
        data = json.dumps(dict(DomainNames=list(self.domains),
                               Metadata=self.metadata))
        req = urllib2.Request(url=self.base_url, headers=headers, data=data)
        doc = self._get_doc(req)
        if doc.get('error'):
            raise TunnelMachineProvisionError(doc['error'])
        for key in ['ok', 'id']:
            if not doc.get(key):
                raise TunnelMachineProvisionError(
                    "Document for provisioned tunnel host is missing the key "
                    "or value for '%s'" % key)
        self.id = doc['id']
        self.url = "%s/%s" % (self.base_url, self.id)
        logger.debug("Provisioned tunnel host: %s" % self.id)

    def ready_wait(self):
        """Wait for the machine to reach the 'running' state."""
        previous_status = None
        while True:
            doc = self._get_doc(self.url)
            status = doc.get('Status')
            if status == "running":
                break
            if status in ["halting", "terminated"]:
                raise TunnelMachineBootError("Tunnel host was shutdown")
            if status != previous_status:
                logger.info("Tunnel host is %s .." % status)
            previous_status = status
            time.sleep(REST_POLL_WAIT)
        self.host = doc['Host']
        logger.info("Tunnel host is running at %s" % self.host)

    def shutdown(self):
        if self.is_shutdown:
            return

        if self.reverse_ssh:
            self.reverse_ssh.stop()

        logger.info("Shutting down tunnel host (please wait)")
        logger.debug("Tunnel host ID: %s" % self.id)

        doc = self._get_delete_doc(self.url)
        assert doc.get('ok')

        previous_status = None
        while True:
            doc = self._get_doc(self.url)
            status = doc.get('Status')
            if status == "terminated":
                break
            if status != previous_status:
                logger.info("Tunnel host is %s .." % status)
            previous_status = status
            time.sleep(REST_POLL_WAIT)
        logger.info("Tunnel host is shutdown")
        self.is_shutdown = True

    # Make us usable with contextlib.closing
    close = shutdown

    def check_running(self):
        doc = self._get_doc(self.url)
        if doc.get('Status') == "running":
            return
        raise TunnelMachineError(
            "The tunnel host is no longer running. It may have been shutdown "
            "via the website or by another Sauce Connect script requesting these "
            "domains: %s" % list(self.domains))


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
        self.previous_failed = defaultdict(lambda: False)

    def _tcp_connected(self, port):
        with closing(socket.socket()) as sock:
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
                # TCP connection succeeded
                self.last_tcp_connect[port] = time.time()
                if self.previous_failed[port]:
                    logger.info(
                        "Succesfully connected to %s:%s" % (self.host, port))
                self.previous_failed[port] = False
                continue
            # TCP connection failed
            self.previous_failed[port] = True
            logger.warning(self.fail_msg % dict(host=self.host, port=port))
            if time.time() - self.last_tcp_connect[port] > HEALTH_CHECK_FAIL:
                raise HealthCheckFail(
                    "Could not connect to %s:%s for %s seconds"
                    % (self.host, port, HEALTH_CHECK_FAIL))


class ReverseSSHError(Exception):
    pass


class ReverseSSH(object):

    def __init__(self, tunnel, host, ports, tunnel_ports):
        self.tunnel = tunnel
        self.host = host
        self.ports = ports
        self.tunnel_ports = tunnel_ports

        self.proc = None
        self.readyfile = None

    @property
    def _dash_Rs(self):
        dash_Rs = ""
        for port, tunnel_port in zip(self.ports, self.tunnel_ports):
            dash_Rs += "-R 0.0.0.0:%s:%s:%s " % (tunnel_port, self.host, port)
        return dash_Rs

    def get_plink_command(self):
        return ("plink\plink -l %s -pw %s -N %s %s"
                % (self.tunnel.user, self.tunnel.password,
                   self._dash_Rs, self.tunnel.host))

    def get_expect_script(self):
        wait = "wait"
        if is_openbsd:  # using 'wait;' hangs the script on OpenBSD
            wait = "wait -nowait;sleep 1"  # hack

        host_ip = socket.gethostbyname(self.tunnel.host)
        script = (
            "spawn ssh-keygen -q -R %s;%s;" % (self.tunnel.host, wait) +
            "spawn ssh-keygen -q -R %s;%s;" % (host_ip, wait) +
            "spawn ssh -q -p 22 -l %s -o ServerAliveInterval=%s -N %s %s;"
                % (self.tunnel.user, HEALTH_CHECK_INTERVAL,
                   self._dash_Rs, self.tunnel.host) +
            'expect \\"Are you sure you want to continue connecting'
            ' (yes/no)?\\";send yes\\r;'
            "expect *password:;send -- %s\\r;" % self.tunnel.password +
            "expect -timeout -1 timeout")
        return script

    def _start_reverse_ssh(self, readyfile=None):
        logger.info("Starting SSH process ..")
        if is_windows:
            cmd = "echo 'n' | %s" % self.get_plink_command()
        else:
            cmd = 'exec expect -c "%s"' % self.get_expect_script()

        # start ssh process
        devnull = open(os.devnull)
        stderr_tmp = tempfile.TemporaryFile()
        self.proc = subprocess.Popen(
            cmd, shell=True, stdout=devnull, stderr=stderr_tmp)
        self.tunnel.reverse_ssh = self  # BUG: circular ref
        time.sleep(3)  # HACK: some startup time

        # ssh process is running
        announced_running = False
        forwarded_health = HealthChecker(self.host, self.ports)
        tunnel_health = HealthChecker(host=self.tunnel.host, ports=[22],
            fail_msg="!! Your tests may fail because your network can not get "
                     "to the tunnel host (%s:%d)." % (self.tunnel.host, 22))
        start_time = int(time.time())
        while self.proc.poll() is None:
            now = int(time.time())
            if not announced_running:
                # guarantee we health check on first iteration
                now = start_time
            if (now - start_time) % HEALTH_CHECK_INTERVAL == 0:
                self.tunnel.check_running()
                try:
                    forwarded_health.check()
                    tunnel_health.check()
                except HealthCheckFail, e:
                    raise ReverseSSHError(e)
            if not announced_running:
                logger.info("SSH is running. You may start your tests.")
                if readyfile:
                    self.readyfile = readyfile
                    f = open(readyfile, 'w')
                    f.close()
                announced_running = True
            time.sleep(1)

        # ssh process has exited
        devnull.close()
        stderr_tmp.seek(0)
        reverse_ssh_stderr = stderr_tmp.read().strip()
        stderr_tmp.close()
        if self.proc.returncode != 0:
            logger.warning("SSH process exited with error code %d",
                           self.proc.returncode)
        else:
            logger.info("SSH process exited (maybe due to network problems)")
        if reverse_ssh_stderr:
            logger.debug("SSH stderr was: '%s'" % reverse_ssh_stderr)

        return self.proc.returncode

    def _rm_readyfile(self):
        if self.readyfile and os.path.exists(self.readyfile):
            try:
                os.remove(self.readyfile)
            except OSError, e:
                logger.error("Couldn't remove %s: %s", self.readyfile, str(e))

    def stop(self):
        self._rm_readyfile()
        if is_windows or not self.proc:
            return
        try:
            os.kill(self.proc.pid, signal.SIGHUP)
            logger.debug("Sent SIGHUP to PID %d", self.proc.pid)
        except OSError:
            pass

    def run(self, readyfile=None):
        clean_exit = False
        for attempt in xrange(1, RETRY_SSH_MAX + 1):
            # returncode 0 will happen due to ServerAlive checks failing.
            # this may result in a listening port forwarding nowhere, so
            # don't bother restarting the SSH connection.
            # TODO: revisit if server uses OpenSSH instead of Twisted SSH
            if self._start_reverse_ssh(readyfile) == 0:
                clean_exit = True
        self._rm_readyfile()
        if not clean_exit:
            raise ReverseSSHError(
                "SSH process errored %d times (bad network?)" % attempt)


def peace_out(tunnel=None, returncode=0):
    """Shutdown the tunnel and raise SystemExit."""
    if tunnel:
        tunnel.shutdown()
    logger.info("\ Exiting /")
    raise SystemExit(returncode)


def setup_signal_handler(tunnel, options):
    signal_count = defaultdict(int)

    def sig_handler(signum, frame):
        if options.allow_unclean_exit:
            signal_count[signum] += 1
            if signal_count[signum] > SIGNALS_RECV_MAX:
                logger.info("Received signal %d too many times (%d). Making "
                            "unclean exit now!", signum, signal_count[signum])
                raise SystemExit(1)
        logger.info("Received signal %d", signum)
        peace_out(tunnel)  # exits

    # TODO: ?? remove SIGTERM when we implement tunnel leases
    if is_windows:
        # TODO: What do these Windows signals really mean?
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
        version = version_doc[PRODUCT_NAME][u'version']
        download_url = version_doc[PRODUCT_NAME][u'download_url']
    except KeyError, e:
        logger.debug("Bad version doc, missing key: %s", str(e))
        logger.info(failed_msg)
        return

    try:
        latest_release = int(version.partition("-r")[2])
    except (IndexError, ValueError), e:
        logger.debug("Couldn't parse release number: %s", str(e))
        logger.info(failed_msg)
        return
    if RELEASE < latest_release:
        update_msg = "** Please update %s: %s" % (PRODUCT_NAME, download_url)
        logger.warning(update_msg)
        sys.stderr.write("%s\n" % update_msg)


def setup_logging(logfile=None, quiet=False):
    logger.setLevel(logging.DEBUG)

    if not quiet:
        stdout = logging.StreamHandler(sys.stdout)
        stdout.setLevel(logging.INFO)
        stdout.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        logger.addHandler(stdout)

    if logfile:
        if not quiet:
            print "* Debug messages will be sent to %s" % logfile
        fileout = logging.handlers.RotatingFileHandler(
            filename=logfile, maxBytes=128 * 1024, backupCount=8)
        fileout.setLevel(logging.DEBUG)
        fileout.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s"))
        logger.addHandler(fileout)


def get_options():
    usage = """
Usage: %(name)s -u <user> -k <api_key> -s <webserver> -d <domain> [options]

Examples:
  Have tests for example.com go to a staging server on your intranet:
    %(name)s -u user -k 123-abc -s staging.local -d example.com

  Have HTTP and HTTPS traffic for *.example.com go to the staging server:
    %(name)s -u user -k 123-abc -s staging.local -p 80 -p 443 \\
                 -d example.com -d *.example.com

  Have tests for example.com go to your local machine on port 5000:
    %(name)s -u user -k 123-abc -s 127.0.0.1 -t 80 -p 5000 -d example.com

Performance tip:
  It is highly recommended you run this script on the same machine as your
  test server (i.e., you would use "-s 127.0.0.1" or "-s localhost"). Using
  a remote server introduces higher latency (slower web requests) and is
  another failure point.
""" % dict(name=NAME)

    usage = usage.strip()
    logfile = "%s.log" % NAME

    op = optparse.OptionParser(usage=usage, version=DISPLAY_VERSION)
    op.add_option("-u", "--user", "--username",
                  help="Your Sauce Labs account name.")
    op.add_option("-k", "--api-key",
                  help="On your account at https://saucelabs.com/account")
    op.add_option("-s", "--host", default="localhost",
                  help="Host to forward requests to. [%default]")
    op.add_option("-p", "--port", metavar="PORT",
                  action="append", dest="ports", default=[],
                  help="Forward to this port on HOST. Can be specified "
                       "multiple times. [80]")
    op.add_option("-d", "--domain", action="append", dest="domains",
            help="Repeat for each domain you want to forward requests for. "
                 "Example: -d example.test -d '*.example.test'")
    op.add_option("-q", "--quiet", action="store_true", default=False,
                  help="Minimize standard output (see %s)" % logfile)

    og = optparse.OptionGroup(op, "Advanced options")
    og.add_option("-t", "--tunnel-port", metavar="TUNNEL_PORT",
        action="append", dest="tunnel_ports", default=[],
        help="The port your tests expect to hit when they run."
             " By default, we use the same ports as the HOST."
             " If you know for sure _all_ your tests use something like"
             " http://site.test:8080/ then set this 8080.")
    og.add_option("--logfile", default=logfile,
          help="Path of the logfile to write to. [%default]")
    og.add_option("--readyfile",
                  help="Path of the file to drop when the tunnel is ready "
                       "for tests to run. By default, no file is dropped.")
    op.add_option_group(og)

    og = optparse.OptionGroup(op, "Script debugging options")
    og.add_option("--rest-url", default="https://saucelabs.com/rest",
                  help="[%default]")
    og.add_option("--allow-unclean-exit", action="store_true", default=False)
    op.add_option_group(og)

    (options, args) = op.parse_args()

    # default to 80 and default to matching host ports with tunnel ports
    if not options.ports and not options.tunnel_ports:
        options.ports = ["80"]
    if options.ports and not options.tunnel_ports:
        options.tunnel_ports = options.ports[:]

    if len(options.ports) != len(options.tunnel_ports):
        sys.stderr.write("Error: Options -t and -p need to be paired\n\n")
        print "Help with options -t and -p:"
        print "  When forwarding multiple ports, you must pair the tunnel port"
        print "  to forward with the host port to forward to."
        print ""
        print "Example option usage:"
        print "  To have your test's requests to 80 and 443 go to your test"
        print "  server on ports 5000 and 5001: -t 80 -p 5000 -t 443 -p 5001"
        raise SystemExit(1)

    # check for required options without defaults
    for opt in ["user", "api_key", "host", "domains"]:
        if not hasattr(options, opt) or not getattr(options, opt):
            sys.stderr.write("Error: Missing required argument(s)\n\n")
            op.print_help()
            raise SystemExit(1)

    # check for '/' in any domain names (might be a URL)
    # TODO: domain is not an IP
    # TODO: check domain uses a dot and a tld of 2 chars or more
    if [dom for dom in options.domains if '/' in dom]:
        sys.stderr.write(
              "Error: Domain contains illegal character '/' in it.\n")
        print "       Did you use a URL instead of just the domain?\n"
        print "Examples: -d example.com -d '*.example.com' -d cdn.example.org"
        print ""
        raise SystemExit(1)

    return options


class MissingDependenciesError(Exception):

    deb_pkg = dict(ssh="openssh-client", expect="expect")

    def __init__(self, dependency, included=False):
        self.dependency = dependency
        self.included = included

    def __str__(self):
        msg = "You are missing '%s'." % self.dependency
        if self.included:
            return (msg + " This should have come with the zip\n"
                    "you downloaded. If you need assistance, please "
                    "contact help@saucelabs.com.")

        msg += " Please install it or contact\nhelp@saucelabs.com for help."
        try:
            linux_distro = platform.linux_distribution
        except AttributeError:  # Python 2.5
            linux_distro = platform.dist
        if linux_distro()[0].lower() in ['ubuntu', 'debian']:
            if self.dependency in self.deb_pkg:
                msg += ("\n\nTo install: sudo aptitude install %s"
                        % self.deb_pkg[self.dependency])
        return msg


def check_dependencies():
    if is_windows:
        if not os.path.exists("plink\plink.exe"):
            raise MissingDependenciesError("plink\plink.exe", included=True)
        return

    # on unix
    with open(os.devnull) as devnull:
        for command in ["ssh -V", "expect -v"]:
            try:
                subprocess.check_call(command, shell=True, stdout=devnull,
                                               stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError:
                dependency = command.split(" ")[0]
                raise MissingDependenciesError(dependency, included=False)


def _run(options):
    if not options.quiet:
        print ".---------------------------------------------------."
        print "|  Have questions or need help with Sauce Connect?  |"
        print "|  Contact us: http://saucelabs.com/forums          |"
        print "-----------------------------------------------------"
    logger.info("/ Starting \\")
    logger.info("%s" % DISPLAY_VERSION)
    check_version()

    # log the options
    _ops = dict(options.__dict__)
    del _ops['api_key']  # no need to log the API key
    logger.debug("options: %s" % _ops)

    metadata = dict(ScriptName=NAME,
                    ScriptRelease=RELEASE,
                    Platform=platform.platform(),
                    PythonVersion=platform.python_version(),
                    OwnerHost=options.host,
                    OwnerPorts=options.ports,
                    Ports=options.tunnel_ports, )
    logger.debug("metadata: %s" % metadata)

    logger.info("Forwarding: %s:%s -> %s:%s",
                options.domains, options.tunnel_ports,
                options.host, options.ports)

    # Initial check of forwarded ports
    fail_msg = ("!! Are you sure this machine can get to your web server on "
                "host '%(host)s' listening on port %(port)d? Your tests will "
                "fail while the server is unreachable.")
    HealthChecker(options.host, options.ports, fail_msg=fail_msg).check()

    for attempt in xrange(1, RETRY_BOOT_MAX + 1):
        try:
            tunnel = TunnelMachine(options.rest_url, options.user,
                                   options.api_key, options.domains, metadata)
        except TunnelMachineError, e:
            logger.error(e)
            peace_out(returncode=1)  # exits
        setup_signal_handler(tunnel, options)
        try:
            tunnel.ready_wait()
            break
        except TunnelMachineError, e:
            logger.warning(e)
            if attempt < RETRY_BOOT_MAX:
                logger.info("Requesting new tunnel")
                continue
            logger.error("!! Could not get tunnel host")
            logger.info("** Please contact help@saucelabs.com")
            peace_out(tunnel, returncode=1)  # exits

    ssh = ReverseSSH(tunnel, options.host, options.ports, options.tunnel_ports)
    try:
        ssh.run(options.readyfile)
    except (ReverseSSHError, TunnelMachineError), e:
        logger.error(e)
    peace_out(tunnel)  # exits


def main():
    try:
        check_dependencies()
    except MissingDependenciesError, e:
        print "\n== Missing requirements ==\n"
        print e
        raise SystemExit(1)

    options = get_options()
    setup_logging(options.logfile, options.quiet)

    try:
        _run(options)
    except Exception, e:
        logger.exception("Unhandled exception: %s", str(e))
        msg = "*** Please send this error to help@saucelabs.com. ***"
        logger.critical(msg)
        sys.stderr.write("\noptions: %s\n\n%s\n" % (_ops, msg))


if __name__ == '__main__':
    try:
        main()
    except Exception, e:
        msg = "*** Please send this error to help@saucelabs.com. ***"
        msg = "*" * len(msg) + "\n%s\n" % msg + "*" * len(msg)
        sys.stderr.write("\n%s\n\n" % msg)
        raise
