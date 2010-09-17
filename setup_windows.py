from distutils.core import setup
import py2exe


def script(script, name):
    return {
        "script" : script,
        "dest_base" : name,
#        "icon_resources" : [(1, "windows/sauce_connect.ico")], # Soon!
    }

SCRIPTS = (
    ("sauce_connect.py", "sauce_connect"),
)

options = {
           'dll_excludes': [ "mswsock.dll", "powrprof.dll" ],
           'bundle_files': 1,
          }

setup(
    console = [ script(path, name) for path, name in SCRIPTS ],
    options = {"py2exe": options},
    zipfile = None,
)
