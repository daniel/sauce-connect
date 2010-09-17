Sauce Connect
=============

Our own script to get a private SHH tunnel with Sauce Labs' infrastructure.
Once the tunnel is up and running, our servers will be able to go through it to
access your private applications.

For more info: http://saucelabs.com/products/docs/sauce-connect
Questions: http://saucelabs.com/forums

Code structure
--------------

All the code is actually in a single script named `sauce_connect.py`.  The
different platform dependent files are located in bot the `unix` and `windows`
directories and will be copied as is to the final zip during the build process.
The script depends in both
[simplejson](http://pypi.python.org/pypi/simplejson/) and
[plink](http://www.chiark.greenend.org.uk/~sgtatham/putty/), they are
downloaded and added (licenses included) to the final zip during the build,
too.

Building
--------
Just run `make windows` or `make unix` from the root directory to get a zip
ready to distribute.
For dependencies, read the `Makefile`

Installation
------------

Once built, you don't need to install it. Just download, unzip and run from the
console:

    ./sauce_connect -h


For more info: http://saucelabs.com/products/docs/sauce-connect
Questions: http://saucelabs.com/forums
