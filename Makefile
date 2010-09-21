# For building you'll need
#
# Windows:
# * py2exe (http://www.py2exe.org/)
# * A Unix like environment with git, make, rm, cp, curl, zip and unzip
# 	- I'm using http://code.google.com/p/msysgit/ (had to add make, zip and unzip by hand)
#   - For this Makefile to work, you'll need Python in your path
#
# Unix:
# * nothing :)

build = $(shell sh get_build)

all: 
	@echo Please specify "windows" or "unix"

clean:
	rm -rf Output/*
	rm -f *.pyc
	rm -rf dist

test: clean
	nosetests tests

prebuild: clean
	test -d cache || mkdir cache
	test -d Output/Sauce-Connect || mkdir -p Output/Sauce-Connect

distfiles:
	cp changelog Output/Sauce-Connect
	cp LICENSE Output/Sauce-Connect

windows: prebuild distfiles plink.exe py2exe
	cp -r windows/* Output/Sauce-Connect
	mkdir Output/Sauce-Connect/plink
	cp cache/plink.exe Output/Sauce-Connect/plink
	cp cache/license.html Output/Sauce-Connect/plink
	cd Output; zip -mrT Sauce-Connect-1.0-$(build)-$@.zip Sauce-Connect

unix: prebuild distfiles simplejson
	cp -r unix/* Output/Sauce-Connect
	cp -r cache/simplejson-2.1.1/simplejson Output/Sauce-Connect
	cp cache/simplejson-2.1.1/LICENSE.txt Output/Sauce-Connect/simplejson
	cp sauce_connect.py Output/Sauce-Connect/sauce_connect
	cd Output; zip -mrT Sauce-Connect-1.0-$(build)-$@.zip Sauce-Connect

plink.exe:
	test -s cache/$@ || curl -L -o cache/$@ http://the.earth.li/~sgtatham/putty/latest/x86/plink.exe 
	test -s cache/license.html || curl -L -o cache/license.html http://www.chiark.greenend.org.uk/~sgtatham/putty/licence.html

py2exe:
	python setup_windows.py py2exe
	mv dist/sauce_connect.exe Output/Sauce-Connect

simplejson:
	test -s cache/simplejson-2.1.1.tar.gz || curl -L -o cache/simplejson-2.1.1.tar.gz http://pypi.python.org/packages/source/s/simplejson/simplejson-2.1.1.tar.gz
	tar xzf cache/simplejson-2.1.1.tar.gz -C cache
