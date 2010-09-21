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

build = $(shell bash get_build)
release = $(shell python -c 'import sauce_connect; print sauce_connect.RELEASE')
releasedir = "Sauce-Connect-1.0-r$(release)"
outputdir = "Output/$(releasedir)"

all: unix windows
	cd Output; zip -mrT $(releasedir)-$(build).zip $(releasedir)

test: clean
	nosetests tests

clean:
	rm -rf Output
	rm -rf dist
	find . -name '*.pyc' -delete

prebuild:
	test -d cache || mkdir cache
	test -d $(outputdir) || mkdir -p $(outputdir)

distfiles:
	cp changelog $(outputdir)
	cp LICENSE $(outputdir)

windows: prebuild distfiles plink.exe py2exe
	cp -r windows $(outputdir)
	mkdir $(outputdir)/plink
	cp cache/plink.exe $(outputdir)/plink
	cp cache/license.html $(outputdir)/plink

unix: prebuild distfiles simplejson
	cp -r unix $(outputdir)
	cp -r cache/simplejson-2.1.1/simplejson $(outputdir)/unix
	cp cache/simplejson-2.1.1/LICENSE.txt $(outputdir)/unix/simplejson
	cp sauce_connect.py $(outputdir)/unix/sauce_connect

plink.exe:
	test -s cache/$@ || curl -L -o cache/$@ http://the.earth.li/~sgtatham/putty/latest/x86/plink.exe
	test -s cache/license.html || curl -L -o cache/license.html http://www.chiark.greenend.org.uk/~sgtatham/putty/licence.html

py2exe:
	python setup_windows.py py2exe
	mv dist/sauce_connect.exe $(outputdir)

simplejson:
	test -s cache/simplejson-2.1.1.tar.gz || curl -L -o cache/simplejson-2.1.1.tar.gz http://pypi.python.org/packages/source/s/simplejson/simplejson-2.1.1.tar.gz
	tar xzf cache/simplejson-2.1.1.tar.gz -C cache
