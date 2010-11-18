set -e
nosetests --with-xunit tests/
make clean
make all
