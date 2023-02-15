#!/bin/bash

# Installs all dependencies.

if [ ! -d 'dependencies' ]
then
	mkdir dependencies
fi

# libconfig

if [ ! -d 'dependencies/libconfig-1.7.3' ]
then
	cd dependencies &&
	wget http://hyperrealm.github.io/libconfig/dist/libconfig-1.7.3.tar.gz &&
	tar -xzf libconfig-1.7.3.tar.gz &&
	cd libconfig-1.7.3 &&
	cd ../.. ||
	rmdir dependencies/libconfig-1.7.3
fi

if [ ! -d 'dependencies/libconfig-install' ]
then
	installdir=$(pwd)/dependencies/libconfig-install
	mkdir -p ${installdir} &&
	cd dependencies/libconfig-1.7.3 &&
	./configure prefix="${installdir}" && 
	make &&
	make install  &&
	cd ../.. 
fi

# CRIU

if [ ! -d dependencies/criu-3.17.1 ]
then
	cd dependencies &&
	wget https://github.com/checkpoint-restore/criu/archive/refs/tags/v3.17.1.tar.gz &&
	tar -xzf v3.17.1.tar.gz &&
	cd .. ||
	rmdir dependencies/criu-3.17.1
fi

if [ ! -d dependencies/criu-install ]
then
	sudo apt-get -y --no-install-recommends install libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler python-protobuf asciidoc xmlto pkg-config python-ipaddress libbsd-dev iproute2 libnftnl4 libnftnl-dev libcap-dev libnl-3-dev libnet-dev libaio-dev libgnutls28-dev python3-future &&
	cd dependencies/criu-3.17.1 &&
	make
	if [ $? != 0 ]
	then
		exit 1
	fi
	mkdir ../criu-install &&
	PREFIX=$(dirname $(pwd))/criu-install make install
	if [ $? != 0 ]
	then

		rmdir ../criu-install
		exit 1
	fi
	cd ../../
fi
