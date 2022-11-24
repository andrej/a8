#!/bin/bash

# Installs all dependencies.

if [ ! -d 'dependencies' ]
then
	mkdir dependencies
fi

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
