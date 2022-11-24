# mintest.c - a minimal C unit testing framework

Simple unit testing tools built specifically for this project. Might become its
own project at some point.

NOTE: mocking of kernel functions does not currently work in x86_64,
leading to a bunch of failed tests (Segmentation faults). Test on ARM64.
