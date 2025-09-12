About
=====

The `tests` folder contains both unit and functional tests that exercise
the Sunbeam cli.

Functional tests
================

The functional tests from `tests/functional/local` run against a local
cluster deployed in manual mode. If no deployment is detected, a new one
will be bootstrapped.

A manifest used during bootstrap (and other Sunbeam operations) may be
provided.

Some of the tests (e.g. SR-IOV) require dedicated hardware that will
be specified using command arguments (e.g the SR-IOV interface to use).
This is safer than trying to discover which resources to use and it allows
exercising multiple scenarios.

Sample invocation:

```
tox -e functional -- \
	--sriov-interface-name=eno2 \
	--manifest-path ~/sunbeam-manifest.yaml
```
