# Container as a Service

This feature provides Container as a Service project for Sunbeam. It's based on [Magnum](https://docs.openstack.org/magnum/latest/), a Container as a Service project for OpenStack.

## Installation

To enable the Container as a Service project, you need an already bootstraped Sunbeam instance and the following features: Secrets, Loadbalancer. Then, you can install the feature with:

```bash
sunbeam enable caas
```

## Contents

This feature will install the following services:
- Magnum: Container as a Service project for OpenStack [charm](https://opendev.org/openstack/charm-magnum-k8s) [ROCK](https://github.com/canonical/ubuntu-openstack-rocks/tree/main/rocks/magnum-consolidated)
- MySQL Router for Magnum [charm](https://github.com/canonical/mysql-router-k8s-operator) [ROCK](https://github.com/canonical/charmed-mysql-rock)
- MySQL Instance in the case of a multi-mysql installation (for large deployments) [charm](https://github.com/canonical/mysql-k8s-operator) [ROCK](https://github.com/canonical/charmed-mysql-rock)

Services are constituted of charms, i.e. operator code, and ROCKs, the corresponding OCI images.

## Removal

To remove the feature, run:

```bash
sunbeam disable caas
```
