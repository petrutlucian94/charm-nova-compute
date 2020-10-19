# Overview

This charm provides Nova Compute, the OpenStack compute service. Its target
platform is Ubuntu (preferably LTS) + OpenStack.

# Usage

The following interfaces are provided:

  - cloud-compute - Used to relate (at least) with one or more of
    nova-cloud-controller, glance, ceph, cinder, mysql, ceilometer-agent,
    rabbitmq-server, neutron

  - nrpe-external-master - Used to generate Nagios checks.

## Configuration

This section covers common and/or important configuration options. See file
`config.yaml` for the full list of options, along with their descriptions and
default values. See the [Juju documentation][juju-docs-config-apps] for details
on configuring applications.

#### `openstack-origin`

The `openstack-origin` option states the software sources. A common value is an
OpenStack UCA release (e.g. 'cloud:xenial-queens' or 'cloud:bionic-ussuri').
See [Ubuntu Cloud Archive][wiki-uca]. The underlying host's existing apt
sources will be used if this option is not specified (this behaviour can be
explicitly chosen by using the value of 'distro').

#### `pool-type`

The `pool-type` option dictates the Ceph storage pool type. See sections 'Ceph
pool type' and 'RBD Nova images' for more information.

## Ceph pool type

Ceph storage pools can be configured to ensure data resiliency either through
replication or by erasure coding. This charm supports both types via the
`pool-type` configuration option, which can take on the values of 'replicated'
and 'erasure-coded'. The default value is 'replicated'.

For this charm, the pool type will be associated with Nova-managed images.

> **Note**: Erasure-coded pools are supported starting with Ceph Luminous.

### Replicated pools

Replicated pools use a simple replication strategy in which each written object
is copied, in full, to multiple OSDs within the cluster.

The `ceph-osd-replication-count` option sets the replica count for any object
stored within the 'nova' rbd pool. Increasing this value increases data
resilience at the cost of consuming more real storage in the Ceph cluster. The
default value is '3'.

> **Important**: The `ceph-osd-replication-count` option must be set prior to
  adding the relation to the ceph-mon application. Otherwise, the pool's
  configuration will need to be set by interfacing with the cluster directly.

### Erasure coded pools

Erasure coded pools use a technique that allows for the same resiliency as
replicated pools, yet reduces the amount of space required. Written data is
split into data chunks and error correction chunks, which are both distributed
throughout the cluster.

> **Note**: Erasure coded pools require more memory and CPU cycles than
  replicated pools do.

When using erasure coding two pools will be created: a replicated pool (for
storing RBD metadata) and an erasure coded pool (for storing the data written
into the RBD). The `ceph-osd-replication-count` configuration option only
applies to the metadata (replicated) pool.

Erasure coded pools can be configured via options whose names begin with the
`ec-` prefix.

> **Important**: It is strongly recommended to tailor the `ec-profile-k` and
  `ec-profile-m` options to the needs of the given environment. These latter
  options have default values of '1' and '2' respectively, which result in the
  same space requirements as those of a replicated pool.

See [Ceph Erasure Coding][cdg-ceph-erasure-coding] in the [OpenStack Charms
Deployment Guide][cdg] for more information.

## Ceph BlueStore compression

This charm supports [BlueStore inline compression][ceph-bluestore-compression]
for its associated Ceph storage pool(s). The feature is enabled by assigning a
compression mode via the `bluestore-compression-mode` configuration option. The
default behaviour is to disable compression.

The efficiency of compression depends heavily on what type of data is stored
in the pool and the charm provides a set of configuration options to fine tune
the compression behaviour.

> **Note**: BlueStore compression is supported starting with Ceph Mimic.

## Database

Nova compute only requires database access if using nova-network. If using
Neutron, no direct database access is required and the shared-db relation need
not be added.  The nova-network feature is not available in Ussuri and later,
and so this interface produces a warning if added.

## Networking

This charm support nova-network (legacy) and Neutron networking.

## Ceph backed storage

This charm supports a number of different storage backends depending on
your hypervisor type and storage relations.

### RBD Nova images

To make Ceph the storage backend for Nova non-bootable disk images
configuration option `libvirt-image-backend` must be set to 'rbd'. The below
relation is also required:

    juju add-relation nova-compute:ceph ceph-mon:client

### RBD Cinder volumes

Starting with OpenStack Ocata, in order to maintain Cinder RBD support the
below relation is required: 

    juju add-relation nova-compute:ceph-access cinder-ceph:ceph-access

This allows Nova to communicate with multiple Ceph backends using different
cephx keys and user names.

## Availability Zones

There are two options to provide default_availability_zone config
for nova nodes:

  - default-availability-zone
  - customize-failure-domain

The order of precedence is as follows:

  1. Information from a Juju provider (JUJU_AVAILABILITY_ZONE)
     if customize-failure-domain is set to True and Juju
     has set the JUJU_AVAILABILITY_ZONE to a non-empty value;
  2. The value of default-availability-zone will be used
     if customize-failure-domain is set to True but no
     JUJU_AVAILABILITY_ZONE is provided via hook
     context by the Juju provider;
  3. Otherwise, the value of default-availability-zone
     charm option will be used.

The default_availability_zone in Nova affects scheduling if a
given Nova node was not placed into an aggregate with an
availability zone present as a property by an operator. Using
customize-failure-domain is recommended as it provides AZ-aware
scheduling out of the box if an operator specifies an AZ during
instance creation.

These options also affect the AZ propagated down to networking
subordinates which is useful for AZ-aware Neutron agent scheduling.

## NFV support

This charm (in conjunction with the nova-cloud-controller and neutron-api charms)
supports use of nova-compute nodes configured for use in Telco NFV deployments;
specifically the following configuration options (yaml excerpt):

```yaml
nova-compute:
  hugepages: 60%
  vcpu-pin-set: "^0,^2"
  reserved-host-memory: 1024
  pci-passthrough-whitelist: {"vendor_id":"1137","product_id":"0071","address":"*:0a:00.*","physical_network":"physnet1"}
```

In this example, compute nodes will be configured with 60% of available RAM for
hugepage use (decreasing memory fragmentation in virtual machines, improving
performance), and Nova will be configured to reserve CPU cores 0 and 2 and
1024M of RAM for host usage and use the supplied PCI device whitelist as
PCI devices that as consumable by virtual machines, including any mapping to
underlying provider network names (used for SR-IOV VF/PF port scheduling with
Nova and Neutron's SR-IOV support).

The vcpu-pin-set configuration option is a comma-separated list of physical
CPU numbers that virtual CPUs can be allocated to by default. Each element
should be either a single CPU number, a range of CPU numbers, or a caret
followed by a CPU number to be excluded from a previous range. For example:

```yaml
vcpu-pin-set: "4-12,^8,15"
```

The pci-passthrough-whitelist configuration must be specified as follows:

A JSON dictionary which describe a whitelisted PCI device. It should take
the following format:

```
["device_id": "<id>",] ["product_id": "<id>",]
["address": "[[[[<domain>]:]<bus>]:][<slot>][.[<function>]]" |
"devname": "PCI Device Name",]
{"tag": "<tag_value>",}
```

  where '[' indicates zero or one occurrences, '{' indicates zero or multiple
  occurrences, and '|' mutually exclusive options. Note that any missing
  fields are automatically wildcarded. Valid examples are:

```yaml
pci-passthrough-whitelist: {"devname":"eth0", "physical_network":"physnet"}
```

```yaml
pci-passthrough-whitelist: {"address":"*:0a:00.*"}
```

```yaml
pci-passthrough-whitelist: {"address":":0a:00.", "physical_network":"physnet1"}
```

```yaml
pci-passthrough-whitelist: {"vendor_id":"1137", "product_id":"0071"}
```

```yaml
pci-passthrough-whitelist: {"vendor_id":"1137", "product_id":"0071", "address": "0000:0a:00.1", "physical_network":"physnet1"}
```

  The following is invalid, as it specifies mutually exclusive options:

```yaml
pci-passthrough-whitelist: {"devname":"eth0", "physical_network":"physnet", "address":"*:0a:00.*"}
```

A JSON list of JSON dictionaries corresponding to the above format. For
example:

```yaml
pci-passthrough-whitelist: [{"product_id":"0001", "vendor_id":"8086"}, {"product_id":"0002", "vendor_id":"8086"}]
```

The [OpenStack advanced networking documentation](http://docs.openstack.org/mitaka/networking-guide/adv-config-sriov.html)
provides further details on whitelist configuration and how to create instances
with Neutron ports wired to SR-IOV devices.

## Network spaces

This charm supports the use of Juju [network spaces][juju-docs-spaces] (Juju
`v.2.0`). This feature optionally allows specific types of the application's
network traffic to be bound to subnets that the underlying hardware is
connected to.

> **Note**: Spaces must be configured in the backing cloud prior to deployment.

In addition this charm declares two extra-bindings:

* `internal`: used to determine the network space to use for console access to
  instances.

* `migration`: used to determine which network space should be used for live
  and cold migrations between hypervisors.

Note that the nova-cloud-controller application must have bindings to the same
network spaces used for both 'internal' and 'migration' extra bindings.

## Actions

This section lists Juju [actions][juju-docs-actions] supported by the charm.
Actions allow specific operations to be performed on a per-unit basis. To
display action descriptions run `juju actions ceph-mon`. If the charm is not
deployed then see file `actions.yaml`.

* `openstack-upgrade`
* `pause`
* `resume`
* `hugepagereport`
* `security-checklist`

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-nova-compute].

For general charm questions refer to the OpenStack [Charm Guide][cg].

<!-- LINKS -->

[cg]: https://docs.openstack.org/charm-guide
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide
[juju-docs-actions]: https://jaas.ai/docs/actions
[juju-docs-spaces]: https://juju.is/docs/spaces
[juju-docs-config-apps]: https://juju.is/docs/configuring-applications
[lp-bugs-charm-nova-compute]: https://bugs.launchpad.net/charm-nova-compute/+filebug
[cdg-install-openstack]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/install-openstack.html
[cloud-archive-ceph]: https://wiki.ubuntu.com/OpenStack/CloudArchive#Ceph_and_the_UCA
[wiki-uca]: https://wiki.ubuntu.com/OpenStack/CloudArchive
[cdg-ceph-erasure-coding]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-erasure-coding.html
[ceph-bluestore-compression]: https://docs.ceph.com/en/latest/rados/configuration/bluestore-config-ref/#inline-compression
