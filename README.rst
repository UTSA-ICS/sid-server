===========
sidserver
===========

SID-SERVER service for Openstack

This service will act as a SID Server for Security Based Resource Sharing<br>

First you will need to download the sidserver project:

a.) cd /opt/stack

b.) git clone https://github.com/UTSA-ICS/sidserver.git

c.) sudo mkdir /etc/sidserver/

To be able to use this service do the following:

1.) Copy sidserver/etc to /etc/sidserver:

    sudo cp /opt/stack/sidserver/etc/* /etc/sidserver/.

2.) Create a directory called /var/cache/sidserver and give it 777 permission:

    sudo mkdir /var/cache/sidserver
    
    sudo chmod 777 /var/cache/sidserver

3.) Create a user [sidserver] with password [admin] in the service tenant with 'admin' role:

    openstack user create --password admin --enable sidserver
    
    openstack role add --project service --user "sidserver" admin
    
4.) Create a service called 'sidserver' in Keystone:

    openstack service create --name "sidserver" --description "SID Server" --enable sidserver
    
5.) To start the SID-SERVER service run the following commands:

    cd /opt/stack; sudo pip install -e sidserver
    
    cd /opt/stack/sidserver; /opt/stack/sidserver/bin/sidserver-api --config-file=/etc/sidserver/g/sidserver-api.conf || touch "/opt/stack/status/stack/sidserver-api.failure"

6.) Verify sidserver service running in screen

To Test Usage:
==============


==================
OpenStack Keystone
==================

Keystone provides authentication, authorization and service discovery
mechanisms via HTTP primarily for use by projects in the OpenStack family. It
is most commonly deployed as an HTTP interface to existing identity systems,
such as LDAP.

Developer documentation, the source of which is in ``doc/source/``, is
published at:

    http://keystone.openstack.org/

The API specification and documentation are available at:

    http://specs.openstack.org/openstack/keystone-specs/

The canonical client library is available at:

    https://github.com/openstack/python-keystoneclient

Documentation for cloud administrators is available at:

    http://docs.openstack.org/

The source of documentation for cloud administrators is available at:

    https://github.com/openstack/openstack-manuals

Information about our team meeting is available at:

    https://wiki.openstack.org/wiki/Meetings/KeystoneMeeting

Bugs and feature requests are tracked on Launchpad at:

    https://bugs.launchpad.net/keystone

Future design work is tracked at:

    http://specs.openstack.org/openstack/keystone-specs/#identity-program-specifications

Contributors are encouraged to join IRC (``#openstack-keystone`` on freenode):

    https://wiki.openstack.org/wiki/IRC

For information on contributing to Keystone, see ``CONTRIBUTING.rst``.
