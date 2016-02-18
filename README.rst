===========
sidserver
===========

SIDSERVER service for AWS & Azure

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
    
    cd /opt/stack/sidserver/bin; ./start_sidserver_screen.sh

6.) Verify sidserver service running in screen

To Test Usage:
==============

