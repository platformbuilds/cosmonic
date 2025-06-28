#!/bin/bash

echo "🚀 Basic VNIC Setup Example"

sudo vnic-tool create basic-vnic eth0,eth1
sudo vnic-tool config basic-vnic 192.168.1.10/24
sudo vnic-tool enable basic-vnic

echo "✅ Basic VNIC created"
sudo vnic-tool show basic-vnic
