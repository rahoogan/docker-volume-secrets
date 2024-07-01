#!/bin/bash

PLUGIN_SRC_PATH=""
if [[ -z "$1" ]]; then
    echo "You must specify the path to the plugin source code"
else
    PLUGIN_SRC_PATH=$1
fi

docker plugin disable rahoogan/dsv
docker plugin rm rahoogan/dsv
sudo rm -rf /tmp/dsv
cd $PLUGIN_SRC_PATH
docker build -t rootfsimage .
id=$(docker create rootfsimage true)
cd /tmp/
sudo mkdir -p dsv/rootfs
sudo docker export "$id" | sudo tar -x -C dsv/rootfs
docker rm -vf "$id"
docker rmi rootfsimage
sudo cp $PLUGIN_SRC_PATH/config.json /tmp/dsv/config.json
sudo docker plugin create rahoogan/dsv /tmp/dsv
docker plugin enable rahoogan/dsv
docker plugin ls
