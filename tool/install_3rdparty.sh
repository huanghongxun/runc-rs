#!/usr/bin/env bash

distro=$(cat /etc/*release | grep "^ID=")

case $distro in
    "ubuntu")
        apt install libsystemd-dev libcap-dev
        ;;
    "fedora")
        dnf install libsystemd-devel libcap-devel
        ;;
    *)
        echo "Could not determine Linux distribution"
        ;;
esac
