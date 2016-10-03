#!/bin/bash
# buildrpm.sh builds an RPM for Ing.
# You must have fpm (https://github.com/jordansissel/fpm) installed.
#
# NOTE: This script builds an RPM targeted for Centos/RHEL.  It will not
# cross-compile from OS X to RHEL (although you can build the RPM for
# testing purposes.)  If you want to build a valid RPM with a binary
# that will run on Centos/RHEL, then check out the ing-rpm-vm repo
# (https://gitlab.com/threattrace/ing-rpm-vm.git)

if [ ! -f "./ing" ]; then
    echo "Building Ing"
    ./build.sh
fi

echo "Building an RPM for Ing"
fpm -s dir \
    -t rpm \
    --name ing \
    --version 0.1.0 \
    --iteration 1 \
    --epoch 0 \
    --vendor "Threat Trace" \
    --rpm-os linux \
    --depends 'libpcap' \
    --config-files /etc/threat-trace/ing.conf \
    ./ing=/usr/local/bin/ \
    ./etc/banner-terms.json=/etc/threat-trace/ \
    ./etc/ing.conf=/etc/threat-trace/ \
    ./etc/ing-sync-files=/etc/threat-trace/ \
    ./etc/system.d/ing.service=/lib/systemd/system/ \
    ./etc/cron.d/ing-sync=/etc/cron.d/
