#!/bin/bash
# Setup script - replaces restored_external
# Auto-runs SSH, mount and bruteforce on boot

/usr/local/bin/restored_external.sshrd > /dev/console

/bin/mount.sh > /dev/console
/usr/bin/bruteforce > /dev/console
