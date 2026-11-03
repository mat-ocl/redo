#!/bin/bash
set -e

# Ensure /home/ubuntu exists and is owned by the ubuntu user
chown -R ubuntu:ubuntu /home/ubuntu

# Populate dotfiles (including custom RE aliases in .bashrc) if missing
if [ ! -f /home/ubuntu/.bashrc ]; then
    cp -rn /etc/skel/. /home/ubuntu/ 2>/dev/null || cp -r /etc/skel/. /home/ubuntu/
    chown -R ubuntu:ubuntu /home/ubuntu
fi

# Step down from root and execute the command as user 'ubuntu' (UID 1000)
exec gosu ubuntu "$@"
