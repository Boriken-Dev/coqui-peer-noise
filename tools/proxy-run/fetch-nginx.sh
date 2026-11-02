#!/bin/bash
# Unpacks a distribution's nginx into a directory and prints its path: nothing is installed, and removing
# the directory removes it. Fedora and its relatives; elsewhere, install nginx and name its binary.
# Argument: the directory.
set -eu
target=$1
mkdir -p "$target"
cd "$target"
dnf --quiet download --destdir "$target" nginx nginx-core gperftools-libs libunwind >/dev/null
for package in ./*.rpm; do
    rpm2cpio "$package" | cpio -idm --quiet
done
rm -f ./*.rpm
printf '%s/usr/bin/nginx\n' "$target"
