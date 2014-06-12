#!/bin/sh
#
# Copyright (c) 2014 Citrix Systems, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

# Generate XC-REPOSITORY from XC-REPOSITORY found in directory specified through -r
# with hash of PACKAGES file specified by the -p option.
#

USAGE="$(basename $0) [-s packages.main] [-r packages.main.custom] [-o out-file]"
PKGSMAIN=${PKGSMAIN:-"$(pwd)/packages.main"}
PKGSMAIN_NEW=${PKGSMAIN_NEW:-"$(pwd)/packages.main.custom"}
OFILE=${OFILE:-"${PKGSMAIN}/XC-REPOSITORY"}

while getopts hs:d:o: OPT; do
    case "$OPT" in
        h)
            echo ${USAGE}
            exit 0
            ;;
        s)
            PKGSMAIN=${OPTARG}
            ;;
        d)
            PKGSMAIN_NEW=${OPTARG}
            ;;
        o)
            OFILE=${OPTARG}
            ;;
        \?)
            echo ${USAGE} 1>&2
            exit 1
            ;;
    esac
done

PKGS=${PKGSMAIN_NEW}/XC-PACKAGES
REPO=${PKGSMAIN}/XC-REPOSITORY
OFILE=${PKGSMAIN_NEW}/XC-REPOSITORY

if [ ! -f $PKGS ]; then
    echo "No XC-PACKAGES file found in: ${PKGSMAIN_NEW}" 1>&2
    exit 1
fi

if [ ! -f $REPO ]; then
    echo "No XC-REPOSITORY file found in: ${PKGSMAIN}" 1>&2
    exit 1
fi

ID=${ID:-"$(head -n 10 $REPO | grep '^build' | sed -e 's&^build:\([0-9]\+\)$&\1&')"}
VERSION=${VERSION:-"$(head -n 10 $REPO | grep '^version' | sed -e 's&^version:\(.*\)$&\1&')"}
RELEASE=${RELEASE:-"$(head -n 10 $REPO | grep '^release' | sed -e 's&^release:\(.*\)$&\1&')"}
UPGRADEABLE_RELEASES=${UPGRADEABLE_RELEASES:-"$(head -n 10 $REPO | grep '^upgrade-from' | sed -e 's&^upgrade-from:\(.*\)$&\1&')"}
PACKAGES_SHA256SUM=$(sha256sum "$PKGS" | awk '{ print $1 }')

# Pad XC-REPOSITORY to 1 MB with blank lines. If this is changed, the
# repository signing process will also need to change.
{
    cat <<EOF
xc:main
pack:Base Pack
product:XenClient
build:${ID}
version:${VERSION}
release:${RELEASE}
upgrade-from:${UPGRADEABLE_RELEASES}
packages:${PACKAGES_SHA256SUM}
EOF
    yes ""
} | head -c 1048576 > ${OFILE}
