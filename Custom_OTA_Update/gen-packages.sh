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

# option is the path to a packages.main directory
# absent this explicit option we assume pwd
#
# output is a properly formatted XC-PACKAGES manifest

USAGE="$(basename $0) [-s packages.main] [-d packages.main.custom] [-o out-file]"
PKGSMAIN=${PKGSMAIN:-"$(pwd)/packages.main"}
PKGSMAIN_NEW=${PKGSMAIN_NEW:-"$(pwd)/packages.main.custom"}
OFILE=${OFILE:-"${PKGSMAIN_NEW}/XC-PACKAGES"}

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

if [ ! -f ${PKGSMAIN}/XC-PACKAGES ]; then
    echo "No XC-PACKAGES file found in: ${PKGSMAIN}. Your repository is incomplete." 1>&2
    exit 1
fi
if [ -f ${PKGSMAIN_NEW}/XC-PACKAGES ]; then
    echo "Your new repository already has a XC-PACKAGES file. You must remove it before running this script." 1>&2
    exit 1
fi

# main processing loop
# read entries from existing XC-PACKAGES
#   recalculate filesize and sha256sum
while read line; do
    local shortname=$(echo $line | awk '{ print $1 }')
    local format=$(echo $line | awk '{ print $4 }')
    local required=$(echo $line | awk '{ print $5 }')
    local filename=$(echo $line | awk '{ print $6 }')
    local unpackdir=$(echo $line | awk '{ print $7 }')

    if [ ! -f ${PKGSMAIN}/$filename ]; then
        echo "no file found at ${PKGSMAIN}/$filename, aborting" 1>&2
        exit 1
    fi
    if [ ! -f ${PKGSMAIN_NEW}/$filename ]; then
        echo "copying $filename from source archive" 1>&2
        cp ${PKGSMAIN}/$filename ${PKGSMAIN_NEW}/$filename
    fi

    local filesize=$(du -b ${PKGSMAIN_NEW}/$filename | awk '{ print $1 }')
    local sha256sum=$(sha256sum ${PKGSMAIN_NEW}/$filename | awk '{ print $1 }')

    echo "$shortname" "$filesize" "$sha256sum" "$format" "$required" \
         "$filename" "$unpackdir" >> ${OFILE}
done < ${PKGSMAIN}/XC-PACKAGES
exit 0
