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

USAGE="$(basename $0) [-s crypto_dir] [-d packages.main.custom] [-r XC-REPOSITORY] [-c cert_file] [-k key_file] [-o out-file]"
CRYPTO=${CRYPTO:-"$(pwd)/crypto"}
PKGSMAIN_NEW=${PKGSMAIN_NEW:-"$(pwd)/packages.main.custom"}

while getopts hk:c:s:d:o:r: OPT; do
    case "$OPT" in
        h)
            echo ${USAGE}
            exit 0
            ;;
        s)
            CRYPTO=${OPTARG}
            ;;
        d)
            PKGSMAIN_NEW=${OPTARG}
            ;;
        r)
            REPO=${OPTARG}
            ;;
        o)
            OFILE=${OPTARG}
            ;;
        c)
            CERT=${OPTARG}
            ;;
        k)
            KEY=${OPTARG}
            ;;
        \?)
            echo ${USAGE} 1>&2
            exit 1
            ;;
    esac
done

CERT=${CERT:-"${CRYPTO}/cacert.pem"}
KEY=${KEY:-"${CRYPTO}/priv.key"}
REPO=${REPO:-"${PKGSMAIN_NEW}/XC-REPOSITORY"}
OFILE=${OFILE:-"${PKGSMAIN_NEW}/XC-SIGNATURE"}

if [ ! -f ${CERT} ]; then
    echo "no certificate file at ${CERT}" 1>&2
    exit 1
fi
if [ ! -f ${KEY} ]; then
    echo "no private key file at ${KEY}" 1>&2
    exit 1
fi
if [ ! -f ${REPO} ]; then
    echo "no repository file at ${REPO}" 1>&2
    exit 1
fi

openssl smime -sign \
              -aes256 \
              -binary \
              -in "${REPO}" \
              -out "${OFILE}" \
              -outform PEM \
              -signer "${CERT}" \
              -inkey "${KEY}"

if [ $? -ne 0 ]; then
    echo "Error signing ${REPOSITORY}" 1>&2
    exit 1
fi
