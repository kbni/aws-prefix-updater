#!/usr/bin/env bash

export SCRIPT_DIR="$( cd "$(dirname "$0")" && pwd )"
cd "$SCRIPT_DIR"

if [[ "$1" = "cron" ]]; then
    exec "$0" &> ip-updater.log
fi

#
# ip-updater.sh - script for updating security controls for web servers:
#  - AWS prefix list associated with a security group rule that updates
#  - htaccess which locks down access to /wp-admin
#
# Author: Alex Wilson <admin@kbni.net>
# Created: 2020-09-26
#

# Script configuration should populate these values

#set -e            # fail on error
htaccessDests=()   # list of htaccess files to overwrite
lookupHosts=()    # establish empty array for hosts to lookup
cidrs=()          # establish empty array for raw cidr entries
bail=0            # we'll bail if this equals 1
export LANG=C     # cpanel doesn't like fancy locales

# Modify our environment & include our env_vars
. "${SCRIPT_DIR}/env_vars" 2>/dev/null || bail=1

# Check we have the necessary tools

for check_bin in aws curl nslookup jq; do
    if ! which $check_bin &> /dev/null; then
        bail=1
        echo "[error] is '${check_bin}' installed? cannot find it."
    fi
done

# Check we have certain values

if [[ "$awsPrefixListId" = "" ]]; then
    bail=1
    echo "[error] it seems that \$awsPrefixListId is not set"
fi
if [[ "$htaccessDests" = "" ]]; then
    bail=1
    echo "[error] it seems that \$htaccessDests is not set"
fi
if [ $bail -eq 1 ]; then
    echo "[fatal] one or more checks failed, please fix and try again"
    exit 1
fi

# Resolve $lookupHosts and populate $cidrs

for hn in ${lookupHosts[@]}; do
    ip_addr=$(nslookup "$hn" | awk '/^Address: / { print $2 ; exit }')
    if [[ $ip_addr = "" ]]; then
        echo "[debug] Unable to resolve: ${hn} (ignored)"
        continue
    fi
    echo "[debug] Resolved ${hn} to ${ip_addr}"
    cidrs+=("${ip_addr}/32")
done

# Update the AWS prefix list

get_aws_prefix_version() {
    aws ec2 describe-managed-prefix-lists --prefix-list-ids $awsPrefixListId 2>/dev/null |\
        jq -r '.PrefixLists[] | .Version' 2>/dev/null
}

prefixlist_version=$(get_aws_prefix_version)
if [[ ! "$prefixlist_version" = "" ]]; then
    current_cidrs=(
        $(aws ec2 get-managed-prefix-list-entries --prefix-list-id $awsPrefixListId | jq -r '.Entries[] | .Cidr')
    )

    for existing_cidr in ${current_cidrs[@]}; do
        if [[ ! " ${cidrs[@]} " =~ " ${existing_cidr} " ]]; then
            echo "[warn] removing undefined cidr from prefix-list: ${existing_cidr}"
            aws ec2 modify-managed-prefix-list --prefix-list-id $awsPrefixListId \
                --current-version $prefixlist_version --remove-entries "Cidr=${existing_cidr}" \
                > /dev/null
            prefixlist_version=$(get_aws_prefix_version)
        fi
    done

    for desired_cidr in ${cidrs[@]}; do
        if [[ ! " ${current_cidrs[@]} " =~ " ${desired_cidr} " ]]; then
            echo "[info] will put cidr into prefix-list: ${desired_cidr}"
            aws ec2 modify-managed-prefix-list --prefix-list-id $awsPrefixListId \
                --current-version $prefixlist_version --add-entries "Cidr=${desired_cidr},Description=AUTOMATIC" \
                > /dev/null
            prefixlist_version=$(get_aws_prefix_version)
        fi
    done

else
    echo "[error] cannot find aws prefix version for '${awsPrefixListId}', check aws details" > /dev/stderr
    bail=1
fi

# GENERATE & SEND HTACCESS

echo "[debug] Building htaccess: ${SCRIPT_DIR}/last_htaccess"

# generate htaccess file
(
    echo "# This file is updated automatically, email awilson@answersit.com.au for more information"
    echo "Order deny,allow"
    echo "Deny from all"
    echo "Allow from 127.0.0.1"
    echo "Allow from 69.46.36.0/27" # wordfence
    echo "Allow from 69.46.36.31"   # wordfence
    echo "Allow from 69.46.36.32"   # wordfence
    for cidr in ${cidrs[@]}; do
        echo "Allow from $cidr";
    done
    echo "<Files admin-ajax.php>"
    echo "Order allow,deny"
    echo "Allow from all"
    echo "Satisfy any"
    echo "</Files>"
    echo "ErrorDocument 403 \"Access to this resource is restricted!\""
) > "${SCRIPT_DIR}/last_htaccess"

# copy our htaccess file to htaccessDest
for htaccessDest in ${htaccessDests[@]}; do
	if scp -qB "${SCRIPT_DIR}/last_htaccess" "$htaccessDest"; then
	    echo "[info] uploaded htaccess to ${htaccessDest}"
	else
	    echo "[error] unable to upload htaccess" > /dev/stderr
	    bail=1
	fi
done

exit $bail
