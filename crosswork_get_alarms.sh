#!/bin/bash

#
# Copyright 2019 Cisco Systems Inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOGFILENAME=/tmp/log.$(basename $0).$$
LOGFILENAME=$LOGFILENAME

# Check the crosswork.py script is local
CROSSWORK_PYTHON_SCRIPT="./crosswork.py"
if [ ! -e $CROSSWORK_PYTHON_SCRIPT ] 
  then
  echo """$CROSSWORK_PYTHON_SCRIPT""" file not located
  exit 1
fi

# Check the keys.env script is local
#CROSSWORK_KEYS=./keys.env
#if [ ! -e $CROSSWORK_KEYS ] 
#  then
#  echo keys.env file not located
#  exit 1
#fi

# Get the encyption keys from a file that with the variables
# expected file "./keys.env" to contain the following
# crosswork_host='<insert>'
# crosswork_key='<insert>'
# crosswork_keyid='<insert>'
# uri_alarms='<insert>'
# uri_alarms_details='<insert>'
# export $(grep -v '^#' ./keys.env | xargs -d '\n')

crosswork_host='crosswork.cisco.com'
crosswork_key=''
crosswork_keyid=''
uri_alarms='/api/beta/alarms?state=1'
uri_alarms_details='/api/beta/alarms/'
output_folder="."
args1="--uri=$uri_alarms --key=$crosswork_key --keyid=$crosswork_keyid --method=GET --host=$crosswork_host"
# echo "$args1"

my_date=$(date +"%Y.%m.%d.at.%H.%M")
my_file_name=crosswork.network.insights.alarms
my_alarms_file=$my_file_name.$my_date

echo "RUNNING : $PWD/crosswork.py $args1 > $output_folder/$my_alarms_file"
$CROSSWORK_PYTHON_SCRIPT $args1 > $output_folder/$my_alarms_file

# python3 $CROSSWORK_PYTHON_SCRIPT '"' $cmd1 '"'
# python3 $CROSSWORK_PYTHON_SCRIPT --uri='/api/beta/alarms?state=1' --key='a880b9f458b2b88aea6783e48e11bd41c56b1471efcd80d721792620c7a694cd' --keyid='3c7e82d89372286ed0cb5b63b9554a77' --method=GET --host='crosswork.cisco.com'

# run="$CROSSWORK_PYTHON_SCRIPT --uri $uri_alarms_details --key $crosswork_key --keyid $crosswork_keyid --method GET --host $crosswork_host"
# echo $run
# $run