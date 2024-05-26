#!/bin/bash

set -e

MYDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

GLAUTH=$(cd $MYDIR/../v2 && pwd)

#echo $GLAUTH

cd $GLAUTH && make darwinamd64 && cd $MYDIR

$GLAUTH/bin/darwinamd64/glauth -c ./dump.cfg