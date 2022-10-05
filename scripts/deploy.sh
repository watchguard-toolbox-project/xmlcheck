#!/bin/bash

FULLPATH=$(readlink -f $0)
DEVDIR=`dirname $FULLPATH`
DEVDIR=`dirname $DEVDIR`
PRODUCTIONDIR=`dirname $DEVDIR`/xmlcheck

DATE=`date +%Y-%m-%d`

if [ "$1" == "" ]
then
  cd $DEVDIR
  git fetch --all
  git reset --hard develop
  git pull
  #echo "`git describe --tags`" > templates/version.tpl
fi

if [ "$1" == "merge" ]
then
  $0
  cd $DEVDIR
  git checkout master
  git merge develop
  git push
  git checkout develop
fi

if [ "$1" == "master" ]
then
    cd $PRODUCTIONDIR
    git pull
    #echo "`git describe --tags`" > templates/version.tpl
fi

if [ "$1" == "all" ]
then
    $0
    $0 merge
    $0 master
fi
