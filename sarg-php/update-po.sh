#!/bin/sh

# quick and non portable hack to update the po files from bash
xgettext -o translate.this *.php
for f in locale/*/LC_MESSAGES/messages.po
do
	echo "Updating $f"
   	msgmerge --update "$f" translate.this 
done
