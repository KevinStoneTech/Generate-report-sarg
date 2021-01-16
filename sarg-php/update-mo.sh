#!/bin/sh

# quick and non portable hack to update the mo files from bash
for f in locale/*/LC_MESSAGES/messages.po
do
	echo "Updating $f"
   	msgfmt --check --statistics -o "${f%.po}.mo" "$f" 
done
