#!/bin/sh

set -e

cd $(dirname "${BASH_SOURCE[0]}")
export CommandsJSON=$(cat commands.json)

# replace out the json
perl -pe '
    while (($i = index($_, "{{.CommandsJSON}}")) != -1) {
      substr($_, $i, length("{{.CommandsJSON}}")) = $ENV{"CommandsJSON"};
    }
' commands.go > commands_gen.go

# remove the ignore
sed -i -e 's/\/\/ +build ignore/\/\/ This file was autogenerated. DO NOT EDIT./g' commands_gen.go
rm -rf commands_gen.go-e
