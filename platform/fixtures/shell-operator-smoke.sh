#!/bin/sh
# Run with sh /path/to/shell-operator-smoke.sh NEW_WRITABLE_DIRECTORY.
# Parent operator exercise owns the directory and retires it after inspection.
if test "$#" -ne 1; then
    echo 'usage: sh shell-operator-smoke.sh NEW_WRITABLE_DIRECTORY'
    exit 2
fi
if mkdir "$1"; then
    cd "$1"
else
    exit 1
fi
export OPERATOR_CHECK='ordinary operator'
printenv OPERATOR_CHECK > environment.txt
echo 'mode=initial' > operator.conf
printf 'H\n1s/initial/revised/\nu\n1s/initial/revised/\nw\nq\n' > edits
ed -s operator.conf < edits
if test "$?" -ne 0; then exit 1; fi
for item in one 'two words'; do echo "$item" >> items.txt; done
summary=$(cat operator.conf)
if test "$summary" = 'mode=revised'; then
    echo 'SHELL EDIT OK'
else
    exit 1
fi
case "$OPERATOR_CHECK" in
    ordinary*) echo 'SHELL ENV OK';;
    *) exit 1;;
esac
set -- *.txt
if test "$#" -ne 2; then exit 1; fi
echo 'SHELL GLOB OK'
lines=$(cat items.txt | wc -l)
if test "$lines" -ne 2; then exit 1; fi
echo 'SHELL PIPE CAPTURE OK'
echo 'SHELL OPERATOR OK'
