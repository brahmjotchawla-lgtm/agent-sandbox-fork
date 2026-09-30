#!/bin/sh
# Fetch the workload sources into ./context (not committed). Both the fork
# base image and the Docker baseline image are built from this one context,
# so the two sides of every comparison hold identical content
# (BENCHMARKS.md §3.1).
set -eu
cd "$(dirname "$0")"
DJANGO_TAG=5.1.4
rm -rf context && mkdir -p context/wheels
git clone --quiet --depth 1 --branch "$DJANGO_TAG" https://github.com/django/django context/repo
rm -rf context/repo/.git
# Pure-Python deps; pinned to the image's Python so no wheel is ABI-mismatched.
pip download --quiet --dest context/wheels --python-version 3.12 --only-binary=:all: \
    "asgiref>=3.8.1,<4" "sqlparse>=0.3.1" pytest==8.3.4
echo "fetched django $DJANGO_TAG: $(find context/repo -type f | wc -l) files, $(du -sh context | cut -f1)"
