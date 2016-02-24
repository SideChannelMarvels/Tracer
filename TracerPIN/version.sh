#!/bin/bash

echo "GIT_DESC=$(git describe --tags --always)" > version.mk
