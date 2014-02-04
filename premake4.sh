#!/bin/sh
./premake4nix --os=linux gmake || die "Premake failed creating project for Linux (GMake)"