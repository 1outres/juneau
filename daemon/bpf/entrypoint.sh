#!/bin/bash

cp /vmlinux.h /app/daemon/bpf/vmlinux.h
cd /app/daemon
go generate ./internal/daemon/bpf
