#!/bin/bash
uv run ptflow run external ~/Tests/ptflow-external-$(date +%Y%m%d-%H%M%S) ~/Tests/scope.txt -v --observe
