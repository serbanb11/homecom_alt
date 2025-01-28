#!/bin/bash

PYTHON_VERSION=3.12

python$PYTHON_VERSION -m pipx install uv
uv venv venv --seed --python=$PYTHON_VERSION
source venv/bin/activate
pip install uv
uv pip install -r requirements-dev.txt
pre-commit install
