#!/bin/bash
source ../.venv/bin/activate
cd ../src/utils/
python3 nvd_fetch.py
python3 process_data.py