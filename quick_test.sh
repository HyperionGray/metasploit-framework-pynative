#!/bin/bash

echo "Quick functionality test for MSF PyNative tools"
echo "=============================================="
echo

echo "Testing msfconsole.py help:"
python3 msfconsole.py -h
echo

echo "Testing msfconsole.py version:"
python3 msfconsole.py -v
echo

echo "Testing msfconsole.py execute command:"
python3 msfconsole.py -q -x "version; exit"
echo

echo "Testing msfvenom help:"
python3 msfvenom -h
echo

echo "Testing msfvenom list payloads:"
python3 msfvenom -l payloads | head -20
echo

echo "Quick test completed!"