#!/bin/bash

gcc loader.c proc_maps.c proc_maps.h -Wall -shared -o loader.so
python3 fix_placeholder.py
gcc  main.c -ldl -o main
