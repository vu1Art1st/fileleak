#!/usr/bin/env python3
"""FileLeak - Comprehensive file leak exploitation tool.

Usage: python fileleak.py -u <URL> [options]
"""
import sys
import os

# Ensure the package directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fileleak.cli import main

if __name__ == '__main__':
    main()
