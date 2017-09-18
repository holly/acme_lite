#!/usr/bin/env python
# vim:fileencoding=utf-8

try:
    import setuptools
    from setuptools import setup, find_packages
except ImportError:
    print("Please install setuptools.")

def find_scripts(scripts_path):
    base_path = os.path.abspath(scripts_path)
    return list(map(lambda path: os.path.join(scripts_path, path), 
           filter(lambda file_name: os.path.isfile(
             os.path.join(base_path, file_name)), os.listdir(base_path)
         )))

import os, sys

libdir = "lib"
#bindir = "bin"
requires_list = 'requirements.txt'

# package information.
setup(
  name         = "acme_lite",
  description  = "acme lite client by python",
  version      = "0.1.1",
  author       = "Akira Horimoto",
  author_email = "emperor.kurt@gmail.com",
  license      = "MIT License",
  url          = "https://github.com/holly/acme_lite",
  classifiers  = [
    "Development Status :: 5 - Production/Stable",
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "Topic :: Utilities"
  ],
  install_requires = open(requires_list).read().splitlines(),
  #scripts          = find_scripts(bindir),
  packages         = find_packages(libdir),
  package_dir      = { "": libdir },
)

