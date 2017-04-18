#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='crypto_utils',
      version='0.0.1',
      description='Python Crypto tools for confidential tx',
      author='boolafish',
      author_email='boolafish945@gmail.com',
      packages=['crypto_utils'],
      data_files=[("", ["LICENSE"])],
      install_requires=[
          'pyelliptic==1.5.7'
      ],
      )
