#-*- coding:utf-8 -*-

from setuptools import setup, find_packages
import sys, os

setup(
    name='muttfuzz',
    version='1.1.11',
    description='Fuzzing with mutants',
    long_description_content_type="text/markdown",
    long_description=open('README.md').read(),
    packages=['muttfuzz',],
    license='MIT',
    entry_points="""
    [console_scripts]
    muttfuzz = muttfuzz.fuzz:main
    """,
    keywords='fuzzing mutation',
    classifiers=[
      "Intended Audience :: Developers",
      "Development Status :: 4 - Beta",
      "Programming Language :: Python :: 3",      
      ],
    install_requires=[
    ],
    url='https://github.com/agroce/muttfuzz',
)
