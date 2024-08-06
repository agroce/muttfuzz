#-*- coding:utf-8 -*-

from setuptools import setup


setup(
    name='muttfuzz',
    version='1.2.12',
    description='Fuzzing with mutants',
    long_description_content_type="text/markdown",
    long_description=open('README.md').read(),
    packages=['muttfuzz',],
    license='MIT',
    entry_points="""
    [console_scripts]
    muttfuzz = muttfuzz.fuzz:main
    apply_mutant = muttfuzz.apply_mutant:main
    libfuzzer_prune = muttfuzz.libfuzzer_prune:main
    analyze_results = muttfuzz.analyze_results:main
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
