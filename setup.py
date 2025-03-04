#!/usr/bin/env python3
"""
Setup script for the Link Extractor package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="link-extractor",
    version="1.0.0",
    author="Moineau54",
    author_email="Moineau54@protonmail.com",
    description="A tool for extracting possible tracking domains from websites",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/link-extractor",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "link-extractor=link_extractor:main",
        ],
    },
    package_data={
        "link_extractor": ["*.txt"],
    },
    include_package_data=True,
)