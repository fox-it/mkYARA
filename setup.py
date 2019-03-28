import re
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()
    long_description = re.sub(r'\!\[\]\(.*?\)', '', long_description)


setup(
    name='mkYARA',
    version="1.0.0",
    author="Jelle Vergeer / Fox-IT",
    description="Generating YARA rules based on binary code",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="GPLv3",
    packages=find_packages(),
    keywords="YARA IDA",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    ],
    install_requires=[
        "capstone>=4.0.0",
        "yara-python"
    ],
    entry_points='''
        [console_scripts]
        mkyara=mkyara.utils.mkyara_tool:main
    ''',
)
