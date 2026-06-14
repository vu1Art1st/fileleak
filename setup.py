import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))


def read_version():
    version_ns = {}
    with open(os.path.join(here, "fileleak", "__version__.py")) as f:
        exec(f.read(), version_ns)
    return version_ns["__version__"]


def read_requirements():
    with open(os.path.join(here, "requirements.txt")) as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


setup(
    name="fileleak",
    version=read_version(),
    description="A tool for exploiting file leak vulnerabilities (Git, SVN, DS_Store, etc.)",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "fileleak=fileleak.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "fileleak": ["data/*.txt"],
    },
)
