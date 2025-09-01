"""Setup module for homecom_alt."""

from pathlib import Path

from setuptools import setup

PROJECT_DIR = Path(__file__).parent.resolve()
README_FILE = PROJECT_DIR / "README.md"
VERSION = "1.3.9"

setup(
    name="homecom_alt",
    version=VERSION,
    author="serbanb11",
    description=("Python wrapper for controlling devices managed by HomeCom Easy APP."),
    long_description=README_FILE.read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    include_package_data=True,
    url="https://github.com/serbanb11/homecom-alt",
    license="MIT",
    packages=["homecom_alt"],
    package_data={"homecom_alt": ["py.typed"]},
    python_requires=">=3.12",
    install_requires=["aiohttp>=3.9.4", "tenacity", "PyJWT>=2.1.0"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3 :: Only",
        "Typing :: Typed",
    ],
)
