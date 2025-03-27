import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

version = "0.1.0"

setup(
    name="violet_svg",
    version=version,
    description="Analyze an SVG for potential malicious or suspicious content",
    author="node5",
    packages=find_packages(),
    install_requires=[
        "bs4",
        "regex",
        "beautifulsoup4",
        "python-magic",
        "Pillow",
        "imagehash",
    ],
    entry_points={
        "console_scripts": [
            "violet_svg=violet_svg.cli:main",
        ],
    },
    python_requires=">=3.8",
    include_package_data=True,
    zip_safe=False,
)
