from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="network-traffic-inspector",
    version="1.8.3",
    author="Applied Science Research Institute",
    author_email="research@appresearch.org",
    description="Advanced network traffic analysis tool for examining application communication patterns",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/appresearch/network-traffic-inspector",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.4.5",
        "dpkt>=1.9.8",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.12.0",
            "black>=21.0",
            "flake8>=3.9",
        ],
    },
    entry_points={
        "console_scripts": [
            "network-traffic-inspector=network_traffic_inspector.cli:main",
        ],
    },
)


