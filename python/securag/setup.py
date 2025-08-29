from setuptools import setup, find_packages
import os


def get_requirements(filename, exclude=None):
    exclude = exclude or []
    with open(filename) as f:
        return [
            line.strip()
            for line in f
            if line.strip()
            and not line.startswith("#")
            and not any(line.strip().startswith(pkg) for pkg in exclude)
        ]


setup(
    name="securag",
    version="0.0.1",
    description="SECURAG",
    long_description=open("README.md").read(
    ) if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Pavan Reddy",
    author_email="preddy.osdev@gmail.com",
    url="https://github.com/pavanreddyml/secuRAG",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=get_requirements(
        "requirements.txt"),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_data={"": ["*.md", "*.txt"]},
)