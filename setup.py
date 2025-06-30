from setuptools import setup, find_packages

setup(
    name="secelf",
    version="0.1.0",
    description="A multi-stage ELF binary analysis and vulnerability mapping tool",
    author="Fabiha Hashmat",
    license="MIT",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "pyelftools>=0.29",
        "requests>=2.25",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
)
