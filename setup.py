import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

required_url = []
required = []
with open("requirements.txt", "r") as freq:
    for line in freq.read().split():
        if "://" in line:
            required_url.append(line)
        else:
            required.append(line)

packages = setuptools.find_packages("src")

setuptools.setup(
    name="sharkreduce",
    version="0.2.0",
    author="Johannes Abel, Joseph Birkner, Tom Mirwald",
    description="Convenience functionality to annotate and reduce wireshark captures.",
    long_description=long_description,
    long_description_content_type="text/markdown",

    package_dir={'': 'src'},
    packages=packages,

    install_requires=required,
    dependency_links=required_url,
    python_requires='>=3.6',

    license="BSD-3 Clause",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: BSD License"
     ],
)
