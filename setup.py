from setuptools import setup, find_packages

with open("README.md", "r") as file:
    long_description = file.read()

setup(
    name="fastjwtapi",
    version="0.0.5",
    description="An add-on for the FastAPI framework that makes it easier to work with JWT authorization.",
    package_dir={"": "app"},
    packages=find_packages(where="app"),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lengthylyova/fastjwtapi/",
    author="lengthylyova",
    author_email="lengthylyova@gmail.com",
    license="MIT",
    install_requires=[
        "PyJWT>=2.8.0",
        "fastapi>=0.111.1",
        "SQLAlchemy>=2.0.31"
    ],
    extras_require={
        "dev": ["twine>=5.1.1"],
    }
)
