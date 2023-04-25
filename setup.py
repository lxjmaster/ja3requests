import os
import sys
from setuptools import setup
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    user_options = [("pytest-args=", "a", "Arguments to pass into py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        try:
            from multiprocessing import cpu_count

            self.pytest_args = ["-n", str(cpu_count()), "--boxed"]
        except (ImportError, NotImplementedError):
            self.pytest_args = ["-n", "1", "--boxed"]

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


with open("requirements.txt", "r", encoding="utf8") as f:
    requires = f.readlines()

with open("requirements-dev.txt", "r", encoding="utf8") as f:
    test_requirements = f.readlines()

about = {}
here = os.path.abspath(os.path.dirname(__file__))
version_file = os.path.join(here, "ja3requests", "__version__.py")
with open(version_file, "r", encoding="utf8") as f:
    exec(f.read(), about)

with open("README.md", "r", encoding="utf8") as f:
    readme = f.read()


setup(
    name=about["__title__"],
    version=about["__version__"],
    description=about["__description__"],
    long_description=readme,
    long_description_content_type="text/markdown",
    keywords=["pip", "ja3requests", "ja3", "requests"],
    license=about["__license__"],
    author=about["__author__"],
    author_email=about["__author_email__"],
    url=about["__url__"],
    packages=["ja3requests"],
    package_dir={"ja3requests": "ja3requests"},
    zip_safe=False,
    include_package_data=True,
    platforms="any",
    install_requires=requires,
    tests_require=test_requirements,
    cmdclass={"test": PyTest},
)
