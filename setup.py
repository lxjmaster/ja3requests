import os
from setuptools import setup


with open("requirements.txt", "r", encoding="utf8") as f:
    requires = f.readlines()

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
    packages=[
        "ja3requests",
        "ja3requests/base",
        "ja3requests/contexts",
        "ja3requests/protocol",
        "ja3requests/protocol/h2",
        "ja3requests/protocol/tls",
        "ja3requests/protocol/tls/cipher_suites",
        "ja3requests/protocol/tls/extensions",
        "ja3requests/protocol/tls/layers",
        "ja3requests/requests",
        "ja3requests/sockets",
    ],
    package_dir={"ja3requests": "ja3requests"},
    zip_safe=False,
    include_package_data=True,
    package_data={"ja3requests": ["py.typed"]},
    platforms="any",
    python_requires=">=3.7",
    install_requires=requires,
)
