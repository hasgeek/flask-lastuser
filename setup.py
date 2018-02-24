import os
import re
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
CHANGES = open(os.path.join(here, 'CHANGES.rst')).read()
versionfile = open(os.path.join(here, "flask_lastuser", "_version.py")).read()

mo = re.search(r"^__version__\s*=\s*['\"]([^'\"]*)['\"]", versionfile, re.M)
if mo:
    version = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in flask_lastuser/_version.py.")

requires = [
    'coaster',
    'SQLAlchemy>=1.0',
    'Flask-BabelEx',
    'Flask',
    'requests',
    'six',
    ]

setup(
    name='Flask-Lastuser',
    version=version,
    url='https://github.com/hasgeek/flask-lastuser',
    license='BSD',
    author='Kiran Jonnalagadda',
    author_email='kiran@hasgeek.com',
    description='Flask extension for Lastuser',
    long_description=README + '\n\n' + CHANGES,
    packages=find_packages(),
    include_package_data=True,
    zip_safe=True,
    platforms='any',
    install_requires=requires,
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
        ],
    dependency_links=[
        "https://github.com/hasgeek/coaster/archive/master.zip#egg=coaster-dev",
        ],
    )
