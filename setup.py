"""
flask-lastuser
--------------

Flask extension for HasGeek's Lastuser user management app

Links
`````

* `documentation <http://packages.python.org/flask-lastuser>`_
* `development version
  <http://github.com/hasgeek/flask-lastuser/zipball/master#egg=flask-lastuser-dev>`_

"""
from setuptools import setup


setup(
    name='Flask-Lastuser',
    version='0.3.3',
    url='https://github.com/hasgeek/flask-lastuser',
    license='BSD',
    author='Kiran Jonnalagadda',
    author_email='kiran@hasgeek.in',
    description='Flask extension for Lastuser',
    long_description=__doc__,
    packages=['flask_lastuser'],
    zip_safe=False,
    platforms='any',
    dependency_links=[
        'https://github.com/hasgeek/coaster/zipball/master#egg=coaster',
    ],
    install_requires=[
        'Flask',
        'httplib2',
        'SQLAlchemy',
        'coaster',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
