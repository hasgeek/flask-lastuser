"""
flask-lastuser
--------------

Flask extension for HasGeek's LastUser user management app

Links
`````

* `documentation <http://packages.python.org/flask-lastuser>`_
* `development version
  <http://github.com/hasgeek/flask-lastuser/zipball/master#egg=flask-lastuser-dev>`_

"""
from setuptools import setup


setup(
    name='Flask-Lastuser',
    version='0.3.2',
    url='https://github.com/hasgeek/flask-lastuser',
    license='BSD',
    author='Kiran Jonnalagadda',
    author_email='kiran@hasgeek.in',
    description='Flask extension for LastUser',
    long_description=__doc__,
    packages=['flask_lastuser'],
    zip_safe=False,
    platforms='any',
    install_requires=[
        'Flask',
        'httplib2',
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
