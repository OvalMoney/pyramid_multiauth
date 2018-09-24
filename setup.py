import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst')) as f:
    README = f.read()

with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = ['pyramid']

setup(name='pyramid_selectauth',
      version='1.0.1',
      description='pyramid_selectauth',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
          "Programming Language :: Python",
          "Framework :: Pylons",
          "Topic :: Internet :: WWW/HTTP",
          "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
      ],
      author='Walter Danilo Galante',
      author_email='walter.galante@ovalmoney.com',
      url='https://github.com/OvalMoney/pyramid_selectauth',
      keywords='web pyramid pylons authentication',
      packages=find_packages(include=['pyramid_selectauth']),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="pyramid_selectauth",
      paster_plugins=['pyramid'])
