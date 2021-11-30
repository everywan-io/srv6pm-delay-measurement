#!/usr/bin/env python

from setuptools import setup, find_packages
from os import path, makedirs
import subprocess
import sys


PYTHON_PATH = sys.executable

makedirs(path.dirname('./srv6_delay_measurement/commons/protos/srv6pm/gen_py/'), exist_ok=True)

# Generate python grpc stubs from proto files
print('Generation of python gRPC stubs')
args = "-I ./srv6_delay_measurement/commons/protos/srv6pm --proto_path=./srv6_delay_measurement/commons/protos/srv6pm --python_out=./srv6_delay_measurement/commons/protos/srv6pm/gen_py --grpc_python_out=./srv6_delay_measurement/commons/protos/srv6pm/gen_py/ ./srv6_delay_measurement/commons/protos/srv6pm/*.proto"
result = subprocess.call("%s -m grpc_tools.protoc %s" % (PYTHON_PATH, args), shell=True)
if result != 0:
    exit(-1)

open('./srv6_delay_measurement/commons/protos/srv6pm/gen_py/__init__.py', 'a').close()


here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'requirements.txt'), encoding='utf-8') as f:
    install_requires = f.read()

with open(path.join(here, 'VERSION'), encoding='utf-8') as f:
    version = f.read()

setup(name='srv6_delay_measurement',
      version=version,
      description='SRv6 Performance Measurement Framework',
      author='Carmine Scarpitta',
      author_email='carmine.scarpitta@uniroma2.it',
      url='https://github.com/cscarpitta/srv6pm-delay-measurement/',
      packages=find_packages('.'),
      entry_points={'console_scripts': [
         'controller = srv6_delay_measurement.controller_cli:__main']},
      include_package_data=True,
      install_requires=install_requires,
     )
