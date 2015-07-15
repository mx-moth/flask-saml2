FROM python:2.7.9-wheezy

RUN apt-get update -yy && apt-get install -q -y swig python-pip
RUN pip install tox

WORKDIR /app
