FROM python:2.7.9-wheezy

RUN apt-get update -yy && apt-get install -q -y swig python-pip

ADD . /app
WORKDIR /app

RUN pip install -e /app && pip install -r requirements-dev.txt
