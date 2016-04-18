FROM python:2.7.11-slim

RUN apt-get update -yy && apt-get install -q -y swig python-pip libssl-dev

ADD . /app
WORKDIR /app

RUN pip install -e /app && pip install -r requirements-dev.txt
