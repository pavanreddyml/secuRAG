FROM python:3.11-slim

WORKDIR /usr/src/app

COPY python python
RUN mkdir -p /usr/src/app/databases && chmod 777 /usr/src/app/databases

RUN mv python/appserver appserver && mv python/securag securag && rm -rf python

RUN pip install -r appserver/requirements.txt
RUN pip install ./securag

EXPOSE 8000

CMD ["sh", "-c", "python appserver/manage.py migrate --noinput && python appserver/manage.py runserver 0.0.0.0:8000"]
