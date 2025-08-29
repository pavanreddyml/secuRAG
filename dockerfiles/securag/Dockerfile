FROM python:3.11-slim

WORKDIR /usr/src/app

COPY python python
RUN mkdir -p /usr/src/app/databases && chmod 777 /usr/src/app/databases

RUN mv python/securagserver securagserver && mv python/securag securag && rm -rf python

RUN pip install -r securagserver/requirements.txt
RUN pip install ./securag

EXPOSE 5000

CMD ["python", "securagserver/server/server.py"]