FROM python:3.8

COPY ./requirements.txt /src/requirements.txt

RUN pip install -r /src/requirements.txt

COPY ./src ./srv/src

WORKDIR /srv/src/

CMD ["python", "monitor.py"]
