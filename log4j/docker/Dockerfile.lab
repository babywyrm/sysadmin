FROM python:3-alpine

WORKDIR /app

COPY requirements.lab.txt requirements.lab.txt

RUN apk add gcc g++ make libffi-dev openssl-dev
RUN pip3 install -r requirements.lab.txt

COPY . .

ENTRYPOINT ["python", "log4j-scan.py" ]
