# Web container for flask

FROM ubuntu:18.04
MAINTAINER Alex Tumwesigye "atumwesigye@gmail.com"
RUN apt update
RUN apt install -y build-essential libxml2-dev libxslt1-dev zlib1g-dev

RUN apt install -y python-pip python3 python3-dev python3-pip python-pyrex libpcre3 libpcre3-dev
RUN mkdir -p /app

WORKDIR /app
COPY ihisengine/web_app/app .
RUN pip install -r requirements.txt
#RUN pip3 install -r requirements.txt
EXPOSE 8900
# Finally, we run uWSGI with the ini file we
# created earlier
CMD [ "uwsgi", "--ini", "app.ini" ]
