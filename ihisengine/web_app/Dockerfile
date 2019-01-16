# Web container for flask
MAINTAINER Alex Tumwesigye "atumwesigye@gmail.com"
FROM ubuntu:18.04
RUN apt update -y
RUN apt install python3 python3-dev python3-pip
RUN mkdir /app
COPY ./app /app
WORKDIR /app
RUN pip3 install -r requirements.txt
EXPOSE 8900
# Finally, we run uWSGI with the ini file we
# created earlier
CMD [ "uwsgi", "--ini", "app.ini" ]
