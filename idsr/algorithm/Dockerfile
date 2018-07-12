FROM ubuntu:latest

RUN mkdir -p /idsr/scripts
COPY scripts/wait-for-it.sh *.war /idsr/scripts

RUN apt-get update \ 
    && apt-get install -y curl netcat \
    && rm -rf /var/lib/apt/lists/*
# Install python3
RUN apt -y install python3 python3-pip
RUN pip3 install --upgrade pip

# Fundamentals
RUN pip3 install --upgrade numpy \
	pandas \
	requests \
	moment 