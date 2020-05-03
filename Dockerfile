FROM python:3.7-alpine

# env vars
ENV PROXY_PROTOCOL=socks5

# add files and user
RUN adduser -D -h /soxyproxy soxyproxy
WORKDIR /soxyproxy

# setup requirements
ADD requirements.txt requirements.txt
RUN pip install --disable-pip-version-check --requirement requirements.txt

# execute from user
USER soxyproxy
ADD ./soxyproxy soxyproxy/

ENTRYPOINT ["python", "-m", "soxyproxy"]
