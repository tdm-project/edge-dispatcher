FROM multiarch/alpine:armhf-edge

LABEL maintainer="Massimo Gaggero <massimo dot gaggero at crs4 dot it>"

ENV APP_HOME=/opt/edge/

# Install required packages
RUN apk add --no-cache python3 ca-certificates && \
	ln -sf /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem && \
	pip3 install virtualenv


RUN \
	mkdir -p ${APP_HOME} && \
	cd ${APP_HOME} && \
	virtualenv venv && \
	. venv/bin/activate && \
	pip3 install paho-mqtt 

WORKDIR ${APP_HOME}

COPY src src
COPY tests tests

ENTRYPOINT ["src/entrypoint.sh"]

CMD [ "-c", "/opt/configs/tdm.conf" ]
