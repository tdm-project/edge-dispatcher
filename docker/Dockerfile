FROM alpine:latest

ENV APP_HOME=/opt/edge/

# Install required packages
RUN apk add --no-cache python3 && \
	pip3 install virtualenv

RUN \
	mkdir -p ${APP_HOME} && \
	cd ${APP_HOME} && \
	virtualenv venv && \
	. venv/bin/activate && \
	pip3 install paho-mqtt 

WORKDIR ${APP_HOME}
COPY src src

ENTRYPOINT ["src/entrypoint.sh"]

CMD [ "-c", "/opt/configs/tdm.conf" ]
