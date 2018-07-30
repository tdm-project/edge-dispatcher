#!/usr/bin/env python
#
#  Copyright 2018, CRS4 - Center for Advanced Studies, Research and Development in Sardinia
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import re
import sys
import json
import signal
import logging
import argparse
import configparser
import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish


MQTT_LOCAL_HOST = "localhost"  # Local MQTT Broker address
MQTT_LOCAL_PORT = 1883         # Local MQTT Broker port

MQTT_REMOTE_HOST = ""          # Remote MQTT Broker address
MQTT_REMOTE_PORT = 8883        # Remote MQTT Broker port

# AUTH/TLS Defaults
MQTT_REMOTE_TLS  = True        # Remote MQTT Broker use TLS
MQTT_REMOTE_CA_FILE = "/etc/ssl/cert.pem"   # Remote MQTT Broker CA Certificate
MQTT_REMOTE_USER = ""          # Remote MQTT Username
MQTT_REMOTE_PASS = ""          # Remote MQTT Password
MQTT_REMOTE_SECRET = ""        # Remote MQTT Password in Docker Secret File

# Unused, reserved for future use
MQTT_REMOTE_CERT_FILE = ""
MQTT_REMOTE_KEY_FILE  = ""


APPLICATION_NAME = 'EDGE_dispatcher'


TOPIC_MAP = {
        'WeatherObserved': '37371A66CAD33',
        'EnergyMonitor':   '13298B927F927',
        'DeviceStatus':    '61F76456255F2',
        }


TOPIC_LIST = TOPIC_MAP.keys()


def edge_serial():
    _serial = None
    with open('/proc/cpuinfo', 'r') as _fp:
        for _line in _fp:
            _match = re.search('Serial\s+:\s+0+(?P<serial>\w+)$', _line)
            if _match:
                _serial = _match.group('serial').upper()
                break

    return _serial


class MQTTConnection(object):
    def __init__(self, host='localhost', port=1883, keepalive=60, logger=None, userdata=None):
        self._host = host
        self._port = port
        self._keepalive = keepalive
        self._userdata = userdata

        self._logger = logger
        if self._logger == None:
            self._logger = logger.getLoger()

        self._client = mqtt.Client(userdata=self._userdata)

        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect

    def connect(self):
        self._logger.debug("Connecting to MQTT broker '{:s}:{:d}'".format(
            self._host, self._port))
        try:
            self._client.connect(self._host, self._port, self._keepalive)
            self._client.loop_forever()
        except Exception as ex:
            self._logger.fatal("Connection to MQTT broker '{:s}:{:d}' failed. "
                "Error was: {:s}.".format(self._host, self._port, str(ex)))
            self._logger.info("Exiting.")
            sys.exit(-1)

    def signal_handler(self, signal, frame):
        self._logger.info("Got signal '{:d}': exiting.".format(signal))
        self._client.disconnect()

    def _on_connect(self, client, userdata, flags, rc):
        self._logger.info("Connected to MQTT broker '{:s}:{:d}' with result code {:d}".format(self._host, self._port, rc))
        for _topic in TOPIC_LIST:
            _topic += '/#'

            self._logger.debug("Subscribing to {:s}".format(_topic))

            (result, mid) = client.subscribe(_topic)
            if result == mqtt.MQTT_ERR_SUCCESS:
                self._logger.info("Subscribed to {:s}".format(_topic))

    def _on_disconnect(self, client, userdata, rc):
        self._logger.info("Disconnected with result code {:d}".format(rc))

    def _on_message(self, client, userdata, msg):
        _message = msg.payload.decode()
        self._logger.debug("Received message -  topic:\'{:s}\', message:\'{:s}\'".format(
            msg.topic, _message))

        _api_key, _, _station_id = msg.topic.partition('/')
        _topic = "/{:s}/{:s}.{:s}/attrs".format(
                TOPIC_MAP[_api_key], userdata['EDGE_ID'], _station_id)

        _tls = None
        if userdata['MQTT_REMOTE_TLS'] == True:
            _tls = {
                    'ca_certs': userdata['MQTT_REMOTE_CAFILE'],
                    # Unused, reserved
                    # 'certfile': userdata['MQTT_REMOTE_CERT_FILE'],
                    # 'keyfile':  userdata['MQTT_REMOTE_KEY_FILE']
                    }
        _auth = None
        if userdata['MQTT_REMOTE_USER'] not in [""]:
            _auth = {
                    'username': userdata['MQTT_REMOTE_USER'],
                    'password': userdata['MQTT_REMOTE_PASS'],
                    }

        self._logger.debug("Sent message -  topic:\'{:s}\', message:\'{:s}\'".format(
            _topic, _message))
        publish.single(_topic, _message,
                hostname=userdata['MQTT_REMOTE_HOST'],
                port=userdata['MQTT_REMOTE_PORT'],
                auth=_auth, tls=_tls)

def main():
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
    logger = logging.getLogger(APPLICATION_NAME)

    # Checks the Python Interpeter version
    if (sys.version_info < (3, 0)):
        ###TODO: Print error message here
        sys.exit(-1)

    pre_parser = argparse.ArgumentParser(add_help=False)

    pre_parser.add_argument('-c', '--config-file', dest='config_file', action='store',
        type=str, metavar='FILE',
        help='specify the config file')

    args, remaining_args = pre_parser.parse_known_args()

    v_general_config_defaults = {
        'mqtt_host'     : MQTT_LOCAL_HOST,
        'mqtt_port'     : MQTT_LOCAL_PORT,
        'logging_level' : logging.INFO,
        }

    v_specific_config_defaults = {
        'mqtt_local_host' : MQTT_LOCAL_HOST,
        'mqtt_local_port' : MQTT_LOCAL_PORT,

        'mqtt_remote_host' : MQTT_REMOTE_HOST,
        'mqtt_remote_port' : MQTT_REMOTE_PORT,

        # AUTH/TLS Section
        'mqtt_remote_tls'      : MQTT_REMOTE_TLS,
        'mqtt_remote_cafile'   : MQTT_REMOTE_CA_FILE,
        'mqtt_remote_certfile' : MQTT_REMOTE_CERT_FILE,
        'mqtt_remote_keyfile'  : MQTT_REMOTE_KEY_FILE,
        'mqtt_remote_user'     : MQTT_REMOTE_USER,
        'mqtt_remote_pass'     : MQTT_REMOTE_PASS,
        'mqtt_remote_secret'   : MQTT_REMOTE_SECRET,
        }

    v_config_section_defaults = {
        'GENERAL': v_general_config_defaults,
        APPLICATION_NAME: v_specific_config_defaults
        }

    # Default config values initialization
    v_config_defaults = {}
    v_config_defaults.update(v_general_config_defaults)
    v_config_defaults.update(v_specific_config_defaults)

    v_serial = edge_serial()
    if v_serial:
        _edge_serial = "Edge-{}".format(v_serial)
        v_config_defaults.update({'edge_id': _edge_serial})
        v_config_defaults.update({'mqtt_remote_user': _edge_serial.lower()})

    if args.config_file:
        _config = configparser.ConfigParser()
        _config.read_dict(v_config_section_defaults)
        _config.read(args.config_file)

        # Filter out GENERAL options not listed in v_general_config_defaults
        _general_defaults = {_key: _config.get('GENERAL', _key) for _key in
                _config.options('GENERAL') if _key in
                v_general_config_defaults}

        # Updates the defaults dictionary with general and application specific
        # options
        v_config_defaults.update(_general_defaults)
        v_config_defaults.update(_config.items(APPLICATION_NAME))

    parser = argparse.ArgumentParser(parents=[pre_parser],
            description='Collects data from other sensors and publish them to a remote MQTT broker.',
            formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.set_defaults(**v_config_defaults)

    parser.add_argument('-l', '--logging-level', dest='logging_level', action='store',
        type=int,
        help='threshold level for log messages (default: {})'.format(logging.INFO))
    parser.add_argument('--local-broker', dest='mqtt_local_host', action='store',
        type=str,
        help='hostname or address of the local broker (default: {})'
            .format(MQTT_LOCAL_HOST))
    parser.add_argument('--local-port', dest='mqtt_local_port', action='store',
        type=int,
        help='port of the local broker (default: {})'.format(MQTT_LOCAL_PORT))

    parser.add_argument('--remote-broker', dest='mqtt_remote_host', action='store',
        type=str,
        help='hostname or address of the remote broker (default: {})'
            .format(MQTT_REMOTE_HOST))
    parser.add_argument('--remote-port', dest='mqtt_remote_port', action='store',
        type=int,
        help='port of the remote broker (default: {})'.format(MQTT_REMOTE_PORT))
    parser.add_argument('--remote-tls', dest='mqtt_remote_tls', action='store',
        type=bool,
        help='the remote broker uses TLS (default: {})'.format(MQTT_REMOTE_TLS))
    parser.add_argument('--remote-cafile', dest='mqtt_remote_cafile', action='store',
        type=str,
        help='path of the ca file for the remote broker')
    parser.add_argument('--remote-certfile', dest='mqtt_remote_certfile', action='store',
        type=str,
        help='path of the cert file for the remote broker')
    parser.add_argument('--remote-keyfile', dest='mqtt_remote_keyfile', action='store',
        type=str,
        help='path of the key file for the remote broker')
    parser.add_argument('--remote-user', dest='mqtt_remote_user', action='store',
        type=str,
        help='username for the remote broker')
    parser.add_argument('--remote-pass', dest='mqtt_remote_pass', action='store',
        type=str,
        help='password for the remote broker')
    parser.add_argument('--remote-secret', dest='mqtt_remote_secret', action='store',
        type=str,
        help='password for the remote broker in Docker Secret')


    parser.add_argument('--edge-id', dest='edge_id', action='store',
        type=str, help='id of the edge gateway (mandatory)')

    args = parser.parse_args()

    logger.setLevel(args.logging_level)
    logger.info("Starting {:s}".format(APPLICATION_NAME))
    logger.debug(vars(args))

    if not args.edge_id:
        logger.fatal("No EDGE ID specified. Specify in command line with '--edge-id' or in config file option 'edge_id'")
        sys.exit(-1)

    _userdata = {
        'EDGE_ID': args.edge_id,
        'MQTT_REMOTE_HOST': args.mqtt_remote_host,
        'MQTT_REMOTE_PORT': args.mqtt_remote_port,
        'MQTT_REMOTE_TLS':    args.mqtt_remote_tls,
        'MQTT_REMOTE_CAFILE': args.mqtt_remote_cafile,
        'MQTT_REMOTE_USER':   args.mqtt_remote_user,
        'MQTT_REMOTE_PASS':   args.mqtt_remote_pass,
        'MQTT_REMOTE_SECRET': args.mqtt_remote_secret,
    }

    connection = MQTTConnection(args.mqtt_local_host, args.mqtt_local_port, logger=logger, userdata=_userdata)
    signal.signal(signal.SIGINT, connection.signal_handler)

    connection.connect()


if __name__ == "__main__":
    main()

# vim:ts=4:expandtab
