# TDM Edge Dispatcher
In [TDM Edge Gateway Reference Architecture](http://www.tdm-project.it/en/) the
Edge Dispatcher is the micro-service in charge of collecting the data sent by
sensor and station *handlers* to the internal broker and forward them as *messages* to
the remote TDM Cloud.

It carries out the task of:

- decouple data production from data transmission in order to temporarily
  store, compress and send data at intervals that can be configured according
  to network capabilities;
- present the credentials for remote cloud accessing and transmission;
- manage locally any interruptions or deteriorations of the communications.

## Dispatcher Data Flow
![MacDown Screenshot](./doc/img/Dispatcher Data Flow.png "Dispatcher Data Flow")

## Configurations
Settings are retrieved from both configuration file and command line.
Values are applied in the following order, the last overwriting the previous:

1. configuration file section '***GENERAL***' for the common options (logging, local MQTT broker...);
2. configuration file section '***EDGE\_dispatcher***' for both common and specific options;
3. command line options.

-
### Configuration file
#### Local broker options
* **mqtt\_host**

   hostname or address of the local broker (default: *localhost*)

* **mqtt\_port**

   port of the local broker (default: *1883*)

#### Remote broker options
* **mqtt\_local\_host**

	hostname or address of the local broker (default: *localhost*)

* **mqtt\_local\_port**

	port of the local broker (default: *1883*)

* **mqtt\_remote\_host**

	hostname or address of the remote broker (default: )

* **mqtt\_remote\_port**

	port of the remote broker (default: *8883*)

#### AUTH/TLS options for the remote borker
* **mqtt\_remote\_tls**

	remote broker uses TLS (default: *True*)

* **mqtt\_remote\_cafile**

	path of the trusted CA certificates file for the remote broker (default: */etc/ssl/cert.pem*)

* **mqtt\_remote\_certfile**

	path of the cert file for the remote broker (*UNUSED, RESERVED*)

* **mqtt\_remote\_keyfile**

	path of the key file for the remote broker (*UNUSED, RESERVED*)

* **mqtt\_remote\_user**

	username to use for the remote broker (default: *the edge id*)

* **mqtt\_remote\_pass**

	password to use for the remote broker

* **mqtt\_remote\_secret**

	password to use for the remote broker in Docker Secret

#### Other options
* **logging\_level**

   threshold level for log messages (default: *20*)


When a settings is present both in the *GENERAL* and *application specific*  section, the application specific is applied to the specific handler.

In this example, the *logging\_level* settings is overwritten to *1* only for this handler, while other handlers use *0* from the section *GENERAL*:

```ini
[GENERAL]
logging_level = 0

[EDGE_dispatcher]
mqtt_local_host = mosquitto
mqtt_local_port = 1883
mqtt_remote_host = tdm-broker.example.com
mqtt_remote_port = 8883
logging_level = 0
```

-
### Command line
-  **-h, --help**

	shows the help message and exit

-  **-c FILE, --config-file FILE**

	specifies the path of the configuration file

-  **-l LOGGING\_LEVEL, --logging-level LOGGING\_LEVEL**

	threshold level for log messages (default: *20*)

-  **--local-broker MQTT\_LOCAL\_HOST**

	hostname or address of the local broker (default: *localhost*)

-  **--local-port MQTT\_LOCAL\_PORT**

	port of the local broker (default: *1883*)

-  **--remote-broker MQTT\_REMOTE\_HOST**

	hostname or address of the remote broker (default: )

-  **--remote-port MQTT\_REMOTE\_PORT**

	port of the remote broker (default: *8883*)

-  **--remote-tls MQTT\_REMOTE\_TLS**

	remote broker uses TLS (default: *True*)

-  **--remote-cafile MQTT\_REMOTE\_CAFILE**

	path of the trusted CA certificates file for the remote broker (default: */etc/ssl/cert.pem*)

-  **--remote-certfile MQTT\_REMOTE\_CERTFILE**

	path of the cert file for the remote broker (*UNUSED, RESERVED*)

-  **--remote-keyfile MQTT\_REMOTE\_KEYFILE**

	path of the key file for the remote broker (*UNUSED, RESERVED*)

-  **--remote-user MQTT\_REMOTE\_USER**

	username to use for the remote broker (default: *the edge id*)

-  **--remote-pass MQTT\_REMOTE\_PASS**

	password to use for the remote broker

-  **--remote-secret MQTT\_REMOTE\_SECRET**

	password to use for the remote broker in Docker Secret

-  **--edge-id EDGE\_ID**

	id of the edge gateway (default: *the board serial number*)
