### Docker
Build docker image with:
```
docker build . -f docker/Dockerfile -t tdm/edge_dispatcher
```

Config file example:

```
[EDGE_dispatcher]
edge_id = 12345
mqtt_local_host = mosquitto
mqtt_local_port = 1883
mqtt_remote_host = remote.example.com
mqtt_remote_port = 8883
logging_level = 0
```
