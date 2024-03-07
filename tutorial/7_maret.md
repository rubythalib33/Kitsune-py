# Setup Grafana
## setup grafana ubuntu
```
docker run -d -p 3000:3000 --name=grafana grafana/grafana-enterprise
```
## running mongodb
```
docker run -d -p 27017:27017 --name mongodb mongo
```