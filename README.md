# How to setup
1. install libcap and tshark
```
sudo apt-get update
sudo apt-get install libcap2-bin tshark
```
2. install requirements of the project
```
pip install -r requirements.txt
```
3. (optional) running mongodb
```
docker run --name some-mongo -d -p 27017:27017 mongo
```

next: mencoba membreakdown 10 paper terkait NIDS yang terbaru supaya kita bisa dapatkan noveltynya
- judul
- methods
- kesimpulan
- kalau bisa (code)