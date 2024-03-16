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

to-do list:
1. membangun real time tracking menggunakan streamlit DONE
2. membangun real time tracking dengan streamlit dan mongodb
3. menggunakan fitur logs dan filter untuk dashboardnya