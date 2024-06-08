

# Installation

1. Clone project
```bash
git clone -b poetry https://github.com/rubythalib33/Kitsune-py.git 
```

2. Install Dependencies 

```bash
sudo apt-get update
sudo apt install build-essential libpcap-dev libcap2-bin tshark
```

3. Run MongoDB (optional)
```bash
sudo docker pull mongo
sudo docker run --name some-mongo -d -p 27017:27017 mongo
```

4. Install poetry (`pip install poetry`)
5. Install python dependencies
   
```bash
poetry shell
poetry install
```

# Running the code

1. change the directory to kitsune folder
2. Change environment using `poetry shell`
3. To run CLI use `poetry run kitsune --save True --file_path '../filepath.pcapng'`
4. To run simulation run with `streamlit run simulation.py`