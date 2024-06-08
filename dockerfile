# Use a Python base image
FROM python:3.9

# 1. Update Linux packages
RUN apt-get update && apt-get upgrade -y

# 2. Install required packages
RUN apt-get install -y build-essential libpcap-dev libcap2-bin tshark

# 3. Install Poetry using pip
RUN pip install poetry

# 4. Set the working directory
WORKDIR /app

# 5. Copy the current directory contents into the container at /app
COPY . .

# 6. Use Poetry shell
RUN poetry config virtualenvs.create false

# 7. Install dependencies
RUN poetry install

# 8. Set up command to run the app
CMD ["poetry", "run", "streamlit", "run", "kitsune/simulation.py"]
