from pymongo import MongoClient
from Kitsune import Kitsune
import numpy as np
import time

# Connect to MongoDB
# client = MongoClient('mongodb://localhost:27017/')
# db = client['kitsune']  # Change 'your_database_name' to your MongoDB database name
# collection = db['network_rmse_1']

# Load Mirai pcap (a recording of the Mirai botnet malware being activated)
# The first 70,000 observations are clean...
print("Unzipping Sample Capture...")
import zipfile
with zipfile.ZipFile("mirai.zip", "r") as zip_ref:
    zip_ref.extractall()

# File location
path = "Active_Wiretap_pcap.pcapng"  # the pcap, pcapng, or tsv file to process.
packet_limit = 200_000  # the number of packets to process

# KitNET params:
maxAE = 10  # maximum size for any autoencoder in the ensemble layer
FMgrace = 5000  # the number of instances taken to learn the feature mapping (the ensemble's architecture)
ADgrace = 50000  # the number of instances used to train the anomaly detector (ensemble itself)

# Build Kitsune
K = Kitsune(file_path=path, limit=packet_limit, max_autoencoder_size=maxAE, FM_grace_period=FMgrace,
            AD_grace_period=ADgrace)

print("Running Kitsune:")
RMSEs = []
i = 0
start = time.time()
# Here we process (train/execute) each individual packet.
# In this way, each observation is discarded after performing process() method.
while True:
    i += 1
    if i % 1000 == 0:
        print(i)
    rmse = K.proc_next_packet()
    if rmse == -1 or i > K.limit:
        break
    RMSEs.append(rmse)
    # Push data to MongoDB
    # collection.insert_one({"timestamp": time.time(), "rmse": rmse})
stop = time.time()
print("Complete. Time elapsed: " + str(stop - start))

# Here we demonstrate how one can fit the RMSE scores to a log-normal distribution (useful for finding/setting a cutoff threshold \phi)
from scipy.stats import norm
benignSample = np.log(RMSEs[FMgrace + ADgrace + 1:100000])
logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))

# plot the RMSE anomaly scores
print("Plotting results")
from matplotlib import pyplot as plt
from matplotlib import cm
plt.figure(figsize=(10,5))
fig = plt.scatter(range(FMgrace+ADgrace+1,len(RMSEs)),RMSEs[FMgrace+ADgrace+1:],s=0.1,c=logProbs[FMgrace+ADgrace+1:],cmap='RdYlGn')
plt.yscale("log")
plt.title("Anomaly Scores from Kitsune's Execution Phase")
plt.ylabel("RMSE (log scaled)")
plt.xlabel("Time elapsed [min]")
figbar=plt.colorbar()
figbar.ax.set_ylabel('Log Probability\n ', rotation=270)
plt.show()