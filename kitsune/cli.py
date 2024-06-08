import argparse
from pymongo import MongoClient
from kitsune.kitnet.kitsune import Kitsune
import numpy as np
import time
import zipfile
from scipy.stats import norm
from matplotlib import pyplot as plt
from matplotlib import cm
import click
from tqdm import tqdm

@click.command()
@click.option('--save', type=bool, default=True, help='Save results to MongoDB')
@click.option('--mongo_uri', type=str, default='mongodb://localhost:27017/', help='MongoDB URI')
@click.option('--database', type=str, default='kitsune', help='MongoDB database name')
@click.option('--collection', type=str, default='network_rmse', help='MongoDB collection name')
@click.option('--file_path', type=str, default='Active_Wiretap_pcap.pcapng', help='Path to the pcap file')
@click.option('--packet_limit', type=int, default=200000, help='Number of packets to process')
@click.option('--max_ae', type=int, default=10, help='Maximum size for any autoencoder in the ensemble layer')
@click.option('--fm_grace', type=int, default=5000, help='Number of instances for feature mapping')
@click.option('--ad_grace', type=int, default=50000, help='Number of instances to train the anomaly detector')
def main(save, mongo_uri, database, collection, file_path, packet_limit, max_ae, fm_grace, ad_grace):
    SAVE = save
    # Connect to MongoDB
    if SAVE:
        client = MongoClient(mongo_uri)
        db = client[database]
        collection = db[collection]

    # File location
    path = file_path
    packet_limit = packet_limit

    # KitNET params:
    maxAE = max_ae
    FMgrace = fm_grace
    ADgrace = ad_grace
    
    # Build Kitsune
    K = Kitsune(file_path=path, limit=packet_limit, max_autoencoder_size=maxAE, FM_grace_period=FMgrace,
                AD_grace_period=ADgrace)

    print("Running Kitsune:")
    RMSEs = []
    i = 0
    start = time.time()
    if K.type != "tshark":
        for i in (pbar := tqdm(range(K.limit))):
            data = K.proc_next_packet(pbar=pbar)
            if data['rmse'] == -1:
                break
            RMSEs.append(data['rmse'])
            if SAVE:
                collection.insert_one(data)
    # Process each packet
    else:
        while True:
            i += 1
            if i % 1000 == 0:
                print(i)
            data = K.proc_next_packet()
            rmse = data['rmse']
            if rmse == -1 or i > K.limit:
                break
            
            RMSEs.append(rmse)
            if SAVE:
                # Push data to MongoDB
                collection.insert_one(data)
    stop = time.time()
    print("Complete. Time elapsed: " + str(stop - start))

    # Fit RMSE scores to a log-normal distribution
    # benignSample = np.log(RMSEs[FMgrace + ADgrace + 1:100000])
    benignSample = np.log(RMSEs[FMgrace + ADgrace + 1:FMgrace + ADgrace +100000])
    logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))

    # Plot the RMSEsE anomaly scores
    print("Plotting results")
    plt.figure(figsize=(10, 5))
    fig = plt.scatter(range(FMgrace + ADgrace + 1, len(RMSEs)), RMSEs[FMgrace + ADgrace + 1:], s=0.1, c=logProbs[FMgrace + ADgrace + 1:], cmap='RdYlGn')
    plt.yscale("log")
    plt.title("Anomaly Scores from Kitsune's Execution Phase")
    plt.ylabel("RMSE (log scaled)")
    plt.xlabel("Time elapsed [min]")
    figbar = plt.colorbar()
    figbar.ax.set_ylabel('Log Probability\n ', rotation=270)
    plt.show()

if __name__ == "__main__":
    main()
