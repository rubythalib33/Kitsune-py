from kitsune.kitnet.kitsune import Kitsune
import numpy as np
import time
import streamlit as st
from matplotlib import pyplot as plt
from scipy.stats import norm
from kitsune.utils.db import get_db, insert_plot

st.set_page_config(page_title="Kitsune Engine", page_icon="📈", layout="wide")

@st.cache_resource
def get_collection():
    return get_db()

collection=get_collection()

def plot(FMgrace,ADgrace, RMSEs, logProbs):
    # plot the RMSE anomaly scores
    fig, ax = plt.subplots(figsize=(12, 4))
    scatter = ax.scatter(range(FMgrace+ADgrace+1,len(RMSEs)),RMSEs[FMgrace+ADgrace+1:],s=0.1,c=logProbs[FMgrace+ADgrace+1:],cmap='RdYlGn')
    ax.set_yscale("log")
    ax.set_title("Anomaly Scores from Kitsune's Execution Phase")
    ax.set_ylabel("RMSE (log scaled)")
    ax.set_xlabel("Time elapsed [min]")
    fig.colorbar(scatter, label='Log Probability\n', orientation='vertical')

    return fig

col1, col2 = st.columns(2)
path = col1.text_input("pcap file path", "mirai.pcap")
packet_limit = col2.number_input("packet limit", min_value=10_000, value=200_000)

col1, col2, col3 = st.columns(3)
# KitNET params:
maxAE = col1.number_input("max AE", min_value=5, value=10)
FMgrace = col2.number_input("FM Grace", min_value=100, value=5000)
ADgrace = col3.number_input("AD Grace", min_value=1000, value=50_000)

save = st.sidebar.toggle("Save data", False)

if st.button("Run the Anomaly Detector"):
# Build Kitsune
    K = None
    if path.endswith('pcap') or path.endswith('pcapng'):
        K = Kitsune(file_path=path, limit=packet_limit, max_autoencoder_size=maxAE, FM_grace_period=FMgrace,
                    AD_grace_period=ADgrace)
    elif path.endswith('csv'):
        K = Kitsune(file_path=path, limit=packet_limit, max_autoencoder_size=maxAE, FM_grace_period=FMgrace,
                    AD_grace_period=ADgrace, type='csv')
    else:
        K = Kitsune(interface=path, limit=packet_limit, max_autoencoder_size=maxAE, FM_grace_period=FMgrace,
                    AD_grace_period=ADgrace,type='tshark')

    print("Running Kitsune:")
    RMSEs = []
    i = 0
    start = time.time()
    # Here we process (train/execute) each individual packet.
    # In this way, each observation is discarded after performing process() method.
    progress_text = f'Operation in progress. Please wait. Data will be {"saved" if save else "not saved"} in mongoDB.' 
    my_bar = st.progress(0, text=progress_text)
    
    graph_placeholder = st.empty()
    if K.type != "tshark":
        limit = K.limit
        for i in range(limit):
            if i % 1000 == 0:
                if i > FMgrace+ADgrace:
                    benignSample = np.log(RMSEs[FMgrace + ADgrace + 1:FMgrace + ADgrace +100000])
                    logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))
                    fig = plot(FMgrace, ADgrace, RMSEs, logProbs)
                    graph_placeholder.pyplot(fig)
                else:
                    graph_placeholder.text(f"Learning the clean data first at datapoint {i}/{FMgrace+ADgrace}")
            data = K.proc_next_packet()
            rmse = data['rmse']
            data['phase'] = 'train' if i < FMgrace+ADgrace else 'predict'
            data['path'] = path
            if save:
                result = collection.insert_one(data)
            RMSEs.append(rmse)
            my_bar.progress((i + 1) / limit, text=progress_text)
            
    else:
        while True:
            i += 1
            if i % 1000 == 0:
                if i > FMgrace+ADgrace:
                    benignSample = np.log(RMSEs[FMgrace + ADgrace + 1:FMgrace + ADgrace +100000])
                    logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))
                    fig = plot(FMgrace, ADgrace, RMSEs, logProbs)
                    graph_placeholder.pyplot(fig)
                else:
                    graph_placeholder.text(f"Learning the clean data first at datapoint {i}/{FMgrace+ADgrace}")
            
            data = K.proc_next_packet()
            rmse = data['rmse']
            data['phase'] = 'train' if i < FMgrace+ADgrace else 'predict'
            if rmse == -1 or i > K.limit:
                break
            data['path'] = path
            if save:
                result = collection.insert_one(data)
            RMSEs.append(rmse)
    stop = time.time()
    print("Complete. Time elapsed: " + str(stop - start))

    # Here we demonstrate how one can fit the RMSE scores to a log-normal distribution (useful for finding/setting a cutoff threshold \phi)
    benignSample = np.log(RMSEs[FMgrace + ADgrace + 1:FMgrace + ADgrace +100000])
    logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))
    fig = plot(FMgrace, ADgrace, RMSEs, logProbs)
    if save:
        insert_plot(FMgrace, ADgrace, RMSEs, logProbs, data)
    graph_placeholder.pyplot(fig)