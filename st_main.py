from Kitsune import Kitsune
import numpy as np
import time
import streamlit as st
from matplotlib import pyplot as plt
from scipy.stats import norm
from pymongo import MongoClient
from math import ceil
import pandas as pd
from datetime import datetime

SAVE_DATA = False

st.set_page_config(layout="wide")
if SAVE_DATA:
    client = MongoClient('mongodb://localhost:27017/')
    db = client['kitsune']  # Change 'your_database_name' to your MongoDB database name
    collection = db['network_rmse_2']

menu = st.sidebar.selectbox("Menu", ['Kitsune Engine', 'Logs'])

st.title("NIDS Dashboard")

def plot(FMgrace,ADgrace, RMSEs, logProbs):
    # plot the RMSE anomaly scores
    print("Plotting results")
    fig, ax = plt.subplots(figsize=(12, 4))
    scatter = ax.scatter(range(FMgrace+ADgrace+1,len(RMSEs)),RMSEs[FMgrace+ADgrace+1:],s=0.1,c=logProbs[FMgrace+ADgrace+1:],cmap='RdYlGn')
    ax.set_yscale("log")
    ax.set_title("Anomaly Scores from Kitsune's Execution Phase")
    ax.set_ylabel("RMSE (log scaled)")
    ax.set_xlabel("Time elapsed [min]")
    fig.colorbar(scatter, label='Log Probability\n', orientation='vertical')

    return fig

# File location
if menu == "Kitsune Engine":
    st.subheader("Kitsune Engine")
    col1, col2 = st.columns(2)
    path = col1.text_input("pcap file path", "mirai.pcap")
    packet_limit = col2.number_input("packet limit", min_value=10_000, value=200_000)

    col1, col2, col3 = st.columns(3)
    # KitNET params:
    maxAE = col1.number_input("max AE", min_value=5, value=10)
    FMgrace = col2.number_input("FM Grace", min_value=100, value=5000)
    ADgrace = col3.number_input("AD Grace", min_value=1000, value=50_000)


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
        graph_placeholder = st.empty()
        while True:
            i += 1
            if i % 1000 == 0:
                print(i)
                if i > FMgrace+ADgrace:
                    print(RMSEs[i-2])
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
            if SAVE_DATA:
                result = collection.insert_one(data)
            RMSEs.append(rmse)
        stop = time.time()
        print("Complete. Time elapsed: " + str(stop - start))

        # Here we demonstrate how one can fit the RMSE scores to a log-normal distribution (useful for finding/setting a cutoff threshold \phi)
        benignSample = np.log(RMSEs[FMgrace + ADgrace + 1:FMgrace + ADgrace +100000])
        logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))
        fig = plot(FMgrace, ADgrace, RMSEs, logProbs)
        graph_placeholder.pyplot(fig)
elif menu=="Logs":
    st.subheader("Logs")
    page_size = st.sidebar.selectbox("Logs per page", [50, 100, 200], index=0)
    phase = st.sidebar.selectbox('phase', ["All","train", "predict"])
    path = st.sidebar.text_input('path')
    timestamp_option = st.sidebar.radio("Timestamp", ["All", "Select Range"])

    # Handling timestamp selection
    if timestamp_option == "Select Range":
        start_date = st.sidebar.date_input("Start date", value=datetime.now())
        end_date = st.sidebar.date_input("End date", value=datetime.now())
    else:
        start_date, end_date = None, None
    
    query_filter = {}
    if phase != "All":
        query_filter["phase"] = phase

    if timestamp_option == "Select Range":
        # Convert user input to UNIX timestamp (the number of seconds since epoch)
        start_timestamp = int(datetime(start_date.year, start_date.month, start_date.day).timestamp())
        # Adding one day worth of seconds to include the end_date in the query
        end_timestamp = int(datetime(end_date.year, end_date.month, end_date.day).timestamp()) + 86400
        
        query_filter["timestamp"] = {"$gte": start_timestamp, "$lte": end_timestamp}
    
    if path != "":
        query_filter['path'] = path

    total_documents = collection.count_documents(query_filter)
    total_pages = ceil(total_documents / page_size)
    if total_documents == 0:
        st.write("The logs still empty")
    else:
        page_number = st.sidebar.number_input("Select page", min_value=1, max_value=total_pages, value=1)
        # Retrieve data from MongoDB
        skips = page_size * (page_number - 1)
        logs_cursor = collection.find(query_filter).skip(skips).limit(page_size)
        
        # Convert the logs into a DataFrame
        logs_df = pd.DataFrame(list(logs_cursor))

        logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'], unit='s').dt.strftime('%Y-%m-%d')
        
        # If your MongoDB data keys match the DataFrame column names, you can directly display the DataFrame
        # Otherwise, you might need to rename DataFrame columns to match your desired structure
        logs_df = logs_df.rename(columns={
            "path": "Path",
            "timestamp": "Timestamp",
            "ip_protocol": "IP Protocol",
            "source_mac": "Source MAC",
            "destination_mac": "Destination MAC",
            "source_ip": "Source IP",
            "source_port": "Source Port",
            "destination_ip": "Destination IP",
            "destination_port": "Destination Port",
            "data_length": "Data Length",
            "rmse": "RMSE",
        })
        
        logs_df.drop(columns=['_id'], inplace=True)
        # Displaying the DataFrame as a table
        st.table(logs_df)
    