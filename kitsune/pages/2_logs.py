from kitsune.kitnet.kitsune import Kitsune
import numpy as np
import time
import streamlit as st
from matplotlib import pyplot as plt
from scipy.stats import norm
from kitsune.utils.db import get_db
from datetime import datetime
from math import ceil
import pandas as pd

st.set_page_config(page_title="Log", page_icon="📈", layout="wide")

@st.cache_resource
def get_collection():
    return get_db()

collection=get_collection()

@st.cache_data(show_spinner=False)
def get_logs(phase, path, timestamp_option, start_date, end_date, page_size, page_number):
    query_filter = {}
    
    if phase != "All":
        query_filter["phase"] = phase

    if timestamp_option == "Select Range":
        start_timestamp = int(datetime(start_date.year, start_date.month, start_date.day).timestamp())
        end_timestamp = int(datetime(end_date.year, end_date.month, end_date.day).timestamp()) + 86400
        query_filter["timestamp"] = {"$gte": start_timestamp, "$lte": end_timestamp}

    if path:
        query_filter['path'] = path

    # Assuming `collection` is your MongoDB collection object
    total_documents = collection.count_documents(query_filter)
    total_pages = ceil(total_documents / page_size)

    if total_documents == 0:
        return None, 0

    skips = page_size * (page_number - 1)
    logs_cursor = collection.find(query_filter).skip(skips).limit(page_size)
    logs_df = pd.DataFrame(list(logs_cursor))

    logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'], unit='s').dt.strftime('%Y-%m-%d')
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

    return logs_df, total_pages


page_size = st.sidebar.selectbox("Logs per page", [50, 100, 200], index=0)
phase = st.sidebar.selectbox('phase', ["All", "train", "predict"])
path = st.sidebar.text_input('path')
timestamp_option = st.sidebar.radio("Timestamp", ["All", "Select Range"])

if timestamp_option == "Select Range":
    start_date = st.sidebar.date_input("Start date", value=datetime.now())
    end_date = st.sidebar.date_input("End date", value=datetime.now())
else:
    start_date, end_date = None, None

logs_df, total_pages = get_logs(phase, path, timestamp_option, start_date, end_date, page_size, 1)

if logs_df is None:
    st.write("The logs are still empty")
else:
    page_number = st.sidebar.number_input("Select page", min_value=1, max_value=total_pages, value=1)
    logs_df, _ = get_logs(phase, path, timestamp_option, start_date, end_date, page_size, page_number)
    st.table(logs_df)