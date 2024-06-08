import streamlit as st
from kitsune.utils.db import get_plot_data
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

st.set_page_config(page_title="Kitsune Charts", page_icon="📈", layout="wide")

data = get_plot_data()

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

data = list(data)
data_show = []
for d in data:
    data_show.append({
        "title": f"Plot {d['data']['path']} ({datetime.utcfromtimestamp(d['data']['timestamp']).strftime('%Y-%m-%d')})",
        "plot": plot(d['metrics']['FMgrace'],d['metrics']['ADgrace'], d['metrics']['RMSEs'], d['metrics']['logProbs'])
    })
# Display the data as a expander for every data
for d in data_show:
    st.expander(d['title']).write(d['plot'])
