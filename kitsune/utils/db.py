import pymongo
from dotenv import load_dotenv
import os
import numpy as np
load_dotenv()

def get_db():
    client = pymongo.MongoClient(os.getenv('MONGODB_URI'))
    db = client[os.getenv('MONGODB_DB')]  # Change 'your_database_name' to your MongoDB database name
    collection = db[os.getenv('MONGODB_COLLECTION')]  # Change 'your_collection_name' to your MongoDB collection name
    return collection

def insert_plot(FMgrace, ADgrace, RMSEs, logProbs, data):
    client = pymongo.MongoClient(os.getenv('MONGODB_URI'))
    db = client[os.getenv('MONGODB_DB')]  # Change 'your_database_name' to your MongoDB database name
    collection = db[os.getenv('MONGODB_COLLECTION_PLOT')]  # Change 'your_collection_name' to your MongoDB collection name
    data_input = {
        'data': data,
        'metrics': {
            'FMgrace': FMgrace.tolist() if isinstance(FMgrace, np.ndarray) else FMgrace,
            'ADgrace': ADgrace.tolist() if isinstance(ADgrace, np.ndarray) else ADgrace,
            'RMSEs': RMSEs.tolist() if isinstance(RMSEs, np.ndarray) else RMSEs,
            'logProbs': logProbs.tolist() if isinstance(logProbs, np.ndarray) else logProbs
        }
    }
    collection.insert_one(data_input)
    
def get_plot_data():
    client = pymongo.MongoClient(os.getenv('MONGODB_URI'))
    db = client[os.getenv('MONGODB_DB')]  # Change 'your_database_name' to your MongoDB database name
    collection = db[os.getenv('MONGODB_COLLECTION_PLOT')]  # Change 'your_collection_name' to your MongoDB collection name
    # get only data field
    data = collection.find({})
    return data