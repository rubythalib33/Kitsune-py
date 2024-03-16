from pymongo import MongoClient

# Establish a connection to the MongoDB server
client = MongoClient('mongodb://localhost:27017/')

# Select the database and collection you want to clean
db = client['kitsune']  # Replace 'kitsune' with your database name if different
collection = db['network_rmse_2']  # Replace 'network_rmse_2' with your collection name if different

# Delete all documents in the collection
result = collection.delete_many({})

# Print the result of the operation
print(f"Documents deleted: {result.deleted_count}")
