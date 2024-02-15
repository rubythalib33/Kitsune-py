from FeatureExtractor import FE

feature_extractor = FE(interface='wlo1', limit=10, type='tshark')

print(feature_extractor.get_next_vector())

print(feature_extractor.get_next_vector())

print(feature_extractor.get_next_vector())