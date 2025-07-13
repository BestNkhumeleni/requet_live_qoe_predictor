import pickle
import re
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from collections import Counter
import pandas as pd
from sklearn.metrics import accuracy_score


def load_all_chunks(filepath='all_chunks_no1080.pkl'):
    """
    Loads the nested all_chunks list from disk.

    Parameters:
    - filepath: path to the input pickle file

    Returns:
    - all_chunks: the nested list structure loaded from disk
    """
    with open(filepath, 'rb') as f:
        all_chunks = pickle.load(f)
    return all_chunks


def parse_resolution(value):
    """Convert resolution label (e.g., '720p' or 720) to numeric (e.g., 720.0)."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        digits = re.findall(r'\d+', value)
        if digits:
            return float(digits[0])
    raise ValueError(f"Cannot parse resolution value: {value}")

def train_chunk_resolution_model(
    chunk_data,
    test_size=0.2,
    random_state=84,
    model_path='chunk_rf_model.pkl',
    encoder_path='chunk_label_encoder.pkl'
):
    """
    Train a Random Forest to predict resolution per individual chunk.

    Parameters:
    - chunk_data: 2D list where each element is
                  [time_stamp, chunk_duration, ttfb, slacktime,
                   download_time, chunk_size, audio_video, resolution]
    - test_size: fraction of samples to reserve for testing (default 0.2)
    - random_state: seed for reproducibility (default 42)
    - model_path: filepath to save the trained Random Forest (default 'chunk_rf_model.pkl')
    - encoder_path: filepath to save the LabelEncoder (default 'chunk_label_encoder.pkl')

    Returns:
    - clf: trained RandomForestClassifier
    - le: fitted LabelEncoder for resolution labels
    - acc: chunk-level prediction accuracy on the test set
    """
    # Extract features (first 7 entries) and labels (last entry)
    X = np.array([chunk[:7] for chunk in chunk_data], dtype=float)
    y = np.array([chunk[7] for chunk in chunk_data])

    # Encode resolution labels
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    # Split into train and test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=test_size, random_state=random_state, stratify=y_enc
    )

    # Train Random Forest
    clf = RandomForestClassifier(n_estimators=500, random_state=random_state)
    clf.fit(X_train, y_train)

    # Save model and encoder
    joblib.dump(clf, model_path)
    joblib.dump(le, encoder_path)

    # Evaluate
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Chunk-level resolution prediction accuracy: {acc:.2%}")

    return clf, le, acc

all_chunks = load_all_chunks() 

train_chunk_resolution_model(all_chunks)
# print(len(all_chunks))