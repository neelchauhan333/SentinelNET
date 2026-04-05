# backend/ml_detector.py
"""
ML Anomaly Detection for SentinelNet
Uses Isolation Forest to detect unusual device behavior
"""

from sklearn.ensemble import IsolationForest
import numpy as np
from datetime import datetime
from typing import List, Dict, Tuple

class MLAnomalyDetector:
    """Simple ML-based anomaly detector"""
    
    def __init__(self):
        self.models = {}  # One model per device
        self.min_events = 5  # Minimum events needed to train
        
    def extract_features(self, device: Dict, events: List[Dict]) -> np.ndarray:
        """
        Extract 5 key features from device behavior:
        1. Events per hour (recent activity rate)
        2. Hour of day (when device is active)
        3. Total events in last 24h
        4. Number of unique event types
        5. Average time between events (seconds)
        """
        
        if not events:
            return np.array([[0, 12, 0, 0, 3600]])  # Default values
        
        # Feature 1: Events per hour (recent)
        recent_events = events[:10]  # Last 10 events
        if len(recent_events) >= 2:
            first_time = datetime.fromisoformat(recent_events[-1]['event_time'])
            last_time = datetime.fromisoformat(recent_events[0]['event_time'])
            time_diff = (last_time - first_time).total_seconds() / 3600  # hours
            events_per_hour = len(recent_events) / max(time_diff, 0.1)
        else:
            events_per_hour = 0
        
        # Feature 2: Current hour of day (0-23)
        if events:
            try:
                latest_time = datetime.fromisoformat(events[0]['event_time'])
                hour_of_day = latest_time.hour
            except:
                hour_of_day = 12
        else:
            hour_of_day = 12
        
        # Feature 3: Total events in last 24h
        total_events_24h = len(events)
        
        # Feature 4: Number of unique event types
        event_types = set(e.get('event_type', '') for e in events)
        unique_event_types = len(event_types)
        
        # Feature 5: Average time between events
        if len(events) >= 2:
            times = []
            for i in range(min(len(events) - 1, 10)):
                try:
                    t1 = datetime.fromisoformat(events[i]['event_time'])
                    t2 = datetime.fromisoformat(events[i + 1]['event_time'])
                    times.append(abs((t1 - t2).total_seconds()))
                except:
                    pass
            avg_time_between = np.mean(times) if times else 3600
        else:
            avg_time_between = 3600
        
        return np.array([[
            events_per_hour,
            hour_of_day,
            total_events_24h,
            unique_event_types,
            avg_time_between
        ]])
    
    def train_or_update(self, device_id: str, features: np.ndarray):
        """Train or update model for a device"""
        
        if device_id not in self.models:
            # Create new model
            self.models[device_id] = {
                'model': IsolationForest(
                    contamination=0.1,  # 10% anomaly rate
                    random_state=42,
                    n_estimators=100
                ),
                'training_data': []
            }
        
        # Add to training data
        self.models[device_id]['training_data'].append(features)
        
        # Keep last 50 samples only
        if len(self.models[device_id]['training_data']) > 50:
            self.models[device_id]['training_data'] = \
                self.models[device_id]['training_data'][-50:]
        
        # Retrain if we have enough data
        if len(self.models[device_id]['training_data']) >= self.min_events:
            training_array = np.vstack(self.models[device_id]['training_data'])
            self.models[device_id]['model'].fit(training_array)
            return True
        
        return False
    
    def predict_anomaly(self, device_id: str, features: np.ndarray) -> Tuple[int, str]:
        """
        Predict if current behavior is anomalous
        Returns: (anomaly_score, explanation)
        """
        
        # Check if model exists and is trained
        if device_id not in self.models:
            return 0, "Learning normal behavior..."
        
        if len(self.models[device_id]['training_data']) < self.min_events:
            return 0, f"Collecting baseline data ({len(self.models[device_id]['training_data'])}/{self.min_events})"
        
        # Get prediction
        model = self.models[device_id]['model']
        prediction = model.predict(features)
        anomaly_score_raw = model.score_samples(features)
        
        # Convert to 0-100 scale (more negative = more anomalous)
        # score_samples returns negative values, more negative = more anomalous
        anomaly_score = int(max(0, min(100, (-anomaly_score_raw[0]) * 20)))
        
        # Generate explanation
        feature_values = features[0]
        explanations = []
        
        # Check each feature for unusual values
        if feature_values[0] > 10:  # High event rate
            explanations.append(f"High activity rate ({feature_values[0]:.1f} events/hour)")
        
        if feature_values[1] < 6 or feature_values[1] > 22:  # Unusual hours
            explanations.append(f"Unusual hour ({int(feature_values[1])}:00)")
        
        if feature_values[2] > 50:  # Many events
            explanations.append(f"High event count ({int(feature_values[2])} in 24h)")
        
        if feature_values[4] < 60:  # Rapid events
            explanations.append(f"Rapid event sequence ({int(feature_values[4])}s between events)")
        
        if prediction[0] == -1:  # Anomaly detected
            if not explanations:
                explanations.append("Behavior deviates from learned baseline")
            explanation = "ML Anomaly: " + ", ".join(explanations)
        else:
            explanation = "Behavior matches normal pattern"
        
        return anomaly_score, explanation

# Global ML detector instance
ml_detector = MLAnomalyDetector()

def get_ml_score(device: Dict, events: List[Dict]) -> Tuple[int, str]:
    """
    Main function to get ML anomaly score
    
    Args:
        device: Device record
        events: List of events for this device
    
    Returns:
        (ml_score, explanation)
    """
    
    device_id = device.get('device_id')
    
    # Extract features
    features = ml_detector.extract_features(device, events)
    
    # Train/update model
    ml_detector.train_or_update(device_id, features)
    
    # Get prediction
    ml_score, explanation = ml_detector.predict_anomaly(device_id, features)
    
    return ml_score, explanation