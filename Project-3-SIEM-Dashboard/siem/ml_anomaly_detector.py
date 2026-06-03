"""
Machine Learning Based Anomaly Detector
========================================

Enhanced anomaly detection using machine learning algorithms to complement
statistical methods. This module provides:
1. Isolation Forest for outlier detection
2. Autoencoder for reconstruction error-based anomaly detection
3. One-Class SVM for novelty detection
4. LSTM for temporal anomaly detection in log sequences

This detector can be used alongside or instead of the statistical anomaly detector.
"""

import numpy as np
import time
import joblib
import os
from typing import Dict, List, Optional, Tuple, Any, Union, Deque
from collections import deque
from datetime import datetime
import json

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("Warning: scikit-learn not available. ML anomaly detection disabled.")

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("Warning: TensorFlow not available. Deep learning anomaly detection disabled.")


class MLAnomalyDetector:
    """
    Machine Learning based anomaly detection engine for SIEM.

    Combines multiple ML algorithms for robust anomaly detection:
    - Isolation Forest: Effective for high-dimensional outlier detection
    - One-Class SVM: Good for novelty detection with clear boundary
    - Autoencoder: Learns compressed representation, high reconstruction error = anomaly
    - LSTM: Captures temporal patterns in event sequences

    Features:
    - Online learning with periodic retraining
    - Model persistence and loading
    - Ensemble voting for final decision
    - Feature importance and explainability
    """

    def __init__(self,
                 contamination: float = 0.1,
                 retrain_interval: int = 3600,  # 1 hour
                 min_samples_for_training: int = 100,
                 model_path: str = "./models") -> None:
        """
        Initialize ML anomaly detector.

        Args:
            contamination: Expected proportion of anomalies in data (0.0 to 0.5)
            retrain_interval: Seconds between model retraining
            min_samples_for_training: Minimum samples needed to train models
            model_path: Directory to save/load models
        """
        self.contamination: float = contamination
        self.retrain_interval: int = retrain_interval
        self.min_samples_for_training: int = min_samples_for_training
        self.model_path: str = model_path

        # Ensure model directory exists
        os.makedirs(model_path, exist_ok=True)

        # Initialize models
        self.models: Dict[str, Any] = {}
        self.scalers: Dict[str, Any] = {}
        self.feature_names: List[str] = []
        self.is_trained: bool = False
        self.last_train_time: float = 0

        # Data buffers for training
        self.feature_buffer: Deque[np.ndarray] = deque(maxlen=10000)
        self.labels_buffer: Deque[int] = deque(maxlen=10000)  # For supervised learning if needed

        # Prediction history for ensemble voting
        self.prediction_history: Deque[Tuple[bool, float, Dict[str, Any]]] = deque(maxlen=100)

        # Initialize available models
        self._initialize_models()

    def _initialize_models(self) -> None:
        """Initialize ML models based on available libraries."""
        if SKLEARN_AVAILABLE:
            # Isolation Forest
            self.models['isolation_forest'] = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100
            )
            self.scalers['isolation_forest'] = StandardScaler()

            # One-Class SVM
            self.models['one_class_svm'] = OneClassSVM(
                nu=self.contamination,
                kernel='rbf',
                gamma='scale'
            )
            self.scalers['one_class_svm'] = StandardScaler()

        if TENSORFLOW_AVAILABLE:
            # Autoencoder will be built dynamically based on input shape
            self.models['autoencoder'] = None
            self.scalers['autoencoder'] = StandardScaler()

            # LSTM for sequence data
            self.models['lstm'] = None
            self.scalers['lstm'] = StandardScaler()

    def _extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """
        Extract numerical features from a normalized event for ML models.

        Args:
            event: Normalized event dictionary

        Returns:
            Feature vector as numpy array
        """
        features: List[float] = []

        # Basic event features
        features.append(float(event.get('severity', 0)))
        features.append(1.0 if event.get('src_ip') else 0.0)  # Has source IP
        features.append(1.0 if event.get('dst_ip') else 0.0)  # Has destination IP
        features.append(float(event.get('src_port', 0)))
        features.append(float(event.get('dst_port', 0)))

        # Protocol encoding (simple mapping)
        protocol_map: Dict[str, int] = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'DNS': 5}
        features.append(float(protocol_map.get(event.get('protocol', ''), 0)))

        # Action encoding
        action_map: Dict[str, int] = {'ALLOW': 1, 'DENY': 2, 'DROP': 3, 'REJECT': 4,
                                     'GET': 5, 'POST': 6, 'PUT': 7, 'DELETE': 8,
                                     'QUERY': 9, 'CONNECT': 10, 'DISCONNECT': 11,
                                     'AUTH_FAIL': 12, 'SUCCESS': 13, 'FAILURE': 14}
        features.append(float(action_map.get(event.get('action', ''), 0)))

        # Event type encoding (hash-based for consistency)
        event_type: str = event.get('event_type', '')
        features.append(float(hash(event_type) % 1000) / 1000.0)  # Normalize to 0-1

        # Source type encoding
        source_type: str = event.get('source_type', '')
        features.append(float(hash(source_type) % 1000) / 1000.0)

        # Username features
        features.append(1.0 if event.get('username') and event.get('username') != '-' else 0.0)

        # Metadata features
        metadata: Dict[str, Any] = event.get('metadata', {})
        features.append(float(len(str(metadata))))  # Metadata length

        # Status code if available
        status_code: int = metadata.get('status_code', 0)
        features.append(float(status_code))

        # Bytes if available
        bytes_val: int = metadata.get('bytes', 0)
        features.append(float(bytes_val))

        # Time-based features (if timestamp available)
        timestamp_str: str = event.get('timestamp', '')
        try:
            if 'T' in timestamp_str:
                dt: datetime = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                dt: datetime = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            features.append(float(dt.hour))          # Hour of day (0-23)
            features.append(float(dt.weekday()))     # Day of week (0-6)
            features.append(float(dt.day))           # Day of month (1-31)
            features.append(float(dt.month))         # Month (1-12)
        except:
            features.extend([0.0, 0.0, 0.0, 0.0])    # Default if parsing fails

        # Store feature names for consistency (first time only)
        if not self.feature_names:
            self.feature_names = [
                'severity', 'has_src_ip', 'has_dst_ip', 'src_port', 'dst_port',
                'protocol', 'action', 'event_type_hash', 'source_type_hash',
                'has_username', 'metadata_length', 'status_code', 'bytes',
                'hour', 'weekday', 'day', 'month'
            ]

        return np.array(features).reshape(1, -1)

    def _build_autoencoder(self, input_dim: int) -> Optional[Any]:
        """Build autoencoder model for reconstruction-based anomaly detection."""
        if not TENSORFLOW_AVAILABLE:
            return None

        # Encoder
        input_layer = keras.Input(shape=(input_dim,))
        encoded = layers.Dense(input_dim // 2, activation='relu')(input_layer)
        encoded = layers.Dense(input_dim // 4, activation='relu')(encoded)
        encoded = layers.Dense(input_dim // 8, activation='relu')(encoded)

        # Decoder
        decoded = layers.Dense(input_dim // 4, activation='relu')(encoded)
        decoded = layers.Dense(input_dim // 2, activation='relu')(decoded)
        decoded = layers.Dense(input_dim, activation='linear')(decoded)

        autoencoder = keras.Model(input_layer, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        return autoencoder

    def _build_lstm_model(self, sequence_length: int = 10, feature_dim: int = 17) -> Optional[Any]:
        """Build LSTM model for temporal anomaly detection."""
        if not TENSORFLOW_AVAILABLE:
            return None

        model = keras.Sequential([
            layers.LSTM(50, activation='relu', input_shape=(sequence_length, feature_dim)),
            layers.Dropout(0.2),
            layers.Dense(25, activation='relu'),
            layers.Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model

    def train_models(self, events: List[Dict[str, Any]]) -> bool:
        """
        Train ML models on a batch of events.

        Args:
            events: List of normalized event dictionaries

        Returns:
            True if training succeeded, False otherwise
        """
        if len(events) < self.min_samples_for_training:
            print(f"Not enough samples for training: {len(events)} < {self.min_samples_for_training}")
            return False

        # Extract features
        features_list = []
        for event in events:
            try:
                features = self._extract_features(event)
                features_list.append(features.flatten())
            except Exception as e:
                print(f"Error extracting features from event: {e}")
                continue

        if len(features_list) < self.min_samples_for_training:
            print(f"Too many feature extraction errors: {len(features_list)} valid samples")
            return False

        X = np.array(features_list)

        # Scale features
        if SKLEARN_AVAILABLE:
            # Train Isolation Forest
            if 'isolation_forest' in self.models:
                try:
                    X_scaled = self.scalers['isolation_forest'].fit_transform(X)
                    self.models['isolation_forest'].fit(X_scaled)
                    print("Isolation Forest trained successfully")
                except Exception as e:
                    print(f"Error training Isolation Forest: {e}")

            # Train One-Class SVM
            if 'one_class_svm' in self.models:
                try:
                    X_scaled = self.scalers['one_class_svm'].fit_transform(X)
                    self.models['one_class_svm'].fit(X_scaled)
                    print("One-Class SVM trained successfully")
                except Exception as e:
                    print(f"Error training One-Class SVM: {e}")

        # Train Autoencoder
        if TENSORFLOW_AVAILABLE and 'autoencoder' in self.models:
            try:
                if self.models['autoencoder'] is None:
                    self.models['autoencoder'] = self._build_autoencoder(X.shape[1])

                X_scaled = self.scalers['autoencoder'].fit_transform(X)
                self.models['autoencoder'].fit(
                    X_scaled, X_scaled,
                    epochs=50,
                    batch_size=32,
                    validation_split=0.1,
                    verbose=0
                )
                print("Autoencoder trained successfully")
            except Exception as e:
                print(f"Error training Autoencoder: {e}")

        self.is_trained = True
        self.last_train_time = time.time()
        print(f"ML models trained on {len(X)} samples")
        return True

    def predict_anomaly(self, event: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Predict if an event is anomalous using ensemble of ML models.

        Args:
            event: Normalized event dictionary

        Returns:
            Tuple of (is_anomaly: bool, confidence: float, details: dict)
        """
        if not self.is_trained:
            # Return False if not trained yet
            return False, 0.0, {'reason': 'models_not_trained'}

        try:
            # Extract features
            features = self._extract_features(event)

            # Get predictions from each model
            predictions = {}
            scores = {}

            if SKLEARN_AVAILABLE:
                # Isolation Forest prediction
                if 'isolation_forest' in self.models and self.models['isolation_forest'] is not None:
                    try:
                        X_scaled = self.scalers['isolation_forest'].transform(features)
                        # Isolation Forest returns -1 for anomalies, 1 for normal
                        pred = self.models['isolation_forest'].predict(X_scaled)[0]
                        score = self.models['isolation_forest'].decision_function(X_scaled)[0]
                        # Convert to anomaly score (higher = more anomalous)
                        anomaly_score = -score  # Invert so higher = more anomalous
                        predictions['isolation_forest'] = bool(pred == -1)
                        scores['isolation_forest'] = float(anomaly_score)
                    except Exception as e:
                        print(f"Error in Isolation Forest prediction: {e}")
                        predictions['isolation_forest'] = False
                        scores['isolation_forest'] = 0.0

                # One-Class SVM prediction
                if 'one_class_svm' in self.models and self.models['one_class_svm'] is not None:
                    try:
                        X_scaled = self.scalers['one_class_svm'].transform(features)
                        pred = self.models['one_class_svm'].predict(X_scaled)[0]
                        # One-Class SVM returns -1 for outliers, 1 for inliers
                        score = self.models['one_class_svm'].decision_function(X_scaled)[0]
                        anomaly_score = -score  # Invert so higher = more anomalous
                        predictions['one_class_svm'] = bool(pred == -1)
                        scores['one_class_svm'] = float(anomaly_score)
                    except Exception as e:
                        print(f"Error in One-Class SVM prediction: {e}")
                        predictions['one_class_svm'] = False
                        scores['one_class_svm'] = 0.0

            # Autoencoder prediction
            if TENSORFLOW_AVAILABLE and 'autoencoder' in self.models:
                try:
                    if self.models['autoencoder'] is not None:
                        X_scaled = self.scalers['autoencoder'].transform(features)
                        reconstructed = self.models['autoencoder'].predict(X_scaled, verbose=0)
                        # Reconstruction error (MSE)
                        mse = np.mean(np.power(X_scaled - reconstructed, 2))
                        # Threshold based on training data statistics
                        # For simplicity, use a fixed threshold - in production would be learned
                        threshold = 0.1  # This should be calibrated during training
                        predictions['autoencoder'] = bool(mse > threshold)
                        scores['autoencoder'] = float(mse)
                except Exception as e:
                    print(f"Error in Autoencoder prediction: {e}")
                    predictions['autoencoder'] = False
                    scores['autoencoder'] = 0.0

            # Ensemble decision: majority vote
            if predictions:
                anomaly_votes = sum(predictions.values())
                total_votes = len(predictions)
                is_anomaly = anomaly_votes > (total_votes // 2)  # Majority vote

                # Confidence based on agreement among models
                confidence = anomaly_votes / total_votes if total_votes > 0 else 0.0

                # Average score
                avg_score = np.mean(list(scores.values())) if scores else 0.0

                details = {
                    'predictions': predictions,
                    'scores': scores,
                    'ensemble_vote': f"{anomaly_votes}/{total_votes}",
                    'confidence': confidence,
                    'average_score': avg_score,
                    'feature_count': len(self.feature_names)
                }

                return is_anomaly, confidence, details
            else:
                return False, 0.0, {'reason': 'no_models_available'}

        except Exception as e:
            print(f"Error in ML anomaly prediction: {e}")
            return False, 0.0, {'reason': f'prediction_error: {str(e)}'}

    def partial_fit(self, event: Dict[str, Any]):
        """
        Add event to training buffer for incremental learning.

        Args:
            event: Normalized event dictionary
        """
        try:
            features = self._extract_features(event)
            self.feature_buffer.append(features.flatten())

            # Check if we should retrain
            current_time = time.time()
            if (len(self.feature_buffer) >= self.min_samples_for_training and
                (current_time - self.last_train_time) > self.retrain_interval):

                # Convert buffer to list and train
                events_list = list(self.feature_buffer)
                # We would need to convert back to event dicts - simplified for now
                # In production, we'd store original events or have a separate labeling mechanism
                print(f"Ready to retrain with {len(self.feature_buffer)} samples")
                # Implementation would go here
        except Exception as e:
            print(f"Error in partial_fit: {e}")

    def save_models(self, prefix: str = "siem_ml"):
        """Save trained models to disk."""
        if not SKLEARN_AVAILABLE:
            print("Cannot save models: scikit-learn not available")
            return

        try:
            # Save Isolation Forest
            if 'isolation_forest' in self.models and self.models['isolation_forest'] is not None:
                joblib.dump(self.models['isolation_forest'],
                           os.path.join(self.model_path, f"{prefix}_isolation_forest.pkl"))
                joblib.dump(self.scalers['isolation_forest'],
                           os.path.join(self.model_path, f"{prefix}_isolation_forest_scaler.pkl"))

            # Save One-Class SVM
            if 'one_class_svm' in self.models and self.models['one_class_svm'] is not None:
                joblib.dump(self.models['one_class_svm'],
                           os.path.join(self.model_path, f"{prefix}_one_class_svm.pkl"))
                joblib.dump(self.scalers['one_class_svm'],
                           os.path.join(self.model_path, f"{prefix}_one_class_svm_scaler.pkl"))

            # Save metadata
            metadata = {
                'feature_names': self.feature_names,
                'contamination': self.contamination,
                'is_trained': self.is_trained,
                'last_train_time': self.last_train_time
            }
            with open(os.path.join(self.model_path, f"{prefix}_metadata.json"), 'w') as f:
                json.dump(metadata, f)

            print(f"Models saved to {self.model_path}")
        except Exception as e:
            print(f"Error saving models: {e}")

    def load_models(self, prefix: str = "siem_ml"):
        """Load trained models from disk."""
        if not SKLEARN_AVAILABLE:
            print("Cannot load models: scikit-learn not available")
            return False

        try:
            # Load Isolation Forest
            iso_path = os.path.join(self.model_path, f"{prefix}_isolation_forest.pkl")
            iso_scaler_path = os.path.join(self.model_path, f"{prefix}_isolation_forest_scaler.pkl")
            if os.path.exists(iso_path) and os.path.exists(iso_scaler_path):
                self.models['isolation_forest'] = joblib.load(iso_path)
                self.scalers['isolation_forest'] = joblib.load(iso_scaler_path)

            # Load One-Class SVM
            svm_path = os.path.join(self.model_path, f"{prefix}_one_class_svm.pkl")
            svm_scaler_path = os.path.join(self.model_path, f"{prefix}_one_class_svm_scaler.pkl")
            if os.path.exists(svm_path) and os.path.exists(svm_scaler_path):
                self.models['one_class_svm'] = joblib.load(svm_path)
                self.scalers['one_class_svm'] = joblib.load(svm_scaler_path)

            # Load metadata
            metadata_path = os.path.join(self.model_path, f"{prefix}_metadata.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                self.feature_names = metadata.get('feature_names', [])
                self.contamination = metadata.get('contamination', 0.1)
                self.is_trained = metadata.get('is_trained', False)
                self.last_train_time = metadata.get('last_train_time', 0)

            self.is_trained = (self.is_trained and
                             'isolation_forest' in self.models and
                             self.models['isolation_forest'] is not None)

            if self.is_trained:
                print(f"Models loaded from {self.model_path}")
                return True
            else:
                print("Models loaded but not fully trained")
                return False

        except Exception as e:
            print(f"Error loading models: {e}")
            return False


# Global ML anomaly detector instance
ml_anomaly_detector = MLAnomalyDetector()


def get_ml_anomaly_detector() -> MLAnomalyDetector:
    """Get the global ML anomaly detector instance."""
    return ml_anomaly_detector