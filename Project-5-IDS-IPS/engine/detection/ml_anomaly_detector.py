"""
ML-Based Anomaly Detection Engine for IDS/IPS
==============================================

Implements Isolation Forest algorithm for unsupervised anomaly detection
in network traffic patterns. Features include:
- Online learning with periodic retraining
- Feature extraction from packet metadata
- Model persistence and loading
- Anomaly scoring and threshold-based alerting
"""

import numpy as np
import joblib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import os
import json


class MLAnomalyDetector:
    """
    Machine Learning-based anomaly detection using Isolation Forest.

    Detects anomalous network packets by learning normal traffic patterns
    and identifying deviations that may indicate attacks.

    Attributes:
        contamination: Expected proportion of anomalies in the data (0.0-0.5)
        n_estimators: Number of trees in the forest
        max_samples: Number of samples to draw for each tree
        feature_names: Names of extracted features for debugging
        model_path: Path for saving/loading trained models
        is_trained: Flag indicating if model has been trained
        training_buffer: Buffer for collecting training data
        last_retrain: Timestamp of last model retraining
        retrain_interval: Seconds between automatic retraining
    """

    def __init__(self,
                 contamination: float = 0.1,
                 n_estimators: int = 100,
                 max_samples: str = "auto",
                 model_dir: str = "../models"):
        """
        Initialize the ML anomaly detector.

        Args:
            contamination: Expected proportion of anomalies (default: 0.1)
            n_estimators: Number of trees in forest (default: 100)
            max_samples: Samples per tree (default: "auto")
            model_dir: Directory for saving/loading models
        """
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            raise ImportError("scikit-learn is required for ML anomaly detection. Install with: pip install scikit-learn")

        self.contamination = contamination
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.model_dir = model_dir

        # Create model directory if it doesn't exist
        os.makedirs(self.model_dir, exist_ok=True)

        # Feature names for interpretability
        self.feature_names = [
            'packet_size',           # Size of packet in bytes
            'src_port',             # Source port number
            'dst_port',             # Destination port number
            'is_tcp',               # TCP protocol flag
            'is_udp',               # UDP protocol flag
            'is_icmp',              # ICMP protocol flag
            'is_arp',               # ARP protocol flag
            'has_payload',          # Whether packet has payload
            'payload_length',       # Length of payload if present
            'src_ip_internal',      # Source IP is internal network
            'dst_ip_internal',      # Destination IP is internal network
            'hour_of_day',          # Hour when packet was generated (0-23)
            'day_of_week',          # Day of week (0-6, Monday=0)
        ]

        # Initialize model
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[Any] = None  # StandardScaler if needed
        self.is_trained = False

        # Training data buffer
        self.training_buffer: List[np.ndarray] = []
        self.max_buffer_size = 1000

        # Retraining configuration
        self.last_retrain = datetime.now()
        self.retrain_interval = 3600  # 1 hour in seconds

        # Statistics
        self.stats = {
            'packets_analyzed': 0,
            'anomalies_detected': 0,
            'models_trained': 0,
            'training_samples': 0,
        }

        # Try to load existing model
        self._load_model()

    def _extract_features(self, packet_dict: Dict[str, Any]) -> np.ndarray:
        """
        Extract numerical features from a packet dictionary.

        Args:
            packet_dict: Dictionary representation of a packet

        Returns:
            numpy array of features
        """
        features = []

        # Basic packet features
        features.append(float(packet_dict.get('size', 0)))  # packet_size
        features.append(float(packet_dict.get('src_port', 0)))  # src_port
        features.append(float(packet_dict.get('dst_port', 0)))  # dst_port

        # Protocol flags (one-hot encoded)
        protocol = packet_dict.get('protocol', '').upper()
        features.append(1.0 if protocol == 'TCP' else 0.0)  # is_tcp
        features.append(1.0 if protocol == 'UDP' else 0.0)  # is_udp
        features.append(1.0 if protocol == 'ICMP' else 0.0) # is_icmp
        features.append(1.0 if protocol == 'ARP' else 0.0)  # is_arp

        # Payload features
        payload = packet_dict.get('payload', '')
        features.append(1.0 if payload else 0.0)  # has_payload
        features.append(float(len(payload)))      # payload_length

        # IP address features (simplified internal/external check)
        src_ip = packet_dict.get('src_ip', '')
        dst_ip = packet_dict.get('dst_ip', '')
        internal_prefixes = ('10.', '192.168.', '172.16.', '172.17.', '172.18.',
                           '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                           '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                           '172.29.', '172.30.', '172.31.')
        features.append(1.0 if any(src_ip.startswith(prefix) for prefix in internal_prefixes) else 0.0)  # src_ip_internal
        features.append(1.0 if any(dst_ip.startswith(prefix) for prefix in internal_prefixes) else 0.0)  # dst_ip_internal

        # Temporal features
        try:
            timestamp_str = packet_dict.get('timestamp', datetime.now().isoformat())
            # Handle various timestamp formats
            if isinstance(timestamp_str, str):
                if 'T' in timestamp_str:
                    dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            else:
                dt = timestamp_str
            features.append(float(dt.hour))           # hour_of_day
            features.append(float(dt.weekday()))      # day_of_week
        except:
            features.append(0.0)  # hour_of_day
            features.append(0.0)  # day_of_week

        return np.array(features, dtype=np.float32)

    def _ensure_model_exists(self) -> None:
        """Ensure the ML model exists, creating a default one if needed."""
        if self.model is None:
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                max_samples=self.max_samples,
                random_state=42,
                n_jobs=-1
            )

    def train(self, training_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train the anomaly detection model on provided data.

        Args:
            training_data: List of packet dictionaries for training

        Returns:
            Dictionary with training results and statistics
        """
        if not training_data:
            return {'error': 'No training data provided'}

        # Extract features from all packets
        X = np.array([self._extract_features(packet) for packet in training_data])

        # Ensure we have the model
        self._ensure_model_exists()

        # Train the model
        self.model.fit(X)
        self.is_trained = True

        # Update statistics
        self.stats['models_trained'] += 1
        self.stats['training_samples'] = len(training_data)
        self.last_retrain = datetime.now()

        # Save the model
        self._save_model()

        # Calculate training scores for feedback
        if hasattr(self.model, 'score_samples'):
            scores = self.model.score_samples(X)
            anomaly_scores = -scores  # Invert so higher = more anomalous

            return {
                'status': 'success',
                'samples_trained': len(training_data),
                'features_used': len(self.feature_names),
                'contamination': self.contamination,
                'avg_anomaly_score': float(np.mean(anomaly_scores)),
                'std_anomaly_score': float(np.std(anomaly_scores)),
                'min_anomaly_score': float(np.min(anomaly_scores)),
                'max_anomaly_score': float(np.max(anomaly_scores)),
            }
        else:
            return {
                'status': 'success',
                'samples_trained': len(training_data),
                'features_used': len(self.feature_names),
            }

    def predict(self, packet_dict: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Predict if a packet is anomalous.

        Args:
            packet_dict: Dictionary representation of a packet

        Returns:
            Tuple of (is_anomaly: bool, anomaly_score: float)
            where anomaly_score is higher for more anomalous packets
        """
        self.stats['packets_analyzed'] += 1

        # If not trained yet, return benign
        if not self.is_trained or self.model is None:
            return False, 0.0

        # Extract features
        features = self._extract_features(packet_dict).reshape(1, -1)

        # Get anomaly score (negative values = more anomalous)
        anomaly_score = float(self.model.score_samples(features)[0])
        # Convert to positive anomaly score (higher = more anomalous)
        positive_anomaly_score = -anomaly_score

        # Determine if anomalous based on contamination threshold
        # The decision function returns negative for outliers
        is_anomaly = bool(self.model.predict(features)[0] == -1)

        if is_anomaly:
            self.stats['anomalies_detected'] += 1

        return is_anomaly, positive_anomaly_score

    def add_training_sample(self, packet_dict: Dict[str, Any]) -> None:
        """
        Add a packet to the training buffer for incremental learning.

        Args:
            packet_dict: Dictionary representation of a packet to add to training buffer
        """
        features = self._extract_features(packet_dict)
        self.training_buffer.append(features)

        # Keep buffer size manageable
        if len(self.training_buffer) > self.max_buffer_size:
            self.training_buffer = self.training_buffer[-self.max_buffer_size:]

    def maybe_retrain(self) -> bool:
        """
        Check if it's time to retrain the model and do so if needed.

        Returns:
            True if retraining occurred, False otherwise
        """
        if not self.is_trained:
            return False

        now = datetime.now()
        seconds_since_retrain = (now - self.last_retrain).total_seconds()

        if seconds_since_retrain >= self.retrain_interval and len(self.training_buffer) >= 10:
            # Retrain with buffered data
            training_data = []
            for features in self.training_buffer:
                # Reconstruct a minimal packet dict for compatibility
                # In a real implementation, we'd store the full packet dict
                packet_dict = {
                    'size': features[0],
                    'src_port': features[1],
                    'dst_port': features[2],
                    'protocol': 'TCP' if features[3] == 1.0 else 'UDP' if features[4] == 1.0 else 'ICMP' if features[5] == 1.0 else 'ARP',
                    'payload': 'x' * int(features[7]) if features[6] == 1.0 else '',
                    'src_ip': '10.0.0.1' if features[9] == 1.0 else '185.15.2.14',
                    'dst_ip': '10.0.0.2' if features[10] == 1.0 else '185.15.2.14',
                    'timestamp': now.isoformat()
                }
                training_data.append(packet_dict)

            self.train(training_data)
            return True

        return False

    def _save_model(self) -> None:
        """Save the trained model to disk."""
        if self.model is not None and self.is_trained:
            try:
                model_path = os.path.join(self.model_dir, 'ids_ml_isolation_forest.pkl')
                joblib.dump(self.model, model_path)

                # Save metadata
                metadata = {
                    'contamination': self.contamination,
                    'n_estimators': self.n_estimators,
                    'max_samples': self.max_samples,
                    'feature_names': self.feature_names,
                    'trained_at': datetime.now().isoformat(),
                    'training_samples': self.stats['training_samples'],
                    'version': '1.0'
                }
                metadata_path = os.path.join(self.model_dir, 'ids_ml_metadata.json')
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)

            except Exception as e:
                print(f"Warning: Could not save ML model: {e}")

    def _load_model(self) -> None:
        """Load a pre-trained model from disk."""
        try:
            model_path = os.path.join(self.model_dir, 'ids_ml_isolation_forest.pkl')
            metadata_path = os.path.join(self.model_dir, 'ids_ml_metadata.json')

            if os.path.exists(model_path) and os.path.exists(metadata_path):
                self.model = joblib.load(model_path)
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)

                # Restore configuration
                self.contamination = metadata.get('contamination', self.contamination)
                self.n_estimators = metadata.get('n_estimators', self.n_estimators)
                self.max_samples = metadata.get('max_samples', self.max_samples)
                self.feature_names = metadata.get('feature_names', self.feature_names)
                self.stats['training_samples'] = metadata.get('training_samples', 0)

                self.is_trained = True
                self.last_retrain = datetime.fromisoformat(metadata.get('trained_at', datetime.now().isoformat()))

        except Exception as e:
            # Silently fail - will train a new model when needed
            pass

    def get_stats(self) -> Dict[str, Any]:
        """
        Get detector statistics.

        Returns:
            Dictionary of statistics
        """
        stats = self.stats.copy()
        stats['is_trained'] = self.is_trained
        stats['buffer_size'] = len(self.training_buffer)
        stats['seconds_since_retrain'] = (datetime.now() - self.last_retrain).total_seconds()
        return stats

    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """
        Get feature importance if available (not directly available in Isolation Forest).

        Returns:
            None for Isolation Forest (feature importance not directly available)
        """
        # Isolation Forest doesn't provide direct feature importance
        # Could implement permutation importance or similar if needed
        return None