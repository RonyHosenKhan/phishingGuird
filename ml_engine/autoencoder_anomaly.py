"""
PhishGuard AI - Deep Autoencoder Anomaly Detector
Unsupervised Neural Model for Zero-Day Threat Detection.
Trained exclusively on legitimate communication payloads.
Reconstruction error spikes indicate novel/zero-day phishing attacks.
"""

import json
import os
import numpy as np


class AutoencoderAnomalyDetector:
    def __init__(self, input_dim: int = 16, hidden_dim: int = 8, latent_dim: int = 4):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim

        # Xavier/He weight initialization
        np.random.seed(42)
        self.W1 = np.random.randn(input_dim, hidden_dim) * np.sqrt(2.0 / input_dim)
        self.b1 = np.zeros(hidden_dim)

        self.W2 = np.random.randn(hidden_dim, latent_dim) * np.sqrt(2.0 / hidden_dim)
        self.b2 = np.zeros(latent_dim)

        self.W3 = np.random.randn(latent_dim, hidden_dim) * np.sqrt(2.0 / latent_dim)
        self.b3 = np.zeros(hidden_dim)

        self.W4 = np.random.randn(hidden_dim, input_dim) * np.sqrt(2.0 / hidden_dim)
        self.b4 = np.zeros(input_dim)

        self.threshold = 0.045  # Default tuned threshold epsilon
        self.is_trained = False

    def relu(self, x):
        return np.maximum(0, x)

    def relu_deriv(self, x):
        return (x > 0).astype(float)

    def encode(self, x: np.ndarray) -> np.ndarray:
        """Projects input into lower-dimensional bottleneck latent space."""
        h1 = self.relu(np.dot(x, self.W1) + self.b1)
        z = np.dot(h1, self.W2) + self.b2
        return z

    def decode(self, z: np.ndarray) -> np.ndarray:
        """Reconstructs original input from latent code."""
        h2 = self.relu(np.dot(z, self.W3) + self.b3)
        out = np.dot(h2, self.W4) + self.b4
        return out

    def forward(self, x: np.ndarray):
        """Full pass through autoencoder: x -> encoder -> code -> decoder -> x_hat"""
        x = np.asarray(x, dtype=np.float64)
        h1 = self.relu(np.dot(x, self.W1) + self.b1)
        z = np.dot(h1, self.W2) + self.b2
        h2 = self.relu(np.dot(z, self.W3) + self.b3)
        x_hat = np.dot(h2, self.W4) + self.b4
        return x_hat, (h1, z, h2)

    def compute_reconstruction_error(self, x: np.ndarray, x_hat: np.ndarray):
        """Mean Squared Error (MSE) reconstruction loss."""
        diff = x - x_hat
        feature_errors = diff ** 2
        mse = np.mean(feature_errors)
        return float(mse), feature_errors

    def train(self, X_legit: np.ndarray, epochs: int = 120, lr: float = 0.015, batch_size: int = 16):
        """
        Trains the Autoencoder exclusively on legitimate (non-phishing) samples.
        Minimizes MSE reconstruction loss so legitimate patterns reconstruct smoothly.
        """
        X = np.asarray(X_legit, dtype=np.float64)
        n_samples = len(X)

        for epoch in range(epochs):
            indices = np.random.permutation(n_samples)
            X_shuffled = X[indices]

            for i in range(0, n_samples, batch_size):
                batch = X_shuffled[i:i + batch_size]
                batch_size_actual = len(batch)

                # Forward
                h1 = self.relu(np.dot(batch, self.W1) + self.b1)
                z = np.dot(h1, self.W2) + self.b2
                h2 = self.relu(np.dot(z, self.W3) + self.b3)
                x_hat = np.dot(h2, self.W4) + self.b4

                # Backprop (MSE gradient)
                loss_grad = 2.0 * (x_hat - batch) / (batch_size_actual * self.input_dim)

                grad_W4 = np.dot(h2.T, loss_grad)
                grad_b4 = np.sum(loss_grad, axis=0)

                grad_h2 = np.dot(loss_grad, self.W4.T) * self.relu_deriv(h2)
                grad_W3 = np.dot(z.T, grad_h2)
                grad_b3 = np.sum(grad_h2, axis=0)

                grad_z = np.dot(grad_h2, self.W3.T)
                grad_W2 = np.dot(h1.T, grad_z)
                grad_b2 = np.sum(grad_z, axis=0)

                grad_h1 = np.dot(grad_z, self.W2.T) * self.relu_deriv(h1)
                grad_W1 = np.dot(batch.T, grad_h1)
                grad_b1 = np.sum(grad_h1, axis=0)

                # Update weights
                self.W4 -= lr * grad_W4
                self.b4 -= lr * grad_b4
                self.W3 -= lr * grad_W3
                self.b3 -= lr * grad_b3
                self.W2 -= lr * grad_W2
                self.b2 -= lr * grad_b2
                self.W1 -= lr * grad_W1
                self.b1 -= lr * grad_b1

        # Calibrate threshold epsilon: 95th percentile of legitimate reconstruction loss
        all_recon, _ = self.forward(X)
        errors = [self.compute_reconstruction_error(X[i], all_recon[i])[0] for i in range(len(X))]
        self.threshold = float(np.percentile(errors, 95)) + 0.015
        self.is_trained = True
        return self.threshold

    def detect_anomaly(self, feature_vector: list, feature_names: list = None) -> dict:
        """
        Infers whether a payload is anomalous (Zero-Day threat).
        Returns reconstruction loss, threshold, anomaly flag, and feature-by-feature diffs.
        """
        x = np.array(feature_vector, dtype=np.float64)
        x_hat, _ = self.forward(x.reshape(1, -1))
        x_hat = x_hat[0]

        mse, feature_errors = self.compute_reconstruction_error(x, x_hat)
        is_anomaly = bool(mse > self.threshold)

        # Scale anomaly risk score (0 to 100%)
        anomaly_ratio = mse / (self.threshold + 1e-6)
        if anomaly_ratio < 1.0:
            anomaly_score = (anomaly_ratio * 40.0)  # low / normal
        else:
            anomaly_score = min(100.0, 50.0 + (anomaly_ratio - 1.0) * 35.0)

        # Map top reconstructed feature deviations
        deviations = []
        names = feature_names or [f"Feature_{i}" for i in range(self.input_dim)]
        for i, (name, err, orig, recon) in enumerate(zip(names, feature_errors, x, x_hat)):
            deviations.append({
                "feature": name,
                "input_val": round(float(orig), 3),
                "reconstructed_val": round(float(recon), 3),
                "squared_error": round(float(err), 4)
            })
        deviations.sort(key=lambda item: item["squared_error"], reverse=True)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(float(anomaly_score), 2),
            "reconstruction_error": round(mse, 5),
            "threshold": round(self.threshold, 5),
            "top_deviations": deviations[:5],
            "all_feature_errors": [round(float(e), 4) for e in feature_errors]
        }

    def save_weights(self, filepath: str):
        """Saves trained model matrices to JSON for fast cross-platform deployment."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        data = {
            "input_dim": self.input_dim,
            "hidden_dim": self.hidden_dim,
            "latent_dim": self.latent_dim,
            "threshold": self.threshold,
            "W1": self.W1.tolist(),
            "b1": self.b1.tolist(),
            "W2": self.W2.tolist(),
            "b2": self.b2.tolist(),
            "W3": self.W3.tolist(),
            "b3": self.b3.tolist(),
            "W4": self.W4.tolist(),
            "b4": self.b4.tolist()
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def load_weights(self, filepath: str):
        """Loads weights from JSON."""
        if not os.path.exists(filepath):
            return False
        with open(filepath, "r") as f:
            data = json.load(f)
        self.input_dim = data["input_dim"]
        self.hidden_dim = data["hidden_dim"]
        self.latent_dim = data["latent_dim"]
        self.threshold = data["threshold"]
        self.W1 = np.array(data["W1"])
        self.b1 = np.array(data["b1"])
        self.W2 = np.array(data["W2"])
        self.b2 = np.array(data["b2"])
        self.W3 = np.array(data["W3"])
        self.b3 = np.array(data["b3"])
        self.W4 = np.array(data["W4"])
        self.b4 = np.array(data["b4"])
        self.is_trained = True
        return True
