import unittest
from pathlib import Path
import tempfile

import numpy as np
import pandas as pd

from src.collectors.network_collector import ProcessNetworkInfo
from src.collectors.process_collector import ProcessInfo
from src.detection.ml_fusion import apply_ml_signal
from src.detection.scoring import ProcessScore
from src.ml.dataset_generator import generate_enterprise_dataset, generate_synthetic_dataset
from src.ml.feature_extractor import FEATURE_NAMES, ProcessFeatureExtractor
from src.ml.model import CryptoJackModel
from src.ml.model_registry import load_model, save_model
from src.ml.real_dataset_loader import (
    build_enterprise_dataset,
    generate_cryptic_bytes_dataset,
    generate_minos_benchmark_dataset,
)
from src.ml.trainer import train_and_evaluate


class TestMLFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = ProcessFeatureExtractor(keywords=["xmrig", "coinhive", "stratum", "nicehash"])

    def test_feature_names_constant(self):
        self.assertEqual(
            FEATURE_NAMES,
            [
                "cpu_percent",
                "memory_percent",
                "cmdline_length",
                "network_connections_count",
                "suspicious_keyword_count",
            ],
        )

    def test_extract_from_process_info_dataclass(self):
        proc = ProcessInfo(
            pid=1234,
            name="xmrig.exe",
            path="C:\\tools\\xmrig.exe",
            cmdline="xmrig.exe --url=stratum+tcp://pool:3333 -u wallet",
            cpu_percent=85.5,
            memory_percent=12.3,
        )
        net_map = {
            1234: ProcessNetworkInfo(
                pid=1234,
                local_ports=[54321],
                remote_ports=[3333],
                remote_addresses=["192.168.1.100:3333"],
                statuses=["ESTABLISHED"],
            )
        }

        features = self.extractor.extract(proc, net_map)
        self.assertAlmostEqual(features["cpu_percent"], 85.5)
        self.assertAlmostEqual(features["memory_percent"], 12.3)
        self.assertEqual(features["cmdline_length"], len(proc.cmdline))
        self.assertEqual(features["network_connections_count"], 1)
        self.assertGreaterEqual(features["suspicious_keyword_count"], 2)  # xmrig, stratum

    def test_extract_from_dict(self):
        proc_dict = {
            "pid": 5678,
            "name": "chrome.exe",
            "cmdline": "chrome.exe --profile-directory=Default",
            "cpu_percent": 3.2,
            "memory_percent": 8.0,
        }
        features = self.extractor.extract(proc_dict, network_data=2)
        self.assertAlmostEqual(features["cpu_percent"], 3.2)
        self.assertAlmostEqual(features["memory_percent"], 8.0)
        self.assertEqual(features["cmdline_length"], len(proc_dict["cmdline"]))
        self.assertEqual(features["network_connections_count"], 2)
        self.assertEqual(features["suspicious_keyword_count"], 0)

    def test_extract_vector(self):
        proc = ProcessInfo(
            pid=999,
            name="miner.exe",
            path="C:\\miner.exe",
            cmdline="miner.exe nicehash",
            cpu_percent=90.0,
            memory_percent=15.0,
        )
        vec = self.extractor.extract_vector(proc, network_data=1)
        self.assertIsInstance(vec, list)
        self.assertEqual(len(vec), 5)
        self.assertEqual(vec[0], 90.0)
        self.assertEqual(vec[1], 15.0)
        self.assertEqual(vec[2], len("miner.exe nicehash"))
        self.assertEqual(vec[3], 1.0)
        self.assertEqual(vec[4], 1.0)  # nicehash

    def test_missing_or_empty_telemetry(self):
        features = self.extractor.extract({})
        self.assertEqual(features["cpu_percent"], 0.0)
        self.assertEqual(features["memory_percent"], 0.0)
        self.assertEqual(features["cmdline_length"], 0)
        self.assertEqual(features["network_connections_count"], 0)
        self.assertEqual(features["suspicious_keyword_count"], 0)


class TestMLDatasetGenerator(unittest.TestCase):
    def test_generate_synthetic_dataset_structure_and_constraints(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out_file = Path(temp_dir) / "test_dataset.csv"
            df = generate_synthetic_dataset(
                output_path=out_file,
                benign_count=200,
                malicious_count=100,
                random_seed=123,
            )

            self.assertTrue(out_file.exists())
            self.assertEqual(len(df), 300)
            self.assertListEqual(
                list(df.columns),
                [
                    "cpu_percent",
                    "memory_percent",
                    "cmdline_length",
                    "network_connections_count",
                    "suspicious_keyword_count",
                    "label",
                ],
            )

            benign_df = df[df["label"] == "BENIGN"]
            self.assertEqual(len(benign_df), 200)
            self.assertTrue((benign_df["suspicious_keyword_count"] == 0).all())
            self.assertTrue((benign_df["cpu_percent"] <= 100.0).all())

            malicious_df = df[df["label"] == "MALICIOUS"]
            self.assertEqual(len(malicious_df), 100)
            self.assertTrue((malicious_df["cpu_percent"] > 70.0).all())
            self.assertTrue((malicious_df["network_connections_count"] >= 1).all())
            self.assertTrue((malicious_df["suspicious_keyword_count"] >= 1).all())

    def test_generate_minos_benchmark_dataset(self):
        df = generate_minos_benchmark_dataset(count=200, benign_ratio=0.6, random_seed=42)
        self.assertEqual(len(df), 200)
        self.assertListEqual(list(df.columns), FEATURE_NAMES + ["label"])

        benign = df[df["label"] == "BENIGN"]
        malicious = df[df["label"] == "MALICIOUS"]
        self.assertEqual(len(benign), 120)
        self.assertEqual(len(malicious), 80)
        self.assertTrue((benign["suspicious_keyword_count"] == 0).all())
        self.assertTrue((malicious["suspicious_keyword_count"] >= 1).all())
        self.assertTrue((malicious["network_connections_count"] >= 1).all())

    def test_generate_cryptic_bytes_dataset(self):
        df = generate_cryptic_bytes_dataset(count=200, benign_ratio=0.6, random_seed=42)
        self.assertEqual(len(df), 200)
        self.assertListEqual(list(df.columns), FEATURE_NAMES + ["label"])

        benign = df[df["label"] == "BENIGN"]
        malicious = df[df["label"] == "MALICIOUS"]
        self.assertEqual(len(benign), 120)
        self.assertEqual(len(malicious), 80)
        self.assertTrue((benign["suspicious_keyword_count"] == 0).all())
        self.assertTrue((malicious["suspicious_keyword_count"] >= 1).all())

    def test_build_and_generate_enterprise_dataset(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out_file = Path(temp_dir) / "enterprise_test.csv"
            df = build_enterprise_dataset(
                output_path=out_file,
                synthetic_benign=100,
                synthetic_malicious=50,
                minos_count=50,
                cryptic_bytes_count=50,
                random_seed=42,
            )

            self.assertTrue(out_file.exists())
            self.assertEqual(len(df), 250)  # 150 + 50 + 50
            self.assertListEqual(list(df.columns), FEATURE_NAMES + ["label"])

            # Test generator proxy function
            out_file2 = Path(temp_dir) / "enterprise_test2.csv"
            df2 = generate_enterprise_dataset(
                output_path=out_file2,
                synthetic_benign=50,
                synthetic_malicious=25,
                minos_count=25,
                cryptic_bytes_count=25,
                random_seed=42,
            )
            self.assertTrue(out_file2.exists())
            self.assertEqual(len(df2), 125)


class TestCryptoJackModel(unittest.TestCase):
    def test_model_train_and_predict(self):
        model = CryptoJackModel(n_estimators=10, random_state=42)
        X = np.array([
            [5.0, 4.0, 50, 0, 0],
            [12.0, 8.0, 80, 1, 0],
            [85.0, 30.0, 200, 2, 2],
            [95.0, 40.0, 250, 4, 3],
        ])
        y = np.array([0, 0, 1, 1])

        model.train(X, y)
        self.assertTrue(model.is_trained)

        preds = model.predict(X)
        self.assertEqual(len(preds), 4)

        probas = model.predict_proba(X)
        self.assertEqual(probas.shape, (4, 2))

        risk = model.predict_risk_score(X[:1])
        self.assertIsInstance(risk, float)
        self.assertLessEqual(risk, 0.5)


class TestModelRegistry(unittest.TestCase):
    def test_save_and_load_model(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_file = Path(temp_dir) / "test_model.pkl"
            model = CryptoJackModel(n_estimators=5, random_state=42)
            X = np.array([[10, 5, 40, 0, 0], [90, 30, 200, 3, 2]])
            y = np.array([0, 1])
            model.train(X, y)

            saved_path = save_model(model, model_file)
            self.assertTrue(saved_path.exists())

            loaded = load_model(saved_path)
            self.assertIsInstance(loaded, CryptoJackModel)
            preds = loaded.predict(X)
            self.assertTrue((preds == y).all())

    def test_load_nonexistent_model_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_model("nonexistent_model_path_12345.pkl")


class TestMLTrainer(unittest.TestCase):
    def test_train_and_evaluate(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            data_file = Path(temp_dir) / "synthetic_data.csv"
            model_file = Path(temp_dir) / "trained_model.pkl"

            generate_synthetic_dataset(
                output_path=data_file,
                benign_count=100,
                malicious_count=50,
                random_seed=42,
            )

            results = train_and_evaluate(
                data_path=data_file,
                model_save_path=model_file,
                test_size=0.2,
                random_state=42,
            )

            self.assertTrue(model_file.exists())
            self.assertIn("metrics", results)
            metrics = results["metrics"]
            self.assertGreaterEqual(metrics["accuracy"], 0.95)
            self.assertGreaterEqual(metrics["f1"], 0.95)


class TestHybridRiskFusion(unittest.TestCase):
    def setUp(self):
        self.proc = ProcessInfo(
            pid=1111,
            name="xmrig.exe",
            path="C:\\tools\\xmrig.exe",
            cmdline="xmrig.exe --url=stratum+tcp://pool.minexmr.com:3333",
            cpu_percent=88.0,
            memory_percent=22.0,
        )
        self.network = ProcessNetworkInfo(
            pid=1111,
            local_ports=[55555],
            remote_ports=[3333],
            remote_addresses=["192.168.1.1:3333"],
            statuses=["ESTABLISHED"],
        )

    def test_apply_ml_signal_high_confidence_elevates_score(self):
        class MockHighRiskModel:
            def predict_risk_score(self, X):
                return [0.85]

        score = ProcessScore(
            pid=1111,
            name="xmrig.exe",
            path="C:\\tools\\xmrig.exe",
            cmdline="xmrig.exe",
            cpu_percent=88.0,
            memory_percent=22.0,
            local_ports=[55555],
            risk_score=30.0,
            reasons=["high CPU usage"],
        )

        conf = apply_ml_signal(score, self.proc, self.network, MockHighRiskModel())
        self.assertAlmostEqual(conf, 0.85)
        self.assertAlmostEqual(score.ml_confidence, 0.85)
        self.assertAlmostEqual(score.risk_score, 85.0)
        self.assertTrue(any("ML Detection: High Confidence" in r for r in score.reasons))

    def test_apply_ml_signal_heuristic_dominance(self):
        class MockLowRiskModel:
            def predict_risk_score(self, X):
                return [0.25]

        score = ProcessScore(
            pid=1111,
            name="xmrig.exe",
            path="C:\\tools\\xmrig.exe",
            cmdline="xmrig.exe",
            cpu_percent=88.0,
            memory_percent=22.0,
            local_ports=[55555],
            risk_score=75.0,
            reasons=["known miner executable name", "high CPU usage"],
        )

        conf = apply_ml_signal(score, self.proc, self.network, MockLowRiskModel())
        self.assertAlmostEqual(conf, 0.25)
        self.assertAlmostEqual(score.ml_confidence, 0.25)
        # Risk score remains 75.0 since heuristic (75.0) > ML scaled (25.0)
        self.assertAlmostEqual(score.risk_score, 75.0)
        self.assertFalse(any("ML Detection: High Confidence" in r for r in score.reasons))

    def test_apply_ml_signal_with_none_model(self):
        score = ProcessScore(
            pid=1111,
            name="app.exe",
            path="C:\\app.exe",
            cmdline="app.exe",
            cpu_percent=5.0,
            memory_percent=2.0,
            local_ports=[],
            risk_score=10.0,
            reasons=[],
        )
        conf = apply_ml_signal(score, self.proc, self.network, None)
        self.assertEqual(conf, 0.0)
        self.assertEqual(score.ml_confidence, 0.0)
        self.assertEqual(score.risk_score, 10.0)


if __name__ == "__main__":
    unittest.main()

