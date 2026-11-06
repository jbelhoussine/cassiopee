#!/usr/bin/env python3
"""Tableau de bord de détection en quasi temps réel pour les flux SDN."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

import joblib
import pandas as pd
import streamlit as st


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_PATH = BASE_DIR / "random_forest_model.pkl"
DEFAULT_ENCODER_PATH = BASE_DIR / "label_encoder.pkl"
DEFAULT_SCALER_PATH = BASE_DIR / "data" / "prepared" / "scaler_stats.json"
DEFAULT_DATA_DIR = BASE_DIR / "data"
NUMERIC_FEATURES = [
    "packet_count",
    "byte_count",
    "duration",
    "packets_per_second",
    "bytes_per_second",
]


def _load_json(path: Path) -> Dict[str, Dict[str, float]]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


@st.cache_resource(show_spinner=False)
def load_artifacts(model_path: str, encoder_path: str, scaler_path: str):
    model_file = Path(model_path)
    encoder_file = Path(encoder_path)
    scaler_file = Path(scaler_path)

    missing = [str(path) for path in [model_file, encoder_file, scaler_file] if not path.exists()]
    if missing:
        raise FileNotFoundError("Artefacts manquants: " + ", ".join(missing))

    model = joblib.load(model_file)
    encoder = joblib.load(encoder_file)
    scaler_stats = _load_json(scaler_file)
    return model, encoder, scaler_stats


def find_latest_csv(data_dir: Path) -> Optional[Path]:
    candidates = sorted(
        [path for path in data_dir.glob("network_traffic_*.csv") if path.is_file()],
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _normalize_value(value: float, low: float, high: float) -> float:
    if high <= low:
        return 0.0
    return max(0.0, min(1.0, (value - low) / (high - low)))


def build_model_input(raw_metrics: Dict[str, float], scaler_stats: Dict[str, Dict[str, float]]) -> pd.DataFrame:
    payload = {}
    for feature in NUMERIC_FEATURES:
        if feature not in scaler_stats:
            raise KeyError(f"Statistiques de scaling manquantes pour: {feature}")
        low = float(scaler_stats[feature]["q01"])
        high = float(scaler_stats[feature]["q99"])
        payload[f"{feature}_norm"] = [_normalize_value(float(raw_metrics.get(feature, 0.0)), low, high)]
    return pd.DataFrame(payload)


def predict_metrics(model, encoder, scaler_stats, raw_metrics: Dict[str, float]):
    frame = build_model_input(raw_metrics, scaler_stats)
    predicted_index = int(model.predict(frame)[0])
    predicted_label = encoder.inverse_transform([predicted_index])[0]

    danger_probability = None
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(frame)[0]
        labels = list(encoder.inverse_transform(model.classes_))
        attack_probability = 0.0
        for label, probability in zip(labels, probabilities):
            if str(label).lower() != "normal":
                attack_probability += float(probability)
        danger_probability = attack_probability

    is_dangerous = str(predicted_label).lower() != "normal"
    return predicted_label, is_dangerous, danger_probability, frame.iloc[0].to_dict()


def normalize_dataframe(df: pd.DataFrame, scaler_stats: Dict[str, Dict[str, float]]) -> pd.DataFrame:
    out = df.copy()
    for feature in NUMERIC_FEATURES:
        if feature not in out.columns:
            out[feature] = 0.0
        low = float(scaler_stats[feature]["q01"])
        high = float(scaler_stats[feature]["q99"])
        out[f"{feature}_norm"] = out[feature].astype(float).apply(lambda value: _normalize_value(value, low, high))
    return out


def predict_dataframe(model, encoder, scaler_stats, df: pd.DataFrame) -> pd.DataFrame:
    normalized = normalize_dataframe(df, scaler_stats)
    feature_frame = normalized[[f"{feature}_norm" for feature in NUMERIC_FEATURES]]
    predicted_indexes = model.predict(feature_frame)
    predicted_labels = encoder.inverse_transform(predicted_indexes)

    result = df.copy().reset_index(drop=True)
    result["predicted_label"] = predicted_labels
    result["status"] = result["predicted_label"].apply(
        lambda label: "dangereux" if str(label).lower() != "normal" else "normal"
    )

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(feature_frame)
        labels = list(encoder.inverse_transform(model.classes_))
        danger_scores = []
        for row in probabilities:
            score = 0.0
            for label, probability in zip(labels, row):
                if str(label).lower() != "normal":
                    score += float(probability)
            danger_scores.append(score)
        result["danger_probability"] = danger_scores
    return result


# Simulation helpers removed to simplify the UI (focus on 'Derniers flux')


def read_traffic_file(path: Path, limit: int = 25) -> pd.DataFrame:
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()

    try:
        df = pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()

    if df.empty:
        return df

    required_columns = {"packet_count", "byte_count", "duration", "packets_per_second", "bytes_per_second"}
    if not required_columns.issubset(df.columns):
        return pd.DataFrame()

    return df.tail(limit).reset_index(drop=True)


def render_artifact_status(model_path: Path, encoder_path: Path, scaler_path: Path) -> None:
    missing = [path for path in [model_path, encoder_path, scaler_path] if not path.exists()]
    if missing:
        st.error(
            "L'interface ne peut pas démarrer tant que les artefacts suivants n'existent pas :\n"
            + "\n".join(f"- {path}" for path in missing)
        )
        st.stop()


def render_latest_csv_preview(
    data_dir: Path,
    latest_limit: int,
    model,
    encoder,
    scaler_stats,
) -> None:
    latest_csv = find_latest_csv(data_dir)
    if latest_csv is None:
        st.info("Aucun fichier `network_traffic_*.csv` trouvé dans le dossier de données.")
        return

    if latest_csv.stat().st_size == 0:
        st.info(f"Le fichier {latest_csv.name} existe mais il est encore vide. Attends quelques secondes.")
        return

    st.write(f"Dernier fichier détecté: {latest_csv}")
    live_df = read_traffic_file(latest_csv, limit=latest_limit)
    if live_df.empty:
        st.info("Le fichier détecté ne contient pas encore de lignes exploitables.")
        return

    prediction_df = predict_dataframe(model, encoder, scaler_stats, live_df)
    display_columns = [
        col
        for col in [
            "timestamp",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "packet_count",
            "byte_count",
            "duration",
            "packets_per_second",
            "bytes_per_second",
            "label",
            "predicted_label",
            "status",
            "danger_probability",
        ]
        if col in prediction_df.columns
    ]
    st.dataframe(prediction_df[display_columns], use_container_width=True)
    dangerous_count = int((prediction_df["status"] == "dangereux").sum())
    normal_count = int((prediction_df["status"] == "normal").sum())
    col_a, col_b = st.columns(2)
    col_a.metric("Flux dangereux", dangerous_count)
    col_b.metric("Flux normaux", normal_count)


def main() -> None:
    st.set_page_config(page_title="Détection temps réel SDN", page_icon="🛡️", layout="wide")

    st.title("Détection temps réel des flux SDN")
    st.caption(
        "Le modèle Random Forest est chargé depuis les fichiers `.pkl`, puis appliqué aux métriques brutes du contrôleur après normalisation avec `scaler_stats.json`."
    )

    with st.sidebar:
        st.header("Configuration")
        model_path = st.text_input("Modèle", value=str(DEFAULT_MODEL_PATH))
        encoder_path = st.text_input("Encodeur", value=str(DEFAULT_ENCODER_PATH))
        scaler_path = st.text_input("Scalage", value=str(DEFAULT_SCALER_PATH))
        data_dir = st.text_input("Répertoire des flux", value=str(DEFAULT_DATA_DIR))
        latest_limit = st.slider("Nombre de lignes à afficher", min_value=5, max_value=100, value=20, step=5)
        auto_refresh = st.toggle("Rafraîchissement automatique", value=True)
        refresh_seconds = st.slider("Intervalle de rafraîchissement (s)", min_value=1, max_value=30, value=5, step=1)

    render_artifact_status(Path(model_path), Path(encoder_path), Path(scaler_path))
    model, encoder, scaler_stats = load_artifacts(model_path, encoder_path, scaler_path)

    if auto_refresh:
        try:
            autorefresh = getattr(st, "autorefresh", None)
            if callable(autorefresh):
                autorefresh(interval=refresh_seconds * 1000, key="mininet_live_refresh")
        except Exception:
            st.caption("Rafraîchissement automatique indisponible dans cette version de Streamlit, utilise le bouton Actualiser.")

    tab_live, tab_mininet = st.tabs(["Derniers flux", "Mininet Live"]) 

    with tab_live:
        st.subheader("Flux récents capturés par le contrôleur")
        if st.button("Actualiser l'affichage"):
            st.rerun()
        render_latest_csv_preview(Path(data_dir), latest_limit, model, encoder, scaler_stats)

    with tab_mininet:
        st.subheader("Mininet Live — lancer l'expérience et suivre les flux")
        st.write(
            "Lance l'expérience Mininet dans un terminal avec `sudo ./scripts/start_mininet_experiment.sh`, "
            "puis ouvre cette interface dans un autre terminal avec `streamlit run scripts/realtime_detection_dashboard.py`."
        )

        st.markdown("**Terminal 1 : Mininet / contrôleur**")
        st.code("sudo ./scripts/start_mininet_experiment.sh", language="bash")

        st.markdown("**Terminal 2 : interface de détection**")
        st.code("streamlit run scripts/realtime_detection_dashboard.py", language="bash")

        st.info("L'interface ne lance rien elle-même : exécute d'abord le script Mininet dans un terminal, puis ouvre Streamlit dans un autre.")

        if st.button("Actualiser le dernier CSV"):
            latest_csv = find_latest_csv(Path(DEFAULT_DATA_DIR))
            if latest_csv is None:
                st.info("Aucun fichier network_traffic_*.csv trouvé. Lancer l'expérience depuis un terminal d'abord.")
            else:
                st.success(f"Dernier fichier trouvé: {latest_csv}")
                st.dataframe(read_traffic_file(latest_csv, limit=50), use_container_width=True)

        st.markdown("**Vue live auto-actualisée**")
        render_latest_csv_preview(Path(data_dir), latest_limit, model, encoder, scaler_stats)

    st.caption(
        "Pour une vraie détection continue, lance le contrôleur Ryu puis rafraîchis cette page sur le dernier fichier CSV généré."
    )


if __name__ == "__main__":
    main()