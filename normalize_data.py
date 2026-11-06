#!/usr/bin/env python3
"""
Normalisation du dataset SDN pour entrainement IA sans fuite de donnees.

Points importants:
- Le scaling est appris uniquement sur le train set.
- Le split est stratifie par label pour limiter le biais de distribution.
- Les outliers sont limites via quantiles (robust scaling clippe [0, 1]).
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Tuple

import pandas as pd


NUMERIC_FEATURES = [
    "packet_count",
    "byte_count",
    "duration",
    "packets_per_second",
    "bytes_per_second",
]


def load_dataset(filepath: str) -> pd.DataFrame:
    """Charge un CSV de trafic SDN."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Fichier non trouve: {filepath}")

    df = pd.read_csv(filepath)
    if df.empty:
        raise ValueError("Le dataset est vide")
    return df


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Nettoie les donnees de base avant split/scaling."""
    data = df.copy()

    if "label" not in data.columns:
        raise ValueError("La colonne 'label' est obligatoire")

    if "src_ip" in data.columns and "dst_ip" in data.columns:
        mask_unknown = (data["src_ip"] == "unknown") & (data["dst_ip"] == "unknown")
        data = data[~mask_unknown].copy()

    for col in NUMERIC_FEATURES + ["src_port", "dst_port"]:
        if col in data.columns:
            data[col] = pd.to_numeric(data[col], errors="coerce")

    mandatory = [col for col in ["label", "packet_count", "byte_count"] if col in data.columns]
    data = data.dropna(subset=mandatory)

    for col in ["duration", "packet_count", "byte_count"]:
        if col in data.columns:
            data = data[data[col] >= 0]

    data = data.drop_duplicates().reset_index(drop=True)

    if data.empty:
        raise ValueError("Dataset vide apres nettoyage")

    return data


def train_val_test_split_stratified(
    df: pd.DataFrame,
    label_col: str = "label",
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    seed: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split stratifie train/val/test sans dependance externe."""
    if train_ratio <= 0 or val_ratio <= 0 or train_ratio + val_ratio >= 1:
        raise ValueError("Ratios invalides: il faut 0 < train,val et train+val < 1")

    test_ratio = 1.0 - train_ratio - val_ratio
    parts: List[Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]] = []

    for _, grp in df.groupby(label_col, dropna=False):
        g = grp.sample(frac=1.0, random_state=seed)
        n = len(g)

        n_train = int(round(n * train_ratio))
        n_val = int(round(n * val_ratio))
        n_test = n - n_train - n_val

        # Garantit au moins 1 ligne par split si possible (petits groupes)
        if n >= 3:
            n_train = max(1, n_train)
            n_val = max(1, n_val)
            n_test = max(1, n_test)
            total = n_train + n_val + n_test
            if total > n:
                overflow = total - n
                for _ in range(overflow):
                    if n_train >= n_val and n_train >= n_test and n_train > 1:
                        n_train -= 1
                    elif n_val >= n_test and n_val > 1:
                        n_val -= 1
                    elif n_test > 1:
                        n_test -= 1

        train_end = n_train
        val_end = n_train + n_val

        parts.append((g.iloc[:train_end], g.iloc[train_end:val_end], g.iloc[val_end:]))

    train_df = pd.concat([p[0] for p in parts], ignore_index=True).sample(frac=1.0, random_state=seed)
    val_df = pd.concat([p[1] for p in parts], ignore_index=True).sample(frac=1.0, random_state=seed)
    test_df = pd.concat([p[2] for p in parts], ignore_index=True).sample(frac=1.0, random_state=seed)

    # Evite un split vide en cas de dataset minuscule
    if train_df.empty or val_df.empty or test_df.empty:
        shuffled = df.sample(frac=1.0, random_state=seed)
        n = len(shuffled)
        n_train = max(1, int(round(n * train_ratio)))
        n_val = max(1, int(round(n * val_ratio)))
        n_train = min(n_train, n - 2)
        n_val = min(n_val, n - n_train - 1)
        train_df = shuffled.iloc[:n_train].copy()
        val_df = shuffled.iloc[n_train : n_train + n_val].copy()
        test_df = shuffled.iloc[n_train + n_val :].copy()

    return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)


def fit_robust_stats(train_df: pd.DataFrame, feature_cols: List[str]) -> Dict[str, Dict[str, float]]:
    """Calcule les bornes de scaling robustes sur le train set uniquement."""
    stats: Dict[str, Dict[str, float]] = {}
    for col in feature_cols:
        if col not in train_df.columns:
            continue
        q_low = float(train_df[col].quantile(0.01))
        q_high = float(train_df[col].quantile(0.99))
        if q_high <= q_low:
            q_low = float(train_df[col].min())
            q_high = float(train_df[col].max())
        if q_high <= q_low:
            q_high = q_low + 1.0
        stats[col] = {"q01": q_low, "q99": q_high}
    return stats


def apply_robust_scaling(df: pd.DataFrame, stats: Dict[str, Dict[str, float]]) -> pd.DataFrame:
    """Applique un scaling [0, 1] avec clipping selon stats de train."""
    out = df.copy()
    for col, values in stats.items():
        if col not in out.columns:
            continue
        low = values["q01"]
        high = values["q99"]
        scaled = (out[col] - low) / (high - low)
        out[f"{col}_norm"] = scaled.clip(lower=0.0, upper=1.0)
    return out


def print_balance(df: pd.DataFrame, name: str) -> None:
    """Affiche la distribution des classes pour verifier le biais."""
    counts = df["label"].value_counts(dropna=False)
    print(f"\n{name}: {len(df)} lignes")
    for label, count in counts.items():
        pct = 100.0 * count / len(df)
        print(f"  - {label}: {count} ({pct:.1f}%)")


def ensure_dir(path: str) -> None:
    """Cree le dossier parent si necessaire."""
    os.makedirs(path, exist_ok=True)


def export_splits(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    out_dir: str,
) -> None:
    """Exporte les splits normalises."""
    ensure_dir(out_dir)
    train_path = os.path.join(out_dir, "train_normalized.csv")
    val_path = os.path.join(out_dir, "val_normalized.csv")
    test_path = os.path.join(out_dir, "test_normalized.csv")

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    print(f"\nExports:")
    print(f"  - {train_path}")
    print(f"  - {val_path}")
    print(f"  - {test_path}")


def build_random_forest_ready_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Construit un dataset compatible avec random_forest.py."""
    out = df.copy()

    # random_forest.py lit ces colonnes brutes; on remplace donc par les valeurs normalisees.
    for col in NUMERIC_FEATURES:
        norm_col = f"{col}_norm"
        if norm_col in out.columns:
            out[col] = out[norm_col]

    required_cols = [c for c in NUMERIC_FEATURES + ["label"] if c in out.columns]
    if "label" not in required_cols or len(required_cols) < 2:
        raise ValueError("Colonnes insuffisantes pour random_forest.py (label + features)")

    return out[required_cols].dropna().reset_index(drop=True)


def export_random_forest_csv(df: pd.DataFrame, output_path: str) -> str:
    """Exporte un CSV directement consommable par random_forest.py."""
    parent = os.path.dirname(output_path)
    if parent:
        ensure_dir(parent)
    df.to_csv(output_path, index=False)
    return output_path


def save_scaler_stats(stats: Dict[str, Dict[str, float]], out_dir: str) -> str:
    """Sauvegarde les stats de scaling pour inference future."""
    ensure_dir(out_dir)
    path = os.path.join(out_dir, "scaler_stats.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalisation robuste du dataset SDN (sans fuite de donnees)."
    )
    parser.add_argument("--input", default="data/network_traffic.csv", help="CSV source")
    parser.add_argument("--output-dir", default="data/prepared", help="Dossier de sortie")
    parser.add_argument("--train-ratio", type=float, default=0.7)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--rf-output",
        default="network_traffic.csv",
        help="CSV final compatible avec random_forest.py",
    )
    args = parser.parse_args()

    try:
        df = load_dataset(args.input)
        clean_df = clean_dataset(df)

        train_df, val_df, test_df = train_val_test_split_stratified(
            clean_df,
            label_col="label",
            train_ratio=args.train_ratio,
            val_ratio=args.val_ratio,
            seed=args.seed,
        )

        usable_features = [c for c in NUMERIC_FEATURES if c in train_df.columns]
        stats = fit_robust_stats(train_df, usable_features)

        train_scaled = apply_robust_scaling(train_df, stats)
        val_scaled = apply_robust_scaling(val_df, stats)
        test_scaled = apply_robust_scaling(test_df, stats)

        print("\n=== Verification distribution labels ===")
        print_balance(clean_df, "Dataset global")
        print_balance(train_scaled, "Train")
        print_balance(val_scaled, "Validation")
        print_balance(test_scaled, "Test")

        export_splits(train_scaled, val_scaled, test_scaled, args.output_dir)
        stats_path = save_scaler_stats(stats, args.output_dir)
        print(f"  - {stats_path}")

        merged_scaled = pd.concat([train_scaled, val_scaled, test_scaled], ignore_index=True)
        rf_ready_df = build_random_forest_ready_dataset(merged_scaled)
        rf_csv = export_random_forest_csv(rf_ready_df, args.rf_output)
        print(f"  - {rf_csv}")

        print("\nTermine. Le fichier RF est pret pour random_forest.py.")
    except Exception as exc:
        print(f"Erreur: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
