# replay.py — optional: stream a CSV you specify (no default)
import sys, time, os
import pandas as pd

def replay(source_path: str, delay=0.2, chunk=5, dst="data/logs.csv"):
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source not found: {source_path}")
    os.makedirs("data", exist_ok=True)
    pd.read_csv(source_path, nrows=0).to_csv(dst, index=False)  # header once
    for chunk_df in pd.read_csv(source_path, chunksize=chunk):
        chunk_df.to_csv(dst, mode="a", header=False, index=False)
        time.sleep(delay)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python replay.py <path_to_csv> [delay_seconds] [chunk_size]")
        sys.exit(1)
    p = sys.argv[1]
    d = float(sys.argv[2]) if len(sys.argv) > 2 else 0.2
    c = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    replay(p, d, c)
