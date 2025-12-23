import pandas as pd
import matplotlib.pyplot as plt

def latest_log():
    all_files = os.listdir(".")
    log_files=[]
    for file_name in all_files:
        if ".csv" in file_name and "average" not in file_name:
            log_files.append(file_name)
    log_files.sort(reverse=True)
    if log_files:
        return log_files[0]
    else:
        return None

def main():
    # ===============================
    # 1. Load CSV file (fixed path)
    # ===============================
    input_csv = "./"+latest_log()
    df = pd.read_csv(input_csv)

    # ===============================
    # 2. Validate required columns
    # ===============================
    required_cols = [
        "vpn_nodes",
        "average_latency_sec",
        "average_throughput_mbps"
    ]
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    # ===============================
    # 3. Group by vpn_nodes and average over all runs (30 runs)
    # ===============================
    grouped = (
        df
        .groupby("vpn_nodes", as_index=False)
        .agg(
            mean_latency_sec=("average_latency_sec", "mean"),
            mean_throughput_mbps=("average_throughput_mbps", "mean")
        )
        .sort_values("vpn_nodes", ascending=False)
    )


    # ===============================
    # 4. Print results and save CSV
    # ===============================
    pd.set_option("display.float_format", "{:.6f}".format)
    print("\n=== 30-run average per vpn_nodes ===")
    print(grouped)

    output_csv = "vpn_nodes_30run_average.csv"
    grouped.to_csv(output_csv, index=False)
    print(f"\nSaved summary CSV to: {output_csv}")

    # ===============================
    # 5. Plot average latency vs vpn_nodes
    # ===============================
    plt.figure()
    plt.plot(
        grouped["vpn_nodes"],
        grouped["mean_latency_sec"]*1000,
        marker="o"
    )
    plt.xlabel("Number of VPN Nodes")
    plt.ylabel("Latency (ms)")
    plt.title("Average Latency")
    plt.grid(True)
    plt.gca().invert_xaxis()
    plt.tight_layout()
    plt.savefig("avg_latency_30runs_by_vpn_nodes.png", dpi=300)
    plt.show()

    # ===============================
    # 6. Plot average throughput vs vpn_nodes
    # ===============================
    plt.figure()
    plt.plot(
        grouped["vpn_nodes"],
        grouped["mean_throughput_mbps"],
        marker="o"
    )
    plt.xlabel("Number of VPN Nodes")
    plt.ylabel("Throughput (Mbps)")
    plt.title("Average Throughput")
    plt.grid(True)

    plt.gca().invert_xaxis()

    plt.tight_layout()
    plt.savefig("avg_throughput_30runs_by_vpn_nodes.png", dpi=300)
    plt.show()

    print("Saved plot files:")
    print(" - avg_latency_30runs_by_vpn_nodes.png")
    print(" - avg_throughput_30runs_by_vpn_nodes.png")

if __name__ == "__main__":
    main()
