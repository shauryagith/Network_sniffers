import tkinter as tk
from tkinter import messagebox, filedialog
from scapy.all import sniff
import threading
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import seaborn as sns
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from collections import defaultdict
from tkinter import font

# Global variables
packet_counts = defaultdict(int)  # Track protocols and ports
time_series_data = []  # Store packet features
anomaly_data = []  # Store anomalies for export
is_sniffing = False  # Sniffing state
model = None  # Anomaly detection model


# Extract features for machine learning
def extract_features(packet):
    if packet.haslayer("IP"):
        features = {
            "protocol": packet["IP"].proto,  # Protocol type (e.g., TCP, UDP, ICMP)
            "src_port": packet.sport if hasattr(packet, 'sport') else 0,  # Source port
            "dst_port": packet.dport if hasattr(packet, 'dport') else 0,  # Destination port
            "length": len(packet),  # Packet length
            "src_ip": packet["IP"].src,  # Source IP address
            "dst_ip": packet["IP"].dst  # Destination IP address
        }
        return features
    else:
        return None  # Return None if no IP layer is found


# Parse packets and store data
def parse_packet(packet):
    global time_series_data
    features = extract_features(packet)
    if features:
        time_series_data.append(features)
        protocol = features["protocol"]
        packet_counts[f"protocol-{protocol}"] += 1
        packet_counts[f"port-{features['src_port']}"] += 1
        packet_counts[f"port-{features['dst_port']}"] += 1
        detect_anomalies(features, packet)


# Train Isolation Forest for anomaly detection
def train_anomaly_model(packet_data):
    if not packet_data:
        messagebox.showwarning("Warning", "No data available to train the anomaly model.")
        return None
    try:
        df = pd.DataFrame(packet_data)
        numerical_features = ["protocol", "src_port", "dst_port", "length"]  # Use only numerical features
        df = df[numerical_features].fillna(0)  # Handle missing values
        clf = IsolationForest(random_state=42)
        clf.fit(df)
        return clf
    except Exception as e:
        messagebox.showerror("Error", f"Failed to train anomaly model: {e}")
        return None



# Detect anomalies in real-time
def detect_anomalies(features, packet):
    global model, anomaly_data
    if model is None:
        print("Model is not initialized or trained. Skipping anomaly detection.")
        return
    try:
        # Convert the feature dictionary into a DataFrame
        df = pd.DataFrame([features])
        prediction = model.predict(df)

        # Check if the prediction indicates an anomaly
        if prediction[0] == -1:  # -1 indicates an anomaly in Isolation Forest
            print("Anomalous packet detected:", features)
            anomaly_data.append(features)
            inspect_anomaly_packet(packet)
    except Exception as e:
        print(f"Error during anomaly detection: {e}")



# Inspect anomalous packet
def inspect_anomaly_packet(packet):
    details = f"Anomalous Packet:\n"
    details += f"Source IP: {packet['IP'].src}\n"
    details += f"Destination IP: {packet['IP'].dst}\n"
    details += f"Source Port: {packet.sport}\n" if hasattr(packet, 'sport') else ""
    details += f"Destination Port: {packet.dport}\n" if hasattr(packet, 'dport') else ""
    details += f"Packet Length: {len(packet)} bytes\n"
    messagebox.showinfo("Packet Inspection", details)


# Heatmap visualization
def plot_heatmap(ax):
    ports = list(range(1, 1025))  # Common ports
    counts = [packet_counts.get(f"port-{port}", 0) for port in ports]
    heatmap_data = np.array(counts).reshape(32, 32)  # Reshape to 32x32
    sns.heatmap(heatmap_data, cmap="YlGnBu", linewidths=0.5, ax=ax)
    ax.set_title("Live Port Activity Heatmap")


# Real-time protocol trends
def update_protocol_trends(frame, ax):
    ax.clear()
    protocols = ["TCP", "UDP", "ICMP", "Others"]
    counts = [packet_counts.get(f"protocol-{protocol}", 0) for protocol in protocols]
    ax.bar(protocols, counts, color=["blue", "green", "orange", "red"])
    ax.set_title("Protocol Trends")
    ax.set_ylabel("Packet Count")
    ax.set_xlabel("Protocol")


# Sniffing functions
def start_sniffing(custom_filter):
    global is_sniffing
    is_sniffing = True
    threading.Thread(target=lambda: sniff(filter=custom_filter, prn=parse_packet, store=False), daemon=True).start()


def stop_sniffing():
    global is_sniffing
    is_sniffing = False
    print("Sniffing stopped.")


# Export anomalies to CSV
def export_anomalies():
    if not anomaly_data:
        messagebox.showwarning("Warning", "No anomalies detected to export.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if file_path:
        df = pd.DataFrame(anomaly_data)
        df.to_csv(file_path, index=False)
        messagebox.showinfo("Info", f"Anomalies exported to {file_path}")


# Save heatmap snapshot
def save_heatmap_snapshot():
    if not packet_counts:
        messagebox.showwarning("Warning", "No data to save.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if file_path:
        fig, ax = plt.subplots(figsize=(6, 6))
        plot_heatmap(ax)
        fig.savefig(file_path)
        messagebox.showinfo("Info", f"Heatmap saved to {file_path}")


# GUI Interface with enhanced design
def create_gui(stop_capture=None, show_visualizations=None):
    global model, time_series_data, filter_entry  # Declare filter_entry as global

    # Initialize with dummy data for model training
    time_series_data = [
        {"protocol": 6, "src_port": 80, "dst_port": 443, "length": 64, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"protocol": 17, "src_port": 53, "dst_port": 123, "length": 128, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.3"},
    ]
    model = train_anomaly_model(time_series_data)

    def start_capture():
        global model, time_series_data
        if not time_series_data:
            messagebox.showwarning("Warning", "No packet data available. Please sniff packets to collect data.")
            return
        if model is None:
            model = train_anomaly_model(time_series_data)
            if model is None:
                return  # If model training fails, do not proceed
        custom_filter = filter_entry.get()  # Access filter_entry here
        if is_sniffing:
            messagebox.showinfo("Info", "Sniffing is already running.")
        else:
            start_sniffing(custom_filter)
            status_label.config(text="Sniffing started...")

    # GUI Setup
    root = tk.Tk()
    root.title("Network Sniffer")
    root.geometry("600x400")  # Set window size
    root.config(bg="#f0f0f0")  # Background color

    # Custom fonts and colors
    header_font = font.Font(family="Helvetica", size=14, weight="bold")
    button_font = font.Font(family="Helvetica", size=12)
    label_font = font.Font(family="Helvetica", size=10)

    # Main Frame for UI components
    main_frame = tk.Frame(root, bg="#f0f0f0")
    main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

    # Header Label
    header_label = tk.Label(main_frame, text="Network Sniffer Tool", font=header_font, bg="#f0f0f0")
    header_label.grid(row=0, column=0, columnspan=2, pady=10)

    tk.Label(main_frame, text="Custom Filter:", font=label_font, bg="#f0f0f0").grid(row=1, column=0, padx=5, pady=5)
    filter_entry = tk.Entry(main_frame, width=50, font=button_font)  # Declare filter_entry here
    filter_entry.grid(row=1, column=1, padx=5, pady=5)

    # Buttons (with custom font)
    start_button = tk.Button(main_frame, text="Start Sniffing", command=start_capture, font=button_font, bg="#4CAF50",
                             fg="white", relief="raised")
    start_button.grid(row=2, column=0, padx=5, pady=10)

    stop_button = tk.Button(main_frame, text="Stop Sniffing", command=stop_capture, font=button_font, bg="#f44336",
                            fg="white", relief="raised")
    stop_button.grid(row=2, column=1, padx=5, pady=10)

    visualize_button = tk.Button(main_frame, text="Show Visualizations", command=show_visualizations, font=button_font,
                                 bg="#2196F3", fg="white", relief="raised")
    visualize_button.grid(row=3, column=0, columnspan=2, pady=10)

    export_button = tk.Button(main_frame, text="Export Anomalies", command=export_anomalies, font=button_font,
                              bg="#FFEB3B", fg="black", relief="raised")
    export_button.grid(row=4, column=0, columnspan=2, pady=10)

    save_button = tk.Button(main_frame, text="Save Heatmap Snapshot", command=save_heatmap_snapshot, font=button_font,
                            bg="#FFC107", fg="black", relief="raised")
    save_button.grid(row=5, column=0, columnspan=2, pady=10)

    status_label = tk.Label(main_frame, text="Status: Idle", font=label_font, bg="#f0f0f0")
    status_label.grid(row=6, column=0, columnspan=2, pady=5)

    # Start the GUI loop
    root.mainloop()



# Run the GUI
if __name__ == "__main__":
    create_gui()
