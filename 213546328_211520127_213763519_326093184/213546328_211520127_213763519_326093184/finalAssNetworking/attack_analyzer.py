import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import hashlib
import os
import matplotlib.ticker as mticker

# Define file paths for five baseline apps + attacker
files = {
    'Chrome': 'chrome.csv',
    'Microsoft Edge': 'microsoft_edge.csv',
    'Spotify': 'spotify.csv',
    'YouTube': 'youtube.csv',
    'Zoom': 'zoom.csv',
    'Chrome & Spotify (Attacker)': 'chrome_spotify_attacker.csv'
}

RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)

def calculate_flow_id(df):
    """
    Calculates a flow_id by hashing the 4-tuple:
    (Source IP, Destination IP, Source Port, Destination Port)
    """
    required_cols = {'Source IP', 'Destination IP', 'Source Port', 'Destination Port'}
    if not required_cols.issubset(df.columns):
        print("Warning: Missing columns for flow ID calculation.")
        df['flow_id'] = None
        return df

    flow_ids = []
    for _, row in df.iterrows():
        src_ip = row.get('Source IP', 'Unknown')
        dst_ip = row.get('Destination IP', 'Unknown')
        src_port = row.get('Source Port', 'Unknown')
        dst_port = row.get('Destination Port', 'Unknown')

        if "Unknown" in [src_ip, dst_ip, src_port, dst_port]:
            flow_ids.append(None)
        else:
            four_tuple = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}"
            flow_id = hashlib.md5(four_tuple.encode()).hexdigest()
            flow_ids.append(flow_id)

    df['flow_id'] = flow_ids
    return df

def load_all_data(files):
    """
    Loads all CSV files, adds an 'Application' column,
    sorts by 'Time' (if present), and creates 'size' from 'Length'.
    """
    data_list = []
    for app_name, path in files.items():
        df = pd.read_csv(path, on_bad_lines='skip')
        df['Application'] = app_name
        if 'Time' in df.columns:
            df = df.sort_values('Time')
        if 'Length' in df.columns:
            df['size'] = df['Length']
        else:
            df['size'] = None
        data_list.append(df)
    return pd.concat(data_list, ignore_index=True)

# 1) Load all data
df_all = load_all_data(files)

# 2) Filter out rows without 'Time' or 'size'
df_full = df_all[df_all['Time'].notna() & df_all['size'].notna()]


# SCENARIO 1 (With Flow ID)

#  Calculate flow IDs and filter out rows that don't have a valid flow_id
df_flow = df_full.copy()
df_flow = calculate_flow_id(df_flow)
df_flow = df_flow[df_flow['flow_id'].notna()]


# Graph 1: Packet Size Over Time (with Flow ID) -- Scatter Plot
plt.figure(figsize=(10, 6))
sns.scatterplot(
    data=df_flow,
    x='Time',
    y='size',
    hue='Application',
    marker='o',
    s=15,
    alpha=0.6,
    edgecolor=None
)
plt.title('Scenario 1: Packet Size Over Time (With Flow ID)')
plt.xlabel('Timestamp')
plt.ylabel('Packet Size (Bytes)')
# Optionally use a log scale if packet sizes vary greatly:
# plt.yscale('log')
plt.legend(title='Application', bbox_to_anchor=(1.05, 1), loc='upper left')
plt.grid(True)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_DIR, "Scenario1_Packet_Size_Over_Time.png"))
plt.close()

# Graph 2: Flow Size Distribution (packets per flow) -- Lines Only
flow_sizes = df_flow.groupby(['Application', 'flow_id']).size().reset_index(name='packets_per_flow')

plt.figure(figsize=(10, 6))
for app_name in files.keys():
    data = flow_sizes[flow_sizes['Application'] == app_name]['packets_per_flow'].dropna()
    if data.shape[0] > 1:
        # Plot KDE lines only, no fill
        sns.kdeplot(data, label=app_name, fill=False, alpha=1.0, lw=2)
# Optionally clip at 99th percentile to zoom in
p99_flow_size = flow_sizes['packets_per_flow'].dropna().quantile(0.99)
plt.xlim(0, p99_flow_size)
plt.title('Scenario 1: Flow Size Distribution (Packets per Flow) - Lines Only')
plt.xlabel('Packets per Flow')
plt.ylabel('Density')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_DIR, "Scenario1_Flow_Size_Distribution.png"))
plt.close()

# SCENARIO 2 (No Flow ID)

# Graph 3: Packet Size Distribution -- Lines Only
plt.figure(figsize=(10, 6))
for app_name in files.keys():
    data = df_full[df_full['Application'] == app_name]['size'].dropna()
    if len(data) > 1:
        # KDE lines only, no fill
        sns.kdeplot(data, label=app_name, fill=False, alpha=1.0, lw=2)
plt.title('Scenario 2: Packet Size Distribution (No Flow ID, Lines Only)')
plt.xlabel('Packet Size (Bytes)')
plt.ylabel('Density')
# Remove scientific notation on y-axis (optional)
plt.gca().yaxis.set_major_formatter(mticker.StrMethodFormatter('{x:,.0f}'))
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_DIR, "Scenario2_Packet_Size_Distribution.png"))
plt.close()

# Graph 4: Packet Inter-Arrival Time Distribution -- Lines Only

df_full = df_full.sort_values('Time')
df_full['inter_arrival'] = df_full.groupby('Application')['Time'].diff()
plt.figure(figsize=(10, 6))
for app_name in files.keys():
    data = df_full[df_full['Application'] == app_name]['inter_arrival'].dropna()
    if len(data) > 1:
        # KDE lines only, no fill
        sns.kdeplot(data, label=app_name, fill=False, alpha=1.0, lw=2)
plt.title('Scenario 2: Packet Inter-Arrival Time Distribution (No Flow ID, Lines Only)')
plt.xlabel('Inter-Arrival Time (s)')
plt.ylabel('Density')
# Use log scale on x-axis if needed
plt.xscale('log')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_DIR, "Scenario2_Inter_Arrival_Time_Distribution.png"))
plt.close()

print("All 4 comparison graphs have been saved to the 'results' directory.")

# Print Summary Statistics

# Packet Size Statistics by Application (Scenario 2)
print("=== Packet Size Statistics by Application ===")
packet_stats = df_full.groupby('Application')['size'].describe()
print(packet_stats)

# Compute inter-arrival times (Scenario 2)
df_full = df_full.sort_values('Time')
df_full['inter_arrival'] = df_full.groupby('Application')['Time'].diff()
print("\n=== Inter-Arrival Time Statistics by Application ===")
inter_arr_stats = df_full.groupby('Application')['inter_arrival'].describe()
print(inter_arr_stats)

# Flow Size Statistics (Scenario 1)
df_flow_stats = df_full.copy()
df_flow_stats = calculate_flow_id(df_flow_stats)
df_flow_stats = df_flow_stats[df_flow_stats['flow_id'].notna()]
flow_sizes_stats = df_flow_stats.groupby(['Application', 'flow_id']).size().reset_index(name='packets_per_flow')
print("\n=== Flow Size (Packets per Flow) Statistics by Application ===")
flow_stats = flow_sizes_stats.groupby('Application')['packets_per_flow'].describe()
print(flow_stats)
