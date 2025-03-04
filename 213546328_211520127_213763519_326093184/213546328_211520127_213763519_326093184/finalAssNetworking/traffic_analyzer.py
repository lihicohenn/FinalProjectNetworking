import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.ticker as mticker

# Load CSV files and add 'Application' column
apps = {
    'Chrome': 'chrome.csv',
    'Edge': 'microsoft_edge.csv',
    'Spotify': 'spotify.csv',
    'YouTube': 'youtube.csv',
    'Zoom': 'zoom.csv'
}

dataframes = []
for app, file in apps.items():
    df = pd.read_csv(file, on_bad_lines='skip')
    df['Application'] = app
    dataframes.append(df)

df_all = pd.concat(dataframes, ignore_index=True)

# (1) Packet Size Over Time (Heatmap)
if {'Time', 'Length', 'Application'}.issubset(df_all.columns):
    fig, ax = plt.subplots(figsize=(8, 5))
    sns.scatterplot(data=df_all, x='Time', y='Length', hue='Application', palette='tab10', alpha=0.7, s=10, ax=ax)
    plt.yscale('log')
    plt.title('Packet Size Over Time by Application')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packet Size (Bytes)')
    plt.legend(title='Application', bbox_to_anchor=(1.3, 1), loc='upper right', fontsize=9)
    plt.subplots_adjust(right=0.8)
    plt.tight_layout()
    plt.show()

# (2) Packet Size vs. TTL per Application (Fixed `stripplot` Warning)
if {'Length', 'Time to Live', 'Application'}.issubset(df_all.columns):
    plt.figure(figsize=(8, 5))
    sns.stripplot(data=df_all, x='Application', y='Time to Live', hue='Application', jitter=True, alpha=0.5, palette='tab10', legend=False)
    plt.title('TTL Distribution per Application')
    plt.xlabel('Application')
    plt.ylabel('Time to Live (TTL)')
    plt.grid(axis='y', linestyle='--', linewidth=0.5, alpha=0.7)
    plt.show()

# (3) Flow Volume vs. Flow Count per Application
if {'Application', 'Length'}.issubset(df_all.columns):
    flow_volume = df_all.groupby('Application')['Length'].sum()
    flow_count = df_all.groupby('Application')['Length'].count()

    fig, ax1 = plt.subplots(figsize=(8, 5))
    ax1.set_xlabel('Application')
    ax1.set_ylabel('Total Bytes Transmitted', color='blue')
    ax1.bar(flow_volume.index, flow_volume, color='blue', alpha=0.7, label='Total Bytes')
    ax1.tick_params(axis='y', labelcolor='blue')

    ax2 = ax1.twinx()
    ax2.set_ylabel('Number of Flows', color='red')
    ax2.plot(flow_count.index, flow_count, color='red', marker='o', linestyle='dashed', linewidth=2, markersize=8, label='Flow Count')
    ax2.tick_params(axis='y', labelcolor='red')

    fig.suptitle('Flow Volume vs. Flow Count per Application')
    fig.tight_layout()
    plt.xticks(rotation=45)
    plt.show()

# (4) TCP Flags Distribution by Application
flag_names = {
    0x02: "SYN",
    0x10: "ACK",
    0x12: "SYN-ACK",
    0x18: "PSH-ACK",
    0x11: "FIN-ACK",
    0x04: "RST",
    0x19: "FIN-PSH-ACK"
}

if {'TCP Flags', 'Application'}.issubset(df_all.columns):
    df_all['TCP Flags'] = df_all['TCP Flags'].map(flag_names).fillna(df_all['TCP Flags'])

    df_tcp_flags = df_all.groupby(['Application', 'TCP Flags']).size().unstack(fill_value=0)

    fig, ax = plt.subplots(figsize=(8, 5))
    df_tcp_flags.plot(kind='bar', stacked=True, colormap='tab10', ax=ax)

    plt.title('TCP Flags Distribution by Application')
    plt.xlabel('Application')  # Ensure x-axis represents applications
    plt.ylabel('Frequency')
    plt.xticks(rotation=45)

    # Fix legend title
    plt.legend(title='TCP Flags', bbox_to_anchor=(1.3, 1), loc='upper right', fontsize=9)

    plt.subplots_adjust(right=0.8)
    plt.tight_layout()
    plt.show()

# (5) TLS Version Distribution by Application
if {'Protocol', 'Application'}.issubset(df_all.columns):
    df_tls = df_all[df_all['Protocol'].str.startswith("TLSv")]
    tls_counts = df_tls.groupby(['Application', 'Protocol']).size().unstack(fill_value=0)

    fig, ax = plt.subplots(figsize=(8, 5))
    tls_counts.plot(kind='bar', stacked=True, colormap='tab10', ax=ax)

    plt.title('TLS Version Distribution by Application')
    plt.xlabel('TLS Version')
    plt.ylabel('Frequency')
    plt.xticks(rotation=45)
    plt.legend(title='Application', bbox_to_anchor=(1.3, 1), loc='upper right', fontsize=9)
    plt.subplots_adjust(right=0.8)
    plt.tight_layout()
    plt.show()

# (6) Simple TCP Window Size Bar Chart (No Scientific Notation)
if {'Calculated Window Size', 'Application'}.issubset(df_all.columns):
    plt.figure(figsize=(9, 5))
    avg_window_size = df_all.groupby('Application')['Calculated Window Size'].mean()
    avg_window_size.plot(kind='bar', color='steelblue', edgecolor='black', alpha=0.7)
    plt.gca().yaxis.set_major_formatter(mticker.StrMethodFormatter('{x:,.0f}'))
    plt.ylabel('Average TCP Window Size (Bytes)')
    plt.xlabel('Application')
    plt.title('Average TCP Window Size per Application')
    plt.xticks(rotation=45)
    plt.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
    plt.show()

# (7) Inter-Arrival Time Distribution per Application (Log Scale for Visibility)
if {'Delta-time', 'Application'}.issubset(df_all.columns):
    fig, ax = plt.subplots(figsize=(8, 5))

    for app, df in df_all.groupby('Application'):
        if df['Delta-time'].nunique() > 1:
            sns.kdeplot(df['Delta-time'].dropna(), label=app, alpha=0.7, bw_adjust=1.5, ax=ax)

    plt.xscale('log')
    plt.title('Packet Inter-Departure Time Distribution per Application')
    plt.xlabel('Time Between Packets (seconds, log-scale)')
    plt.ylabel('Density')
    plt.xlim(1e-4, 1)
    plt.legend(title='Application', bbox_to_anchor=(1.3, 1), loc='upper right', fontsize=9)
    plt.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
    plt.subplots_adjust(right=0.8)
    plt.tight_layout()
    plt.show()

import matplotlib.pyplot as plt
import seaborn as sns

# Use Seaborn's clean whitegrid style
sns.set_style("whitegrid")

# (8) Average Packet Size per Application (Bar Chart)
if {'Length', 'Application'}.issubset(df_all.columns):
    plt.figure(figsize=(9, 5))

    avg_packet_size = df_all.groupby('Application')['Length'].mean()

    avg_packet_size.plot(kind='bar', color=['steelblue', 'orange', 'green', 'red', 'purple'], edgecolor='black', alpha=0.7)

    plt.ylabel('Average Packet Size (Bytes)', fontsize=11)
    plt.xlabel('Application', fontsize=11)
    plt.title('(8) Average Packet Size per Application (Bar Chart)', fontsize=13, fontweight='bold')

    plt.xticks(rotation=45)
    plt.grid(axis='y', linestyle='--', linewidth=0.5, alpha=0.7)
    plt.tight_layout()
    plt.show()

# (10) Protocol Distribution per Application (Fixed - No Extra Windows)
if {'Protocol', 'Application'}.issubset(df_all.columns):
    plt.close('all')  # Ensure no previous figures remain open

    fig, ax = plt.subplots(figsize=(10, 6))  #  Explicitly create one figure

    # Count occurrences of each protocol per application
    protocol_counts = df_all.groupby(['Application', 'Protocol']).size().unstack(fill_value=0)

    # Limit to Top 8 most common protocols to avoid clutter
    top_protocols = protocol_counts.sum().nlargest(8).index  # Get most used protocols
    protocol_counts = protocol_counts[top_protocols]  # Filter data

    #  Plot as a grouped bar chart using Matplotlib instead of Pandas `.plot()`
    protocol_counts.plot(kind='bar', ax=ax, colormap='tab10', edgecolor='black', alpha=0.8, width=0.75)

    ax.set_ylabel('Packet Count', fontsize=11)
    ax.set_xlabel('Application', fontsize=11)
    ax.set_title('Protocol Distribution per Application (Grouped Bar Chart)', fontsize=13, fontweight='bold')

    plt.xticks(rotation=45)
    plt.legend(title='Protocol', bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=9)
    plt.grid(axis='y', linestyle='--', linewidth=0.5, alpha=0.7)
    plt.tight_layout()

    plt.show()
