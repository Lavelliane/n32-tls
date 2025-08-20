"""
Network Topology Simulator for Geographical TLS Performance Testing

Simulates 5G network topology with realistic latencies between different
geographical locations for cross-border roaming scenarios.
"""

import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
import random
import time
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from geopy.distance import geodesic
import threading

@dataclass
class NetworkNode:
    """Represents a network node (SEPP location)"""
    node_id: str
    country: str
    city: str
    latitude: float
    longitude: float
    region: str  # "asia", "europe", "americas", etc.
    node_type: str  # "home_sepp", "visited_sepp", "transit"

@dataclass
class NetworkLink:
    """Represents a network link between nodes"""
    source: str
    destination: str
    base_latency_ms: float
    bandwidth_mbps: float
    packet_loss_rate: float
    jitter_ms: float

@dataclass
class LatencyMeasurement:
    """Latency measurement result"""
    source_node: str
    destination_node: str
    measured_latency_ms: float
    base_latency_ms: float
    additional_delay_ms: float
    timestamp: float

class NetworkTopology:
    """
    Simulates realistic network topology for geographical TLS testing
    """
    
    def __init__(self):
        self.graph = nx.Graph()
        self.nodes: Dict[str, NetworkNode] = {}
        self.links: Dict[Tuple[str, str], NetworkLink] = {}
        
        # Initialize with major 5G network locations
        self._initialize_5g_network_nodes()
        self._create_network_links()
    
    def _initialize_5g_network_nodes(self):
        """Initialize simplified 5G network nodes for key global locations"""
        nodes_data = [
            # Asia-Pacific (Home Network)
            NetworkNode("KR_Seoul", "South Korea", "Seoul", 37.5665, 126.9780, "asia", "home_sepp"),
            
            # Key Visited Networks (simplified to 4 major regions)
            # Europe 
            NetworkNode("DE_Frankfurt", "Germany", "Frankfurt", 50.1109, 8.6821, "europe", "visited_sepp"),
            
            # Americas
            NetworkNode("US_NewYork", "United States", "New York", 40.7128, -74.0060, "americas", "visited_sepp"),
            
            # Middle East
            NetworkNode("AE_Dubai", "UAE", "Dubai", 25.2048, 55.2708, "middle_east", "visited_sepp"),
            
            # Additional Asia-Pacific (for regional comparison)
            NetworkNode("JP_Tokyo", "Japan", "Tokyo", 35.6762, 139.6503, "asia", "visited_sepp"),
        ]
        
        for node in nodes_data:
            self.add_node(node)
    
    def add_node(self, node: NetworkNode):
        """Add a network node to the topology"""
        self.nodes[node.node_id] = node
        self.graph.add_node(node.node_id, **node.__dict__)
    
    def _create_network_links(self):
        """Create realistic network links between nodes"""
        # Connect all nodes with each other (full mesh for simulation)
        # In reality, this would be more selective based on actual network topology
        
        node_ids = list(self.nodes.keys())
        for i, source_id in enumerate(node_ids):
            for dest_id in node_ids[i+1:]:
                self._create_link_between_nodes(source_id, dest_id)
    
    def _create_link_between_nodes(self, source_id: str, dest_id: str):
        """Create a network link between two nodes with realistic parameters"""
        source_node = self.nodes[source_id]
        dest_node = self.nodes[dest_id]
        
        # Calculate geographical distance
        source_coords = (source_node.latitude, source_node.longitude)
        dest_coords = (dest_node.latitude, dest_node.longitude)
        distance_km = geodesic(source_coords, dest_coords).kilometers
        
        # Calculate base latency (rough estimate: speed of light + infrastructure overhead)
        # Speed of light in fiber ~200,000 km/s, plus routing/switching overhead
        light_speed_latency = distance_km / 200000 * 1000  # Convert to ms
        infrastructure_overhead = self._calculate_infrastructure_overhead(source_node, dest_node)
        base_latency = light_speed_latency + infrastructure_overhead
        
        # Estimate bandwidth based on connection type
        bandwidth = self._estimate_bandwidth(source_node, dest_node, distance_km)
        
        # Packet loss and jitter estimates
        packet_loss = self._estimate_packet_loss(distance_km, source_node.region, dest_node.region)
        jitter = max(1.0, base_latency * 0.1)  # Jitter is roughly 10% of base latency
        
        link = NetworkLink(
            source=source_id,
            destination=dest_id,
            base_latency_ms=base_latency,
            bandwidth_mbps=bandwidth,
            packet_loss_rate=packet_loss,
            jitter_ms=jitter
        )
        
        self.links[(source_id, dest_id)] = link
        self.links[(dest_id, source_id)] = link  # Bidirectional
        
        # Add edge to graph
        self.graph.add_edge(source_id, dest_id, 
                          weight=base_latency,
                          bandwidth=bandwidth,
                          packet_loss=packet_loss,
                          jitter=jitter)
    
    def _calculate_infrastructure_overhead(self, source: NetworkNode, dest: NetworkNode) -> float:
        """Calculate additional latency due to network infrastructure"""
        base_overhead = 5.0  # Base infrastructure latency
        
        # Cross-region penalty
        if source.region != dest.region:
            base_overhead += 10.0
        
        # Transit node penalty (more hops)
        if source.node_type == "transit" or dest.node_type == "transit":
            base_overhead += 5.0
        
        # Regional-specific penalties
        region_penalties = {
            "asia": 2.0,
            "europe": 1.0,
            "americas": 3.0,
            "middle_east": 5.0,
            "africa": 8.0
        }
        
        avg_penalty = (region_penalties.get(source.region, 0) + 
                      region_penalties.get(dest.region, 0)) / 2
        
        return base_overhead + avg_penalty
    
    def _estimate_bandwidth(self, source: NetworkNode, dest: NetworkNode, distance_km: float) -> float:
        """Estimate available bandwidth between nodes"""
        # Base bandwidth depends on connection type and distance
        if distance_km < 1000:  # Local/regional
            base_bandwidth = 10000  # 10 Gbps
        elif distance_km < 5000:  # Continental
            base_bandwidth = 1000   # 1 Gbps
        else:  # Intercontinental
            base_bandwidth = 100    # 100 Mbps
        
        # Adjust based on node types
        if source.node_type == "transit" or dest.node_type == "transit":
            base_bandwidth *= 2  # Transit nodes have better connectivity
        
        # Regional adjustments
        region_multipliers = {
            "asia": 1.2,
            "europe": 1.0,
            "americas": 0.8,
            "middle_east": 0.6,
            "africa": 0.4
        }
        
        avg_multiplier = (region_multipliers.get(source.region, 1.0) + 
                         region_multipliers.get(dest.region, 1.0)) / 2
        
        return base_bandwidth * avg_multiplier
    
    def _estimate_packet_loss(self, distance_km: float, source_region: str, dest_region: str) -> float:
        """Estimate packet loss rate"""
        base_loss = 0.001  # 0.1% base loss
        
        # Distance penalty
        distance_penalty = min(0.01, distance_km / 1000000)  # Max 1% additional loss
        
        # Cross-region penalty
        cross_region_penalty = 0.002 if source_region != dest_region else 0.0
        
        return base_loss + distance_penalty + cross_region_penalty
    
    def measure_latency(self, source_id: str, dest_id: str, 
                       additional_delay_ms: float = 0.0) -> LatencyMeasurement:
        """
        Measure latency between two nodes with realistic variation
        """
        if (source_id, dest_id) not in self.links:
            raise ValueError(f"No link between {source_id} and {dest_id}")
        
        link = self.links[(source_id, dest_id)]
        
        # Add random jitter
        jitter_variation = random.uniform(-link.jitter_ms/2, link.jitter_ms/2)
        
        # Add congestion simulation (random additional delay)
        congestion_delay = np.random.exponential(2.0)  # Exponential distribution for congestion
        
        # Calculate total measured latency
        measured_latency = (link.base_latency_ms + 
                          jitter_variation + 
                          congestion_delay + 
                          additional_delay_ms)
        
        # Ensure non-negative latency
        measured_latency = max(0.1, measured_latency)
        
        return LatencyMeasurement(
            source_node=source_id,
            destination_node=dest_id,
            measured_latency_ms=measured_latency,
            base_latency_ms=link.base_latency_ms,
            additional_delay_ms=additional_delay_ms + jitter_variation + congestion_delay,
            timestamp=time.time()
        )
    
    def simulate_network_delay(self, source_id: str, dest_id: str, 
                             additional_delay_ms: float = 0.0):
        """
        Simulate network delay by sleeping for the measured latency time
        """
        latency_measurement = self.measure_latency(source_id, dest_id, additional_delay_ms)
        
        # Sleep for the measured latency (scaled down for simulation)
        # Using 1ms sleep per 100ms of actual latency for faster simulation
        sleep_time = latency_measurement.measured_latency_ms / 100.0 / 1000.0
        time.sleep(max(0.001, sleep_time))  # Minimum 1ms sleep
        
        return latency_measurement
    
    def get_shortest_path(self, source_id: str, dest_id: str) -> List[str]:
        """Get shortest path between two nodes"""
        try:
            return nx.shortest_path(self.graph, source_id, dest_id, weight='weight')
        except nx.NetworkXNoPath:
            return []
    
    def get_path_latency(self, path: List[str]) -> float:
        """Calculate total latency for a given path"""
        total_latency = 0.0
        for i in range(len(path) - 1):
            if (path[i], path[i+1]) in self.links:
                total_latency += self.links[(path[i], path[i+1])].base_latency_ms
        return total_latency
    
    def visualize_topology(self, save_path: str = "network_topology.png", 
                          highlight_nodes: List[str] = None):
        """
        Create a research-quality visualization of the network topology with latency indicators
        """
        plt.figure(figsize=(20, 14))
        plt.rcParams.update({'font.size': 16})  # Large fonts for research papers
        
        # Create layout based on geographical coordinates
        pos = {}
        for node_id, node in self.nodes.items():
            # Normalize coordinates for plotting
            pos[node_id] = (node.longitude, node.latitude)
        
        # Calculate latencies for edge coloring
        edge_colors = []
        edge_widths = []
        edge_labels = {}
        
        for edge in self.graph.edges():
            source_id, dest_id = edge
            if (source_id, dest_id) in self.links:
                latency = self.links[(source_id, dest_id)].base_latency_ms
            elif (dest_id, source_id) in self.links:
                latency = self.links[(dest_id, source_id)].base_latency_ms
            else:
                latency = 50  # Default
            
            # Color code edges by latency
            if latency < 30:
                edge_colors.append('#2E8B57')  # Green - Low latency
                edge_widths.append(4)
            elif latency < 60:
                edge_colors.append('#FFD700')  # Gold - Medium latency  
                edge_widths.append(3)
            elif latency < 100:
                edge_colors.append('#FF8C00')  # Orange - High latency
                edge_widths.append(2)
            else:
                edge_colors.append('#DC143C')  # Red - Very high latency
                edge_widths.append(1)
            
            # Add latency labels on edges
            edge_labels[edge] = f"{latency:.0f}ms"
        
        # Draw edges with latency-based colors and widths
        nx.draw_networkx_edges(self.graph, pos, edge_color=edge_colors, 
                             width=edge_widths, alpha=0.8)
        
        # Color nodes by region with larger, more distinct colors
        region_colors = {
            'asia': '#FF4444',        # Bright Red for Asia
            'europe': '#4444FF',      # Bright Blue for Europe
            'americas': '#44FF44',    # Bright Green for Americas
            'middle_east': '#FF8800', # Orange for Middle East
        }
        
        # Draw home SEPP with special styling
        home_nodes = [node_id for node_id, node in self.nodes.items() 
                     if node.node_type == "home_sepp"]
        if home_nodes:
            nx.draw_networkx_nodes(self.graph, pos, nodelist=home_nodes,
                                 node_color='#FFD700', node_size=1500, alpha=0.9,
                                 edgecolors='black', linewidths=4)
        
        # Draw visited SEPPs by region
        for region, color in region_colors.items():
            region_nodes = [node_id for node_id, node in self.nodes.items() 
                           if node.region == region and node.node_type == "visited_sepp"]
            if region_nodes:
                nx.draw_networkx_nodes(self.graph, pos, nodelist=region_nodes,
                                     node_color=color, node_size=1000, alpha=0.8,
                                     edgecolors='black', linewidths=2)
        
        # Add large, clear labels
        labels = {}
        for node_id, node in self.nodes.items():
            if node.node_type == "home_sepp":
                labels[node_id] = f"{node.city}\n(HOME)"
            else:
                labels[node_id] = f"{node.city}\n{node.country}"
        
        nx.draw_networkx_labels(self.graph, pos, labels, font_size=14, font_weight='bold',
                               bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.8))
        
        # Add edge labels for latencies
        edge_pos = {}
        for edge in self.graph.edges():
            x1, y1 = pos[edge[0]]
            x2, y2 = pos[edge[1]]
            edge_pos[edge] = ((x1 + x2) / 2, (y1 + y2) / 2)
        
        for edge, label in edge_labels.items():
            x, y = edge_pos[edge]
            plt.text(x, y, label, fontsize=12, ha='center', va='center',
                    bbox=dict(boxstyle="round,pad=0.2", facecolor="yellow", alpha=0.7))
        
        plt.title('5G Cross-Border Roaming Network Topology\nLatency-Coded Connections for TLS 1.3 Performance Analysis', 
                 fontsize=20, fontweight='bold', pad=20)
        
        # Enhanced legend
        legend_elements = []
        
        # Region legend
        legend_elements.append(plt.Line2D([0], [0], marker='o', color='w', 
                                        markerfacecolor='#FFD700', markersize=15, 
                                        markeredgecolor='black', markeredgewidth=2,
                                        label='Home SEPP (Seoul)', linewidth=0))
        
        for region, color in region_colors.items():
            if any(node.region == region for node in self.nodes.values()):
                legend_elements.append(plt.Line2D([0], [0], marker='o', color='w', 
                                               markerfacecolor=color, markersize=12, 
                                               markeredgecolor='black', markeredgewidth=1,
                                               label=f'Visited SEPP ({region.title()})', linewidth=0))
        
        # Latency legend
        legend_elements.append(plt.Line2D([0], [0], color='white', linewidth=0, label=''))  # Spacer
        legend_elements.append(plt.Line2D([0], [0], color='#2E8B57', linewidth=4, label='Low Latency (< 30ms)'))
        legend_elements.append(plt.Line2D([0], [0], color='#FFD700', linewidth=3, label='Medium Latency (30-60ms)'))
        legend_elements.append(plt.Line2D([0], [0], color='#FF8C00', linewidth=2, label='High Latency (60-100ms)'))
        legend_elements.append(plt.Line2D([0], [0], color='#DC143C', linewidth=1, label='Very High Latency (> 100ms)'))
        
        plt.legend(handles=legend_elements, loc='upper left', fontsize=14, 
                  title='Network Elements & Latency Levels', title_fontsize=16)
        
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
    
    def create_latency_heatmap(self, save_path: str = "latency_heatmap.png"):
        """Create a latency heatmap between all nodes"""
        node_ids = list(self.nodes.keys())
        n_nodes = len(node_ids)
        
        # Create latency matrix
        latency_matrix = np.zeros((n_nodes, n_nodes))
        
        for i, source in enumerate(node_ids):
            for j, dest in enumerate(node_ids):
                if i == j:
                    latency_matrix[i][j] = 0
                elif (source, dest) in self.links:
                    latency_matrix[i][j] = self.links[(source, dest)].base_latency_ms
                else:
                    latency_matrix[i][j] = np.inf
        
        # Create heatmap
        plt.figure(figsize=(12, 10))
        
        # Replace inf with a large value for visualization
        latency_matrix[latency_matrix == np.inf] = np.max(latency_matrix[latency_matrix != np.inf]) * 1.5
        
        im = plt.imshow(latency_matrix, cmap='YlOrRd', aspect='auto')
        
        # Add colorbar
        cbar = plt.colorbar(im)
        cbar.set_label('Latency (ms)', rotation=270, labelpad=20)
        
        # Set ticks and labels
        city_labels = [self.nodes[node_id].city for node_id in node_ids]
        plt.xticks(range(n_nodes), city_labels, rotation=45, ha='right')
        plt.yticks(range(n_nodes), city_labels)
        
        # Add text annotations
        for i in range(n_nodes):
            for j in range(n_nodes):
                if latency_matrix[i][j] < np.max(latency_matrix) * 0.9:  # Don't annotate inf values
                    plt.text(j, i, f'{latency_matrix[i][j]:.0f}',
                           ha="center", va="center", color="black" if latency_matrix[i][j] < 100 else "white")
        
        plt.title('Network Latency Matrix (ms)\nBetween 5G Network Nodes', 
                 fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def get_nodes_by_region(self, region: str) -> List[NetworkNode]:
        """Get all nodes in a specific region"""
        return [node for node in self.nodes.values() if node.region == region]
    
    def get_home_sepp_nodes(self) -> List[NetworkNode]:
        """Get all home SEPP nodes"""
        return [node for node in self.nodes.values() if node.node_type == "home_sepp"]
    
    def get_visited_sepp_nodes(self) -> List[NetworkNode]:
        """Get all visited SEPP nodes"""
        return [node for node in self.nodes.values() if node.node_type == "visited_sepp"] 