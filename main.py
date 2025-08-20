#!/usr/bin/env python3
"""
TLS 1.3 Performance Simulation for 5G N32 Interface

Main CLI interface for comprehensive TLS 1.3 resumption performance evaluation
in 5G cross-border roaming scenarios using the N32 interface between SEPPs.

Usage:
    python main.py simple --iterations 100
    python main.py load --concurrent 1 5 10 20 50
    python main.py geographical --home-region asia --visited-regions europe americas
"""

import click
import threading
import time
import json
import os
from typing import List, Dict, Any, Optional
from colorama import init, Fore, Style
from tls_simulation import (
    TLSHandshakeSimulator, 
    SEPPSimulator, 
    PerformanceMonitor, 
    NetworkTopology
)
from tls_simulation.performance_monitor import TestConfiguration, PerformanceReport

# Initialize colorama for colored output
init(autoreset=True)

def print_banner():
    """Print application banner"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════════╗
║                    TLS 1.3 Performance Simulation                       ║
║                  5G N32 Interface Cross-Border Roaming                  ║
║                                                                          ║
║  Evaluating TLS 1.3 resumption variants:                               ║
║  • Full Handshake  • PSK Only  • PSK-ECDHE  • 0-RTT  • 0-RTT FS       ║
╚══════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
    """
    print(banner)

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """TLS 1.3 Performance Simulation for 5G N32 Interface"""
    print_banner()

@cli.command()
@click.option('--iterations', '-i', default=10, help='Number of test iterations')
@click.option('--methods', '-m', 
              default='psk_only,psk_ecdhe,0rtt,0rtt_fs',
              help='Comma-separated list of resumption methods to test')
@click.option('--output', '-o', default='simple_test_results', 
              help='Output directory for results')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def simple(iterations: int, methods: str, output: str, verbose: bool):
    """
    Run simple evaluation test with specified number of iterations.
    First iteration uses full handshake, subsequent use resumption methods.
    """
    print(f"{Fore.GREEN}Starting Simple Evaluation Test{Style.RESET_ALL}")
    print(f"Iterations: {iterations}")
    print(f"Methods: {methods}")
    
    # Parse methods
    resumption_methods = [m.strip() for m in methods.split(',')]
    
    # Create output directory
    os.makedirs(output, exist_ok=True)
    
    # Initialize components
    monitor = PerformanceMonitor()
    home_sepp = SEPPSimulator("home_sepp_kr", is_home_sepp=True, port=8443)
    visited_sepp = SEPPSimulator("visited_sepp_test", is_home_sepp=False, port=8444)
    
    # Start monitoring
    monitor.start_monitoring()
    start_time = time.time()
    
    # Start visited SEPP server in background thread
    server_thread = threading.Thread(target=visited_sepp.start_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for server to start
    time.sleep(1.0)
    
    results = []
    
    try:
        print(f"\n{Fore.YELLOW}Phase 1: Initial N32-c Handshake (Full TLS 1.3 with mTLS){Style.RESET_ALL}")
        
        # Initial full handshake for N32-c connection
        initial_metrics = home_sepp.connect_to_sepp(
            'localhost', 8444, 
            connection_type='n32c',
            resumption_method='full_handshake'
        )
        results.append(initial_metrics)
        
        if verbose:
            print(f"Initial handshake: {initial_metrics.total_time*1000:.2f}ms")
        
        # Pre-generate 0-RTT FS tickets if needed
        if '0rtt_fs' in resumption_methods:
            print(f"\n{Fore.CYAN}Phase 1.5: Pre-generating 0-RTT FS Tickets{Style.RESET_ALL}")
            
            # Calculate how many 0-RTT FS tests we'll run
            fs_test_count = sum(1 for i in range(iterations - 1) 
                               if resumption_methods[i % len(resumption_methods)] == '0rtt_fs')
            
            # Generate batch with some extra tickets for safety
            batch_size = max(fs_test_count + 100, 1000)
            
            print(f"Generating {batch_size} fresh 0-RTT FS tickets for {fs_test_count} tests...")
            visited_sepp.prepare_0rtt_fs_ticket_batch("home_sepp_kr", batch_size)
            
            if verbose:
                remaining = visited_sepp.get_remaining_fs_tickets("home_sepp_kr")
                print(f"Ready: {remaining} fresh tickets available for testing")
        
        print(f"\n{Fore.YELLOW}Phase 2: N32-f Data Forwarding with Resumption{Style.RESET_ALL}")
        
        # Subsequent iterations with resumption methods
        for i in range(iterations - 1):
            method = resumption_methods[i % len(resumption_methods)]
            
            if verbose:
                print(f"Iteration {i+2}/{iterations}: Using {method}")
                if method == '0rtt_fs':
                    remaining = visited_sepp.get_remaining_fs_tickets("home_sepp_kr")
                    print(f"  Fresh tickets remaining: {remaining}")
            
            metrics = home_sepp.connect_to_sepp(
                'localhost', 8444,
                connection_type='n32f',
                resumption_method=method
            )
            results.append(metrics)
            
            if verbose and metrics.success:
                print(f"  {method}: {metrics.total_time*1000:.2f}ms")
            elif verbose:
                print(f"  {method}: FAILED - {metrics.error_message}")
            
            # Small delay between iterations
            time.sleep(0.1)
    
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Test interrupted by user{Style.RESET_ALL}")
    finally:
        visited_sepp.stop_server()
        monitor.stop_monitoring()
    
    end_time = time.time()
    
    # Generate report
    config = TestConfiguration(
        test_type="simple",
        iterations=iterations,
        resumption_methods=resumption_methods
    )
    
    report = monitor.create_performance_report(config, results, start_time, end_time)
    
    # Save results
    monitor.save_report(report, f"{output}/simple_test_report.json")
    monitor.create_performance_plots(report, output)
    
    # Print summary
    print(f"\n{Fore.GREEN}Test Complete!{Style.RESET_ALL}")
    monitor.print_summary_table(report)
    print(f"\nResults saved to: {output}/")

@cli.command()
@click.option('--concurrent', '-c', 
              default='1,5,10,20,50',
              help='Comma-separated list of concurrent user counts')
@click.option('--method', '-m', default=None,
              help='Resumption method to test under load (default: test all variants)')
@click.option('--messages-per-user', default=5,
              help='Number of messages per user')
@click.option('--output', '-o', default='load_test_results',
              help='Output directory for results')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def load(concurrent: str, method: Optional[str], messages_per_user: int, output: str, verbose: bool):
    """
    Run load testing with increasing concurrent users.
    Simulates tourists from the same home country visiting a network.
    Tests all variants if no method specified.
    """
    print(f"{Fore.GREEN}Starting Load Testing{Style.RESET_ALL}")
    
    # Parse concurrent user counts
    user_counts = [int(c.strip()) for c in concurrent.split(',')]
    
    # Determine which methods to test
    if method is None:
        test_methods = ['psk_only', 'psk_ecdhe', '0rtt', '0rtt_fs']
        print(f"Testing ALL variants: {test_methods}")
    else:
        test_methods = [method]
        print(f"Testing single method: {method}")
    
    print(f"Concurrent users: {user_counts}")
    print(f"Messages per user: {messages_per_user}")
    
    # Create output directory
    os.makedirs(output, exist_ok=True)
    
    # Initialize components
    monitor = PerformanceMonitor()
    home_sepp = SEPPSimulator("home_sepp_kr", is_home_sepp=True, port=8443)
    visited_sepp = SEPPSimulator("visited_sepp_test", is_home_sepp=False, port=8444)
    
    # Start visited SEPP server
    server_thread = threading.Thread(target=visited_sepp.start_server)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(1.0)
    
    all_results = []
    
    try:
        for user_count in user_counts:
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Testing {user_count} concurrent users{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            
            for test_method in test_methods:
                print(f"\n{Fore.YELLOW}  Method: {test_method}{Style.RESET_ALL}")
                
                # Pre-generate 0-RTT FS tickets if needed
                if test_method == '0rtt_fs':
                    total_fs_tests = user_count * messages_per_user
                    batch_size = max(total_fs_tests + 100, 1000)
                    
                    print(f"    Pre-generating {batch_size} fresh 0-RTT FS tickets for {total_fs_tests} tests...")
                    visited_sepp.prepare_0rtt_fs_ticket_batch("home_sepp_kr", batch_size)
                
                monitor.start_monitoring()
                start_time = time.time()
                
                # Run concurrent test for this method
                results = home_sepp.simulate_concurrent_connections(
                    'localhost', 8444,
                    concurrent_users=user_count,
                    messages_per_user=messages_per_user,
                    resumption_method=test_method
                )
                
                end_time = time.time()
                monitor.stop_monitoring()
                
                # Calculate metrics for this method and user count
                successful_results = [r for r in results if r.success]
                if successful_results:
                    avg_latency = sum(r.total_time for r in successful_results) / len(successful_results) * 1000
                    success_rate = len(successful_results) / len(results) * 100
                    
                    print(f"    Average latency: {avg_latency:.2f}ms")
                    print(f"    Success rate: {success_rate:.1f}%")
                    print(f"    Total requests: {len(results)}")
                else:
                    print(f"    {Fore.RED}No successful results for {test_method}{Style.RESET_ALL}")
                
                all_results.extend(results)
                time.sleep(1.0)  # Short cooldown between methods
            
            time.sleep(2.0)  # Longer cooldown between user counts
    
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Load test interrupted by user{Style.RESET_ALL}")
    finally:
        visited_sepp.stop_server()
    
    # Generate final report
    config = TestConfiguration(
        test_type="load",
        iterations=len(all_results),
        concurrent_users=max(user_counts),
        resumption_methods=test_methods
    )
    
    overall_start_time = time.time() - 300  # Approximate test duration
    overall_end_time = time.time()
    report = monitor.create_performance_report(config, all_results, overall_start_time, overall_end_time)
    
    # Save results
    monitor.save_report(report, f"{output}/load_test_report.json")
    monitor.create_performance_plots(report, output)
    
    print(f"\n{Fore.GREEN}Load Test Complete!{Style.RESET_ALL}")
    monitor.print_summary_table(report)
    print(f"\nResults saved to: {output}/")

@cli.command()
@click.option('--home-region', default='asia', 
              help='Home network region (base location: South Korea)')
@click.option('--visited-regions', 
              default='asia,europe,americas,middle_east',
              help='Comma-separated list of visited regions')
@click.option('--method', '-m', default=None,
              help='Resumption method to test (default: test all variants)')
@click.option('--iterations', '-i', default=5,
              help='Iterations per geographical connection')
@click.option('--output', '-o', default='geographical_test_results',
              help='Output directory for results')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def geographical(home_region: str, visited_regions: str, method: Optional[str], 
                iterations: int, output: str, verbose: bool):
    """
    Run geographical testing simulating cross-border roaming.
    Tests latency impact of different geographical locations.
    """
    print(f"{Fore.GREEN}Starting Geographical Testing{Style.RESET_ALL}")
    
    # Parse visited regions
    target_regions = [r.strip() for r in visited_regions.split(',')]
    
    # Determine which methods to test
    if method is None:
        test_methods = ['psk_only', 'psk_ecdhe', '0rtt', '0rtt_fs']
        print(f"Testing ALL variants: {test_methods}")
    else:
        test_methods = [method]
        print(f"Testing single method: {method}")
    
    print(f"Home region: {home_region}")
    print(f"Visited regions: {target_regions}")
    print(f"Iterations per connection: {iterations}")
    
    # Create output directory
    os.makedirs(output, exist_ok=True)
    
    # Initialize components
    monitor = PerformanceMonitor()
    topology = NetworkTopology()
    
    # Create visualizations
    print(f"\n{Fore.YELLOW}Generating network topology visualizations...{Style.RESET_ALL}")
    topology.visualize_topology(f"{output}/network_topology.png")
    topology.create_latency_heatmap(f"{output}/latency_heatmap.png")
    
    # Get home SEPP (South Korea)
    home_nodes = [node for node in topology.get_home_sepp_nodes() 
                  if node.region == home_region]
    
    if not home_nodes:
        print(f"{Fore.RED}No home SEPP found in region: {home_region}{Style.RESET_ALL}")
        return
    
    home_node = home_nodes[0]
    
    # Get visited SEPPs by region
    visited_nodes = []
    for region in target_regions:
        region_nodes = [node for node in topology.get_visited_sepp_nodes() 
                       if node.region == region]
        visited_nodes.extend(region_nodes)
    
    if not visited_nodes:
        print(f"{Fore.RED}No visited SEPPs found in regions: {target_regions}{Style.RESET_ALL}")
        return
    
    print(f"\nTesting from {home_node.city} to:")
    for node in visited_nodes:
        print(f"  • {node.city}, {node.country} ({node.region})")
    
    all_results = []
    
    try:
        # Initialize SEPP simulators with geographical latency
        home_sepp = SEPPSimulator(f"home_{home_node.node_id}", is_home_sepp=True, port=8443)
        
        for visited_node in visited_nodes:
            print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Testing connection: {home_node.city} → {visited_node.city}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            
            # Measure geographical latency ONCE for this destination (fair comparison across TLS variants)
            latency_measurement = topology.measure_latency(home_node.node_id, visited_node.node_id)
            base_latency = latency_measurement.base_latency_ms
            measured_network_latency_ms = latency_measurement.measured_latency_ms
            
            print(f"  Base network latency: {base_latency:.1f}ms")
            print(f"  Measured latency (with jitter/congestion): {measured_network_latency_ms:.1f}ms")
            
            for test_method in test_methods:
                print(f"\n{Fore.YELLOW}  Method: {test_method}{Style.RESET_ALL}")
                
                # Use unique port for each connection to avoid conflicts
                port = 8445 + hash(f"{visited_node.node_id}_{test_method}") % 1000
                
                # Start visited SEPP with simulated latency
                visited_sepp = SEPPSimulator(f"visited_{visited_node.node_id}", 
                                           is_home_sepp=False, port=port)
                
                # Pre-establish session tickets for fair comparison across all regions
                client_sepp_id = home_sepp.sepp_id  # "home_KR_Seoul"
                
                if test_method == '0rtt_fs':
                    batch_size = max(iterations + 10, 100)
                    print(f"    Pre-generating {batch_size} fresh 0-RTT FS tickets...")
                    visited_sepp.prepare_0rtt_fs_ticket_batch(client_sepp_id, batch_size)
                elif test_method in ['psk_only', 'psk_ecdhe', '0rtt']:
                    # Pre-create session ticket so all regions start with same baseline
                    print(f"    Pre-establishing session ticket for fair comparison...")
                    visited_sepp.tls_simulator.create_fs_ticket(client_sepp_id)
                
                server_thread = threading.Thread(target=visited_sepp.start_server)
                server_thread.daemon = True
                server_thread.start()
                time.sleep(1.0)
                
                # Warm-up handshake to eliminate first-connection overhead
                if test_method in ['psk_only', 'psk_ecdhe']:
                    print(f"    Performing warm-up handshake...")
                    warmup_metrics = home_sepp.connect_to_sepp(
                        'localhost', port,
                        connection_type='n32f',
                        resumption_method=test_method
                    )
                    time.sleep(0.1)
                
                # Run test iterations with geographical latency simulation
                for i in range(iterations):
                    if verbose:
                        print(f"    Iteration {i+1}/{iterations}")
                    
                    # Simulate network delay before TLS handshake (for realistic timing)
                    topology.simulate_network_delay(home_node.node_id, visited_node.node_id)
                    
                    # Perform TLS handshake
                    metrics = home_sepp.connect_to_sepp(
                        'localhost', port,
                        connection_type='n32f',
                        resumption_method=test_method
                    )
                    
                    # Include network latency in total time for fair geographical comparison
                    # Use the SAME network latency for all TLS variants to this destination
                    if metrics.success:
                        tls_time_ms = metrics.total_time * 1000
                        total_latency_ms = tls_time_ms + measured_network_latency_ms
                        metrics.total_time = total_latency_ms / 1000.0  # Convert back to seconds
                    
                    # Add geographical context to metrics
                    metrics.variant = f"{test_method}_geo_{visited_node.region}"
                    all_results.append(metrics)
                    
                    if verbose and metrics.success:
                        print(f"      TLS: {tls_time_ms:.1f}ms + Network: {measured_network_latency_ms:.1f}ms = Total: {total_latency_ms:.1f}ms")
                    
                    time.sleep(0.1)
                
                visited_sepp.stop_server()
                time.sleep(1.0)
    
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Geographical test interrupted by user{Style.RESET_ALL}")
    
    # Generate report
    config = TestConfiguration(
        test_type="geographical",
        iterations=len(all_results),
        geographical_nodes=[node.node_id for node in visited_nodes],
        resumption_methods=test_methods
    )
    
    start_time = time.time() - 300  # Approximate test duration
    end_time = time.time()
    report = monitor.create_performance_report(config, all_results, start_time, end_time)
    
    # Save results
    monitor.save_report(report, f"{output}/geographical_test_report.json")
    monitor.create_performance_plots(report, output)
    
    print(f"\n{Fore.GREEN}Geographical Test Complete!{Style.RESET_ALL}")
    monitor.print_summary_table(report)
    print(f"\nResults and visualizations saved to: {output}/")

@cli.command()
@click.option('--input-file', '-i', required=True,
              help='Path to test results JSON file')
def analyze(input_file: str):
    """Analyze previously saved test results"""
    if not os.path.exists(input_file):
        print(f"{Fore.RED}File not found: {input_file}{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}Analyzing test results from: {input_file}{Style.RESET_ALL}")
    
    with open(input_file, 'r') as f:
        report_data = json.load(f)
    
    # Display basic statistics
    print(f"\nTest Type: {report_data['test_config']['test_type']}")
    print(f"Total Iterations: {report_data['test_config']['iterations']}")
    print(f"Test Duration: {report_data['total_duration']:.2f} seconds")
    
    # Display variant statistics
    print(f"\n{Fore.CYAN}Performance Statistics:{Style.RESET_ALL}")
    for variant, stats in report_data['variant_statistics'].items():
        print(f"\n{variant}:")
        print(f"  Average: {stats['mean_ms']:.2f}ms")
        print(f"  Median:  {stats['median_ms']:.2f}ms")
        print(f"  95th percentile: {stats['p95_ms']:.2f}ms")
        print(f"  Success rate: {stats['success_rate']*100:.1f}%")
    
    # Display recommendations
    print(f"\n{Fore.CYAN}Recommendations:{Style.RESET_ALL}")
    for i, rec in enumerate(report_data['recommendations'], 1):
        print(f"  {i}. {rec}")

if __name__ == '__main__':
    cli() 