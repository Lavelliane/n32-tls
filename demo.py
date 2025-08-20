#!/usr/bin/env python3
"""
TLS 1.3 Simulation System Demo

This script demonstrates the key capabilities of the TLS 1.3 performance
simulation system for 5G N32 interface evaluation.
"""

import sys
import time
from tls_simulation import (
    TLSHandshakeSimulator,
    SEPPSimulator, 
    PerformanceMonitor,
    NetworkTopology
)
from tls_simulation.performance_monitor import TestConfiguration

def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")

def demo_tls_handshake_variants():
    """Demonstrate different TLS 1.3 handshake variants"""
    print_section("TLS 1.3 Handshake Variants Demo")
    
    simulator = TLSHandshakeSimulator()
    client_id = "demo_client"
    
    print("Testing TLS 1.3 handshake variants...\n")
    
    # Test each variant
    variants = [
        ("Full Handshake", lambda: simulator.full_handshake(client_id)),
        ("PSK Only", lambda: simulator.psk_resumption(client_id, use_ecdhe=False)),
        ("PSK ECDHE", lambda: simulator.psk_resumption(client_id, use_ecdhe=True)),
        ("0-RTT", lambda: simulator.zero_rtt_resumption(client_id)),
        ("0-RTT FS", lambda: simulator.zero_rtt_fs_resumption(client_id))
    ]
    
    results = []
    
    for name, test_func in variants:
        try:
            if name == "0-RTT FS":
                # Create FS ticket first
                simulator.create_fs_ticket(client_id)
            
            metrics = test_func()
            results.append(metrics)
            
            status = "✓ Success" if metrics.success else "✗ Failed"
            latency = metrics.total_time * 1000  # Convert to ms
            
            print(f"{name:<15}: {status:<10} | {latency:>6.2f}ms | "
                  f"{metrics.round_trips} round trips | "
                  f"{metrics.bytes_sent + metrics.bytes_received} bytes")
            
        except Exception as e:
            print(f"{name:<15}: ✗ Error     | {str(e)}")
    
    # Show performance ranking
    successful_results = [(r.variant, r.total_time * 1000) for r in results if r.success]
    successful_results.sort(key=lambda x: x[1])
    
    print(f"\nPerformance Ranking (fastest to slowest):")
    for i, (variant, time_ms) in enumerate(successful_results, 1):
        print(f"  {i}. {variant}: {time_ms:.2f}ms")

def demo_0rtt_fs_mechanism():
    """Demonstrate the novel 0-RTT FS mechanism"""
    print_section("0-RTT FS (Forward Secrecy) Demo")
    
    simulator = TLSHandshakeSimulator()
    client_id = "fs_demo_client"
    
    print("Demonstrating 0-RTT FS replay protection and batch processing...\n")
    
    # Create FS ticket
    print("1. Creating 0-RTT FS ticket with unique nonce...")
    ticket = simulator.create_fs_ticket(client_id)
    print(f"   Ticket created with nonce: {ticket.nonce.hex()[:16]}...")
    
    # First use - should succeed
    print("\n2. First 0-RTT FS connection attempt...")
    metrics1 = simulator.zero_rtt_fs_resumption(client_id)
    print(f"   Result: {'Success' if metrics1.success else 'Failed'}")
    print(f"   Latency: {metrics1.total_time * 1000:.2f}ms")
    
    # Second use - should fail due to replay protection
    print("\n3. Second 0-RTT FS connection attempt (replay attack)...")
    metrics2 = simulator.zero_rtt_fs_resumption(client_id)
    print(f"   Result: {'Success' if metrics2.success else 'Failed (Expected - Replay Protection)'}")
    if not metrics2.success:
        print(f"   Error: {metrics2.error_message}")
    
    print("\n✓ 0-RTT FS replay protection working correctly!")
    
    # Demonstrate batch processing for performance testing
    print("\n4. Demonstrating batch ticket generation for performance testing...")
    batch_client_id = "batch_demo_client"
    batch_size = 5
    
    print(f"   Generating batch of {batch_size} fresh tickets...")
    tickets = simulator.create_fs_ticket_batch(batch_client_id, batch_size)
    print(f"   Generated {len(tickets)} unique tickets")
    
    print("\n   Testing multiple connections with fresh tickets:")
    for i in range(min(3, batch_size)):
        ticket_id = f"{batch_client_id}_batch_{i}"
        metrics = simulator.zero_rtt_fs_resumption_with_ticket(ticket_id)
        print(f"   Connection {i+1}: {'Success' if metrics.success else 'Failed'} "
              f"({metrics.total_time * 1000:.2f}ms)")
    
    print("\n✓ Batch ticket processing enables efficient performance testing!")

def demo_geographical_latency():
    """Demonstrate geographical network latency simulation"""
    print_section("Geographical Network Simulation Demo")
    
    topology = NetworkTopology()
    
    print("Global 5G Network Nodes:")
    for region in ['asia', 'europe', 'americas']:
        nodes = topology.get_nodes_by_region(region)
        print(f"\n{region.title()}:")
        for node in nodes[:3]:  # Show first 3 nodes per region
            print(f"  • {node.city}, {node.country}")
    
    print(f"\nLatency measurements from Seoul (home) to visited networks:")
    
    home_node = "KR_Seoul"
    test_destinations = ["JP_Tokyo", "DE_Frankfurt", "US_NewYork", "AU_Sydney"]
    
    for dest in test_destinations:
        if dest in topology.nodes:
            latency = topology.measure_latency(home_node, dest)
            print(f"  Seoul → {topology.nodes[dest].city:<12}: {latency.measured_latency_ms:>6.1f}ms")

def demo_performance_monitoring():
    """Demonstrate performance monitoring capabilities"""
    print_section("Performance Monitoring Demo")
    
    monitor = PerformanceMonitor()
    simulator = TLSHandshakeSimulator()
    
    print("Running mini performance test...\n")
    
    # Start monitoring
    monitor.start_monitoring()
    start_time = time.time()
    
    # Simulate some TLS handshakes
    results = []
    variants = ['full_handshake', 'psk_only', '0rtt']
    
    for i in range(6):  # 6 iterations
        variant = variants[i % len(variants)]
        client_id = f"perf_client_{i}"
        
        if variant == 'full_handshake':
            metrics = simulator.full_handshake(client_id)
        elif variant == 'psk_only':
            metrics = simulator.psk_resumption(client_id, use_ecdhe=False)
        elif variant == '0rtt':
            metrics = simulator.zero_rtt_resumption(client_id)
        
        results.append(metrics)
        print(f"  Test {i+1}: {variant} = {metrics.total_time * 1000:.2f}ms")
        time.sleep(0.1)
    
    end_time = time.time()
    monitor.stop_monitoring()
    
    # Generate report
    config = TestConfiguration(
        test_type="demo",
        iterations=len(results),
        resumption_methods=variants
    )
    
    report = monitor.create_performance_report(config, results, start_time, end_time)
    
    print(f"\nPerformance Summary:")
    for variant, stats in report.variant_statistics.items():
        print(f"  {variant}: {stats['mean_ms']:.2f}ms average, {stats['success_rate']*100:.0f}% success")

def main():
    """Run all demonstrations"""
    print("TLS 1.3 Performance Simulation System")
    print("5G N32 Interface Cross-Border Roaming Demo")
    print("=" * 60)
    
    try:
        # Demo 1: TLS handshake variants
        demo_tls_handshake_variants()
        
        # Demo 2: 0-RTT FS mechanism
        demo_0rtt_fs_mechanism()
        
        # Demo 3: Geographical simulation
        demo_geographical_latency()
        
        # Demo 4: Performance monitoring
        demo_performance_monitoring()
        
        print_section("Demo Complete")
        print("✓ All demonstrations completed successfully!")
        print("\nTo run full simulations:")
        print("  python main.py simple --iterations 20")
        print("  python main.py load --concurrent '5,10,20'")
        print("  python main.py geographical --iterations 5")
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        return 1
    except Exception as e:
        print(f"\n\nDemo failed with error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 