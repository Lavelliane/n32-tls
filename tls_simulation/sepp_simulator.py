"""
SEPP (Security Edge Protection Proxy) Simulator for N32 Interface

Simulates 5G cross-border roaming communications between home and visited SEPPs
using TLS 1.3 with various resumption methods over the N32 interface.
"""

import socket
import threading
import time
import json
import ssl
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from .tls_handshake import TLSHandshakeSimulator, HandshakeMetrics
import logging

@dataclass
class SEPPConnection:
    """Represents a connection between home and visited SEPP"""
    connection_id: str
    home_sepp_id: str
    visited_sepp_id: str
    connection_type: str  # "n32c" or "n32f"
    established_time: float
    last_activity: float
    total_messages: int = 0
    total_bytes: int = 0

@dataclass
class N32Message:
    """N32 interface message structure"""
    message_id: str
    message_type: str  # "modify_request", "modify_response", etc.
    source_sepp: str
    dest_sepp: str
    payload_size: int
    timestamp: float
    requires_response: bool = True

class SEPPSimulator:
    """
    Simulates SEPP operations for N32 interface TLS performance testing
    """
    
    def __init__(self, sepp_id: str, is_home_sepp: bool = True, port: int = 8443):
        self.sepp_id = sepp_id
        self.is_home_sepp = is_home_sepp
        self.port = port
        self.tls_simulator = TLSHandshakeSimulator()
        
        # Connection management
        self.connections: Dict[str, SEPPConnection] = {}
        self.active_sessions: Dict[str, Dict] = {}
        
        # Performance tracking
        self.performance_log: List[HandshakeMetrics] = []
        self.message_log: List[N32Message] = []
        
        # 0-RTT FS ticket management for performance testing
        self.fs_ticket_batches: Dict[str, List] = {}  # Store pre-generated ticket batches
        self.fs_ticket_counters: Dict[str, int] = {}  # Track which ticket to use next
        self.fs_ticket_lock = threading.Lock()  # Thread-safe access to ticket counters
        
        # Server socket for listening
        self.server_socket: Optional[socket.socket] = None
        self.is_running = False
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(f"SEPP-{sepp_id}")
    
    def start_server(self):
        """Start the SEPP server to listen for incoming connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind(('localhost', self.port))
            self.server_socket.listen(10)
            self.is_running = True
            
            self.logger.info(f"SEPP {self.sepp_id} listening on port {self.port}")
            
            while self.is_running:
                try:
                    client_socket, address = self.server_socket.accept()
                    # Handle each connection in a separate thread
                    thread = threading.Thread(
                        target=self._handle_client_connection,
                        args=(client_socket, address)
                    )
                    thread.daemon = True
                    thread.start()
                except socket.error:
                    if self.is_running:
                        self.logger.error("Socket error in server loop")
                    break
                    
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
        finally:
            self._cleanup_server()
    
    def stop_server(self):
        """Stop the SEPP server"""
        self.is_running = False
        if self.server_socket:
            self.server_socket.close()
    
    def _handle_client_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle incoming client connection"""
        connection_id = f"{address[0]}:{address[1]}_{time.time()}"
        
        try:
            with client_socket:
                # Simulate receiving connection request
                data = client_socket.recv(1024)
                if data:
                    request = json.loads(data.decode())
                    self._process_connection_request(connection_id, request, client_socket)
                    
        except Exception as e:
            self.logger.error(f"Error handling client {connection_id}: {e}")
    
    def _process_connection_request(self, connection_id: str, request: Dict, 
                                   client_socket: socket.socket):
        """Process incoming connection request and perform TLS handshake"""
        request_type = request.get('type', 'unknown')
        client_sepp_id = request.get('sepp_id', 'unknown')
        resumption_method = request.get('resumption_method', 'full_handshake')
        
        metrics = None
        try:
            if request_type == 'n32c_handshake':
                # N32-c connection establishment
                metrics = self._perform_n32c_handshake(connection_id, client_sepp_id)
                self.performance_log.append(metrics)
                
            elif request_type == 'n32f_data':
                # N32-f data forwarding
                metrics = self._perform_n32f_communication(connection_id, client_sepp_id, request)
                self.performance_log.append(metrics)
            else:
                # Unknown request type
                self.logger.error(f"Unknown request type: {request_type}")
                metrics = HandshakeMetrics(
                    variant=resumption_method,
                    total_time=0.0,
                    round_trips=0,
                    bytes_sent=0,
                    bytes_received=0,
                    total_message_size=0,
                    crypto_operations={},
                    success=False,
                    error_message=f"Unknown request type: {request_type}"
                )
            
            # Send response back to client
            response = {
                'status': 'success' if metrics.success else 'error',
                'connection_id': connection_id,
                'metrics': asdict(metrics)
            }
            
            response_json = json.dumps(response)
            client_socket.send(response_json.encode())
            
        except Exception as e:
            self.logger.error(f"Error processing request {connection_id}: {e}")
            # Send error response
            error_response = {
                'status': 'error',
                'connection_id': connection_id,
                'metrics': asdict(HandshakeMetrics(
                    variant=resumption_method,
                    total_time=0.0,
                    round_trips=0,
                    bytes_sent=0,
                    bytes_received=0,
                    total_message_size=0,
                    crypto_operations={},
                    success=False,
                    error_message=str(e)
                ))
            }
            try:
                client_socket.send(json.dumps(error_response).encode())
            except:
                self.logger.error(f"Failed to send error response for {connection_id}")
    
    def _perform_n32c_handshake(self, connection_id: str, client_sepp_id: str) -> HandshakeMetrics:
        """
        Perform N32-c handshake (initial connection establishment)
        Uses full TLS 1.3 handshake with mutual authentication
        """
        self.logger.info(f"Performing N32-c handshake with {client_sepp_id}")
        
        # Full handshake with mutual authentication (required for N32-c)
        metrics = self.tls_simulator.full_handshake(
            client_id=client_sepp_id,
            server_cert=True,
            mutual_auth=True
        )
        
        if metrics.success:
            # Create connection record
            connection = SEPPConnection(
                connection_id=connection_id,
                home_sepp_id=self.sepp_id if self.is_home_sepp else client_sepp_id,
                visited_sepp_id=client_sepp_id if self.is_home_sepp else self.sepp_id,
                connection_type="n32c",
                established_time=time.time(),
                last_activity=time.time()
            )
            self.connections[connection_id] = connection
            
            # Create 0-RTT FS ticket for future resumptions
            self.tls_simulator.create_fs_ticket(client_sepp_id)
        
        return metrics
    
    def _perform_n32f_communication(self, connection_id: str, client_sepp_id: str, 
                                   request: Dict) -> HandshakeMetrics:
        """
        Perform N32-f data forwarding communication
        Uses TLS 1.3 mTLS with resumption capabilities
        """
        self.logger.info(f"Performing N32-f communication with {client_sepp_id}")
        
        resumption_method = request.get('resumption_method', 'full_handshake')
        
        if resumption_method == 'full_handshake':
            metrics = self.tls_simulator.full_handshake(
                client_id=client_sepp_id,
                mutual_auth=True
            )
        elif resumption_method == 'psk_only':
            # Ensure session ticket exists for PSK resumption
            if client_sepp_id not in self.tls_simulator.session_tickets:
                self.tls_simulator.create_fs_ticket(client_sepp_id)
            
            metrics = self.tls_simulator.psk_resumption(
                client_id=client_sepp_id,
                use_ecdhe=False
            )
        elif resumption_method == 'psk_ecdhe':
            # Ensure session ticket exists for PSK resumption
            if client_sepp_id not in self.tls_simulator.session_tickets:
                self.tls_simulator.create_fs_ticket(client_sepp_id)
                
            metrics = self.tls_simulator.psk_resumption(
                client_id=client_sepp_id,
                use_ecdhe=True
            )
        elif resumption_method == '0rtt':
            # Ensure session ticket exists for 0-RTT resumption
            if client_sepp_id not in self.tls_simulator.session_tickets:
                self.tls_simulator.create_fs_ticket(client_sepp_id)
                
            metrics = self.tls_simulator.zero_rtt_resumption(
                client_id=client_sepp_id
            )
        elif resumption_method == '0rtt_fs':
            # Use pre-generated ticket if available, otherwise create one
            ticket_client_id = None
            use_batch = False
            
            # Thread-safe ticket selection
            with self.fs_ticket_lock:
                if client_sepp_id in self.fs_ticket_batches and self.fs_ticket_batches[client_sepp_id]:
                    counter = self.fs_ticket_counters.get(client_sepp_id, 0)
                    if counter < len(self.fs_ticket_batches[client_sepp_id]):
                        ticket_client_id = f"{client_sepp_id}_batch_{counter}"
                        self.fs_ticket_counters[client_sepp_id] = counter + 1
                        use_batch = True
                    else:
                        self.logger.warning(f"0-RTT FS ticket batch exhausted for {client_sepp_id}")
            
            # Perform handshake outside the lock
            if use_batch and ticket_client_id:
                metrics = self.tls_simulator.zero_rtt_fs_resumption_with_ticket(
                    client_id=ticket_client_id
                )
            else:
                # Fallback to regular method
                metrics = self.tls_simulator.zero_rtt_fs_resumption(
                    client_id=client_sepp_id
                )
        else:
            raise ValueError(f"Unknown resumption method: {resumption_method}")
        
        if metrics.success:
            # Update connection activity
            if connection_id in self.connections:
                self.connections[connection_id].last_activity = time.time()
                self.connections[connection_id].total_messages += 1
                self.connections[connection_id].total_bytes += (
                    metrics.bytes_sent + metrics.bytes_received
                )
        
        return metrics
    
    def connect_to_sepp(self, target_host: str, target_port: int, 
                       connection_type: str = 'n32c', 
                       resumption_method: str = 'full_handshake') -> HandshakeMetrics:
        """
        Connect to another SEPP (client role)
        """
        try:
            # Create client socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10.0)  # 10 second timeout
            
            with client_socket:
                # Connect to target SEPP
                client_socket.connect((target_host, target_port))
                
                # Prepare connection request
                request = {
                    'type': f'{connection_type}_handshake' if connection_type == 'n32c' else 'n32f_data',
                    'sepp_id': self.sepp_id,
                    'resumption_method': resumption_method,
                    'timestamp': time.time()
                }
                
                # Send request
                client_socket.send(json.dumps(request).encode())
                
                # Receive response
                response_data = client_socket.recv(4096)
                response = json.loads(response_data.decode())
                
                # Extract metrics from response
                metrics_data = response.get('metrics', {})
                metrics = HandshakeMetrics(**metrics_data)
                
                return metrics
                
        except Exception as e:
            self.logger.error(f"Failed to connect to SEPP at {target_host}:{target_port}: {e}")
            return HandshakeMetrics(
                variant=resumption_method,
                total_time=0.0,
                round_trips=0,
                bytes_sent=0,
                bytes_received=0,
                total_message_size=0,
                crypto_operations={},
                success=False,
                error_message=str(e)
            )
    
    def simulate_n32_message_flow(self, target_sepp_host: str, target_sepp_port: int,
                                 message_count: int = 10, 
                                 resumption_methods: List[str] = None) -> List[HandshakeMetrics]:
        """
        Simulate a series of N32 messages with different resumption methods
        """
        if resumption_methods is None:
            resumption_methods = ['full_handshake', 'psk_only', 'psk_ecdhe', '0rtt', '0rtt_fs']
        
        results = []
        
        # First establish N32-c connection
        self.logger.info("Establishing initial N32-c connection...")
        initial_metrics = self.connect_to_sepp(
            target_sepp_host, target_sepp_port, 
            connection_type='n32c'
        )
        results.append(initial_metrics)
        
        if not initial_metrics.success:
            self.logger.error("Failed to establish initial connection")
            return results
        
        # Simulate message flow with different resumption methods
        for i in range(message_count):
            method = resumption_methods[i % len(resumption_methods)]
            
            self.logger.info(f"Sending N32-f message {i+1}/{message_count} using {method}")
            
            metrics = self.connect_to_sepp(
                target_sepp_host, target_sepp_port,
                connection_type='n32f',
                resumption_method=method
            )
            
            results.append(metrics)
            
            # Small delay between messages
            time.sleep(0.1)
        
        return results
    
    def simulate_concurrent_connections(self, target_sepp_host: str, target_sepp_port: int,
                                      concurrent_users: int = 5,
                                      messages_per_user: int = 5,
                                      resumption_method: str = 'psk_only') -> List[HandshakeMetrics]:
        """
        Simulate concurrent connections to test load performance
        """
        results = []
        threads = []
        results_lock = threading.Lock()  # Thread-safe results collection
        
        def user_simulation(user_id: int):
            user_results = []
            user_sepp_id = f"{self.sepp_id}_user_{user_id}"
            
            try:
                for msg_idx in range(messages_per_user):
                    try:
                        # For 0-RTT FS, we need to ensure each request uses a unique client ID
                        # to get a fresh ticket from the batch
                        if resumption_method == '0rtt_fs':
                            # Use the main client ID for the ticket batch (all users share the same batch)
                            # but the server will pick the next available ticket automatically
                            metrics = self.connect_to_sepp(
                                target_sepp_host, target_sepp_port,
                                connection_type='n32f',
                                resumption_method=resumption_method
                            )
                        else:
                            metrics = self.connect_to_sepp(
                                target_sepp_host, target_sepp_port,
                                connection_type='n32f',
                                resumption_method=resumption_method
                            )
                        
                        if metrics:  # Only add non-None results
                            user_results.append(metrics)
                        else:
                            self.logger.warning(f"User {user_id} msg {msg_idx}: received None metrics")
                            
                        time.sleep(0.05)  # Small delay between user messages
                        
                    except Exception as e:
                        self.logger.error(f"User {user_id} msg {msg_idx} failed: {e}")
                        # Create a failed metrics object
                        failed_metrics = HandshakeMetrics(
                            variant=resumption_method,
                            total_time=0.0,
                            round_trips=0,
                            bytes_sent=0,
                            bytes_received=0,
                            total_message_size=0,
                            crypto_operations={},
                            success=False,
                            error_message=str(e)
                        )
                        user_results.append(failed_metrics)
                
                # Thread-safe addition to results
                with results_lock:
                    results.extend(user_results)
                    self.logger.info(f"User {user_id} completed: {len(user_results)} results")
                    
            except Exception as e:
                self.logger.error(f"User {user_id} thread failed: {e}")
        
        # Start concurrent user threads
        for user_id in range(concurrent_users):
            thread = threading.Thread(target=user_simulation, args=(user_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        self.logger.info(f"Concurrent test completed: {len(results)} total results")
        return results
    
    def prepare_0rtt_fs_ticket_batch(self, client_sepp_id: str, batch_size: int = 1000):
        """
        Pre-generate a batch of 0-RTT FS tickets for performance testing.
        
        This separates ticket generation time from resumption performance measurement,
        since each nonce can only be used once.
        
        Args:
            client_sepp_id: Client SEPP identifier
            batch_size: Number of tickets to generate (default: 1000)
        """
        self.logger.info(f"Pre-generating {batch_size} 0-RTT FS tickets for {client_sepp_id}")
        
        # Generate batch of tickets
        start_time = time.time()
        tickets = self.tls_simulator.create_fs_ticket_batch(client_sepp_id, batch_size)
        generation_time = time.time() - start_time
        
        # Store the batch and reset counter
        self.fs_ticket_batches[client_sepp_id] = tickets
        self.fs_ticket_counters[client_sepp_id] = 0
        
        self.logger.info(f"Generated {len(tickets)} tickets in {generation_time:.3f}s "
                        f"({generation_time/batch_size*1000:.2f}ms per ticket)")
        
        return tickets
    
    def get_remaining_fs_tickets(self, client_sepp_id: str) -> int:
        """Get number of remaining unused 0-RTT FS tickets for a client"""
        with self.fs_ticket_lock:
            if client_sepp_id not in self.fs_ticket_batches:
                return 0
            
            total_tickets = len(self.fs_ticket_batches[client_sepp_id])
            used_tickets = self.fs_ticket_counters.get(client_sepp_id, 0)
            return max(0, total_tickets - used_tickets)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary statistics"""
        if not self.performance_log:
            return {"error": "No performance data available"}
        
        # Group metrics by variant
        variant_metrics = {}
        for metrics in self.performance_log:
            variant = metrics.variant
            if variant not in variant_metrics:
                variant_metrics[variant] = {
                    'times': [],
                    'round_trips': [],
                    'bytes_sent': [],
                    'bytes_received': [],
                    'success_count': 0,
                    'failure_count': 0
                }
            
            variant_metrics[variant]['times'].append(metrics.total_time)
            variant_metrics[variant]['round_trips'].append(metrics.round_trips)
            variant_metrics[variant]['bytes_sent'].append(metrics.bytes_sent)
            variant_metrics[variant]['bytes_received'].append(metrics.bytes_received)
            
            if metrics.success:
                variant_metrics[variant]['success_count'] += 1
            else:
                variant_metrics[variant]['failure_count'] += 1
        
        # Calculate statistics
        summary = {}
        for variant, data in variant_metrics.items():
            if data['times']:
                summary[variant] = {
                    'avg_time_ms': sum(data['times']) / len(data['times']) * 1000,
                    'min_time_ms': min(data['times']) * 1000,
                    'max_time_ms': max(data['times']) * 1000,
                    'avg_round_trips': sum(data['round_trips']) / len(data['round_trips']),
                    'avg_bytes_sent': sum(data['bytes_sent']) / len(data['bytes_sent']),
                    'avg_bytes_received': sum(data['bytes_received']) / len(data['bytes_received']),
                    'success_rate': data['success_count'] / (data['success_count'] + data['failure_count']),
                    'total_attempts': data['success_count'] + data['failure_count']
                }
        
        return summary
    
    def _cleanup_server(self):
        """Clean up server resources"""
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.server_socket = None
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        self.stop_server() 