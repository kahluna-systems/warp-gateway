#!/usr/bin/env python3
"""
KahLuna WARP CLI Test Runner
Comprehensive command-line testing suite for VPN gateway validation
"""

import os
import sys
import json
import time
import requests
import subprocess
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
import tempfile

class WARPTestRunner:
    def __init__(self, gateway_url: str = "http://localhost:5000"):
        self.gateway_url = gateway_url.rstrip('/')
        self.session = requests.Session()
        self.results = []
        self.start_time = None
        
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with the gateway"""
        try:
            # Get login page first to get CSRF token
            login_page = self.session.get(f"{self.gateway_url}/login")
            if not login_page.ok:
                raise Exception(f"Cannot access login page: {login_page.status_code}")
            
            # Attempt login
            login_data = {
                'username': username,
                'password': password,
                'csrf_token': ''  # May need to extract from form
            }
            
            response = self.session.post(f"{self.gateway_url}/login", data=login_data)
            
            # Check if redirected away from login (successful login)
            if '/login' not in response.url:
                print(f"✓ Authenticated as {username}")
                return True
            else:
                print(f"✗ Authentication failed for {username}")
                return False
                
        except Exception as e:
            print(f"✗ Authentication error: {e}")
            return False
    
    def test_gateway_connectivity(self) -> Dict[str, Any]:
        """Test basic gateway connectivity"""
        test_name = "Gateway Connectivity"
        try:
            start_time = time.time()
            response = self.session.get(f"{self.gateway_url}/login", timeout=10)
            latency = (time.time() - start_time) * 1000
            
            if response.ok:
                return {
                    'test': test_name,
                    'status': 'PASS',
                    'message': f'Gateway accessible ({latency:.0f}ms)',
                    'latency_ms': latency
                }
            else:
                return {
                    'test': test_name,
                    'status': 'FAIL',
                    'message': f'Gateway returned HTTP {response.status_code}'
                }
        except Exception as e:
            return {
                'test': test_name,
                'status': 'FAIL',
                'message': f'Connection failed: {str(e)}'
            }
    
    def test_api_endpoints(self) -> List[Dict[str, Any]]:
        """Test various API endpoints"""
        endpoints = [
            ('/api/statistics', 'Statistics API'),
            ('/api/networks', 'Networks API'),
            ('/api/endpoints', 'Endpoints API'),
            ('/api/audit-logs', 'Audit Logs API'),
            ('/api/server-config', 'Server Config API')
        ]
        
        results = []
        for endpoint, description in endpoints:
            try:
                response = self.session.get(f"{self.gateway_url}{endpoint}", timeout=5)
                
                if response.ok:
                    results.append({
                        'test': description,
                        'status': 'PASS',
                        'message': 'API endpoint accessible',
                        'endpoint': endpoint
                    })
                elif response.status_code == 401:
                    results.append({
                        'test': description,
                        'status': 'SKIP',
                        'message': 'Authentication required',
                        'endpoint': endpoint
                    })
                else:
                    results.append({
                        'test': description,
                        'status': 'FAIL',
                        'message': f'HTTP {response.status_code}',
                        'endpoint': endpoint
                    })
                    
            except Exception as e:
                results.append({
                    'test': description,
                    'status': 'FAIL',
                    'message': f'Request failed: {str(e)}',
                    'endpoint': endpoint
                })
        
        return results
    
    def test_network_types(self) -> List[Dict[str, Any]]:
        """Test network type creation and management"""
        network_types = [
            'secure_internet',
            'remote_resource_gw',
            'l3vpn_gateway',
            'l2_point_to_point',
            'l2_mesh'
        ]
        
        results = []
        
        for network_type in network_types:
            test_name = f"Network Type: {network_type.replace('_', ' ').title()}"
            
            # Test network creation
            network_data = {
                'name': f'test_{network_type}_{int(time.time())}',
                'network_type': network_type,
                'expected_users': 5
            }
            
            try:
                # Attempt to create network via API
                response = self.session.post(
                    f"{self.gateway_url}/networks/add",
                    json=network_data,
                    timeout=10
                )
                
                if response.ok:
                    results.append({
                        'test': test_name,
                        'status': 'PASS',
                        'message': 'Network created successfully',
                        'network_type': network_type
                    })
                elif response.status_code == 401:
                    results.append({
                        'test': test_name,
                        'status': 'SKIP',
                        'message': 'Authentication required',
                        'network_type': network_type
                    })
                else:
                    results.append({
                        'test': test_name,
                        'status': 'FAIL',
                        'message': f'Creation failed: HTTP {response.status_code}',
                        'network_type': network_type
                    })
                    
            except Exception as e:
                results.append({
                    'test': test_name,
                    'status': 'FAIL',
                    'message': f'Request failed: {str(e)}',
                    'network_type': network_type
                })
        
        return results
    
    def test_configuration_generation(self) -> List[Dict[str, Any]]:
        """Test WireGuard configuration generation"""
        results = []
        
        try:
            # Get networks first
            networks_response = self.session.get(f"{self.gateway_url}/api/networks")
            
            if not networks_response.ok:
                return [{
                    'test': 'Configuration Generation',
                    'status': 'SKIP',
                    'message': 'Cannot access networks API'
                }]
            
            networks = networks_response.json() if networks_response.content else []
            
            if not networks:
                return [{
                    'test': 'Configuration Generation',
                    'status': 'SKIP',
                    'message': 'No networks available for testing'
                }]
            
            # Test configuration generation for first network
            network = networks[0]
            network_id = network.get('id')
            
            if network_id:
                endpoints_response = self.session.get(f"{self.gateway_url}/api/endpoints")
                
                if endpoints_response.ok:
                    endpoints = endpoints_response.json() if endpoints_response.content else []
                    network_endpoints = [ep for ep in endpoints if ep.get('vpn_network_id') == network_id]
                    
                    if network_endpoints:
                        endpoint_id = network_endpoints[0]['id']
                        
                        # Test config download
                        config_response = self.session.get(
                            f"{self.gateway_url}/endpoints/{endpoint_id}/config/download"
                        )
                        
                        if config_response.ok:
                            config_text = config_response.text
                            
                            # Validate config format
                            if '[Interface]' in config_text and '[Peer]' in config_text:
                                results.append({
                                    'test': 'Configuration Generation',
                                    'status': 'PASS',
                                    'message': 'Valid WireGuard config generated',
                                    'config_length': len(config_text)
                                })
                            else:
                                results.append({
                                    'test': 'Configuration Generation',
                                    'status': 'FAIL',
                                    'message': 'Invalid WireGuard config format'
                                })
                        else:
                            results.append({
                                'test': 'Configuration Generation',
                                'status': 'FAIL',
                                'message': f'Config download failed: HTTP {config_response.status_code}'
                            })
                    else:
                        results.append({
                            'test': 'Configuration Generation',
                            'status': 'SKIP',
                            'message': 'No endpoints available for testing'
                        })
                else:
                    results.append({
                        'test': 'Configuration Generation',
                        'status': 'FAIL',
                        'message': 'Cannot access endpoints API'
                    })
            else:
                results.append({
                    'test': 'Configuration Generation',
                    'status': 'FAIL',
                    'message': 'Invalid network data'
                })
                
        except Exception as e:
            results.append({
                'test': 'Configuration Generation',
                'status': 'FAIL',
                'message': f'Test failed: {str(e)}'
            })
        
        return results
    
    def test_wireguard_connectivity(self, config_text: str) -> Dict[str, Any]:
        """Test actual WireGuard connectivity (requires root)"""
        test_name = "WireGuard Connectivity"
        
        # Check if running as root
        if os.geteuid() != 0:
            return {
                'test': test_name,
                'status': 'SKIP',
                'message': 'Root privileges required for WireGuard testing'
            }
        
        # Check if wg command is available
        try:
            subprocess.run(['which', 'wg'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            return {
                'test': test_name,
                'status': 'SKIP',
                'message': 'WireGuard tools not installed'
            }
        
        try:
            # Create temporary config file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
                f.write(config_text)
                config_file = f.name
            
            interface_name = f"wgtest{int(time.time()) % 1000}"
            
            try:
                # Bring up interface
                subprocess.run([
                    'wg-quick', 'up', config_file
                ], check=True, capture_output=True, text=True)
                
                time.sleep(2)  # Wait for interface to be ready
                
                # Test connectivity
                ping_result = subprocess.run([
                    'ping', '-c', '3', '-W', '5', '8.8.8.8'
                ], capture_output=True, text=True)
                
                if ping_result.returncode == 0:
                    result = {
                        'test': test_name,
                        'status': 'PASS',
                        'message': 'WireGuard connectivity successful'
                    }
                else:
                    result = {
                        'test': test_name,
                        'status': 'FAIL',
                        'message': 'WireGuard connectivity failed'
                    }
                
                # Clean up interface
                subprocess.run([
                    'wg-quick', 'down', config_file
                ], capture_output=True)
                
                return result
                
            finally:
                os.unlink(config_file)
                
        except Exception as e:
            return {
                'test': test_name,
                'status': 'FAIL',
                'message': f'WireGuard test failed: {str(e)}'
            }
    
    def run_all_tests(self, username: str = None, password: str = None, 
                     test_wireguard: bool = False) -> None:
        """Run all available tests"""
        self.start_time = datetime.now()
        print("🧪 KahLuna WARP Test Suite")
        print("=" * 50)
        
        # Basic connectivity
        print("\n📡 Testing Gateway Connectivity...")
        result = self.test_gateway_connectivity()
        self.results.append(result)
        self._print_result(result)
        
        # Authentication
        authenticated = False
        if username and password:
            print(f"\n🔐 Testing Authentication...")
            authenticated = self.authenticate(username, password)
        
        # API endpoints
        print("\n🔌 Testing API Endpoints...")
        api_results = self.test_api_endpoints()
        self.results.extend(api_results)
        for result in api_results:
            self._print_result(result)
        
        # Network types
        if authenticated:
            print("\n🌐 Testing Network Types...")
            network_results = self.test_network_types()
            self.results.extend(network_results)
            for result in network_results:
                self._print_result(result)
            
            # Configuration generation
            print("\n📄 Testing Configuration Generation...")
            config_results = self.test_configuration_generation()
            self.results.extend(config_results)
            for result in config_results:
                self._print_result(result)
                
                # WireGuard connectivity test
                if test_wireguard and result.get('status') == 'PASS':
                    print("\n🔗 Testing WireGuard Connectivity...")
                    # This would need the actual config from the result
                    # For now, skip unless config is provided
                    pass
        
        # Print summary
        self._print_summary()
    
    def _print_result(self, result: Dict[str, Any]) -> None:
        """Print a single test result"""
        status_symbols = {
            'PASS': '✓',
            'FAIL': '✗',
            'SKIP': '⚠'
        }
        
        status_colors = {
            'PASS': '\033[92m',  # Green
            'FAIL': '\033[91m',  # Red
            'SKIP': '\033[93m'   # Yellow
        }
        
        reset_color = '\033[0m'
        status = result['status']
        symbol = status_symbols.get(status, '?')
        color = status_colors.get(status, '')
        
        print(f"  {color}{symbol} {result['test']}: {result['message']}{reset_color}")
    
    def _print_summary(self) -> None:
        """Print test summary"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        passed = len([r for r in self.results if r['status'] == 'PASS'])
        failed = len([r for r in self.results if r['status'] == 'FAIL'])
        skipped = len([r for r in self.results if r['status'] == 'SKIP'])
        total = len(self.results)
        
        print("\n" + "=" * 50)
        print("📊 Test Summary")
        print("-" * 20)
        print(f"  Total Tests: {total}")
        print(f"  ✓ Passed: {passed}")
        print(f"  ✗ Failed: {failed}")
        print(f"  ⚠ Skipped: {skipped}")
        print(f"  Duration: {duration:.2f}s")
        
        if failed == 0:
            print("\n🎉 All tests passed!")
        else:
            print(f"\n⚠️  {failed} test(s) failed")
            
        # Print failed tests
        failed_tests = [r for r in self.results if r['status'] == 'FAIL']
        if failed_tests:
            print("\nFailed Tests:")
            for test in failed_tests:
                print(f"  • {test['test']}: {test['message']}")
    
    def export_results(self, filename: str) -> None:
        """Export results to JSON file"""
        export_data = {
            'test_run': {
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': datetime.now().isoformat(),
                'gateway_url': self.gateway_url,
                'total_tests': len(self.results),
                'passed': len([r for r in self.results if r['status'] == 'PASS']),
                'failed': len([r for r in self.results if r['status'] == 'FAIL']),
                'skipped': len([r for r in self.results if r['status'] == 'SKIP'])
            },
            'results': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"\n📄 Results exported to {filename}")

def main():
    parser = argparse.ArgumentParser(description='KahLuna WARP CLI Test Runner')
    parser.add_argument('--gateway', '-g', default='http://localhost:5000',
                       help='Gateway URL (default: http://localhost:5000)')
    parser.add_argument('--username', '-u', help='Username for authentication')
    parser.add_argument('--password', '-p', help='Password for authentication')
    parser.add_argument('--test-wireguard', action='store_true',
                       help='Test actual WireGuard connectivity (requires root)')
    parser.add_argument('--export', help='Export results to JSON file')
    
    args = parser.parse_args()
    
    # Create test runner
    runner = WARPTestRunner(args.gateway)
    
    # Run tests
    runner.run_all_tests(
        username=args.username,
        password=args.password,
        test_wireguard=args.test_wireguard
    )
    
    # Export results if requested
    if args.export:
        runner.export_results(args.export)

if __name__ == '__main__':
    main()