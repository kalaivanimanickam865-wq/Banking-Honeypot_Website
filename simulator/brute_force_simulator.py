"""
Banking Honeypot - Brute Force Attack Simulator
Educational tool for generating login traffic (normal + brute-force) for security testing
Author: Security Research Team
Purpose: Academic/Educational security testing on isolated honeypot systems
"""

import requests
import time
import random
import json
from datetime import datetime
from threading import Thread
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('honeypot_traffic.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class TrafficGenerator:
    """Generate normal and malicious login traffic to honeypot"""
    
    def __init__(self, target_url, output_file='traffic_analysis.json'):
        """
        Initialize the traffic generator
        
        Args:
            target_url: Base URL of the honeypot (e.g., http://localhost:8000)
            output_file: JSON file to store traffic records
        """
        self.target_url = target_url.rstrip('/')
        self.login_endpoint = f"{self.target_url}/login"
        self.output_file = output_file
        self.traffic_log = []
        self.stats = defaultdict(int)
        
        # Valid credentials for normal traffic (honeypot should accept these)
        self.valid_users = [
            {'username': 'admin', 'password': 'admin123'},
            {'username': 'user1', 'password': 'password123'},
            {'username': 'john_doe', 'password': 'john@2024'},
            {'username': 'test_user', 'password': 'test123'}
        ]
        
        # Common usernames for brute force attempts
        self.common_usernames = [
            'admin', 'user', 'root', 'test', 'guest', 'admin@example.com',
            'user1', 'user2', 'john', 'jane', 'manager', 'support'
        ]
        
        # Common passwords for brute force attempts
        self.common_passwords = [
            '123456', 'password', 'admin123', 'letmein', 'welcome',
            'monkey', 'dragon', 'master', 'sunshine', 'princess',
            'qwerty', '12345678', 'password123', 'admin', 'root'
        ]
        
        logger.info(f"Traffic Generator initialized for: {self.target_url}")
    
    def generate_normal_login(self, count=10, delay_range=(2, 8)):
        """
        Generate normal, legitimate login traffic
        
        Args:
            count: Number of normal login attempts
            delay_range: Tuple (min, max) seconds between requests
        """
        logger.info(f"Starting normal login traffic generation: {count} attempts")
        
        for i in range(count):
            # Select random valid user
            user = random.choice(self.valid_users)
            
            try:
                response = self._send_login_request(
                    user['username'],
                    user['password'],
                    is_brute_force=False
                )
                
                self._record_traffic(
                    username=user['username'],
                    password=user['password'],
                    status_code=response.status_code,
                    is_brute_force=False,
                    success=response.status_code == 200
                )
                
                logger.info(f"Normal login {i+1}/{count}: {user['username']} - {response.status_code}")
                
            except Exception as e:
                logger.error(f"Normal login attempt failed: {str(e)}")
                self._record_traffic(
                    username=user['username'],
                    password=user['password'],
                    status_code=0,
                    is_brute_force=False,
                    success=False,
                    error=str(e)
                )
            
            # Random delay between requests (realistic user behavior)
            delay = random.uniform(delay_range[0], delay_range[1])
            time.sleep(delay)
        
        self.stats['normal_attempts'] += count
        logger.info(f"Normal login traffic complete: {count} attempts sent")
    
    def generate_brute_force_attack(self, count=50, delay_range=(0.1, 0.5), target_user=None):
        """
        Generate brute force attack traffic with rapid invalid attempts
        
        Args:
            count: Number of brute force attempts
            delay_range: Tuple (min, max) seconds between requests (much shorter for brute force)
            target_user: Specific user to target, or None for random usernames
        """
        logger.warning(f"Starting brute force attack simulation: {count} attempts")
        
        for i in range(count):
            # Select username (target specific user or random)
            username = target_user if target_user else random.choice(self.common_usernames)
            password = random.choice(self.common_passwords)
            
            try:
                response = self._send_login_request(
                    username,
                    password,
                    is_brute_force=True
                )
                
                self._record_traffic(
                    username=username,
                    password=password,
                    status_code=response.status_code,
                    is_brute_force=True,
                    success=response.status_code == 200
                )
                
                logger.warning(f"Brute force {i+1}/{count}: {username} - Status: {response.status_code}")
                
            except Exception as e:
                logger.error(f"Brute force attempt failed: {str(e)}")
                self._record_traffic(
                    username=username,
                    password=password,
                    status_code=0,
                    is_brute_force=True,
                    success=False,
                    error=str(e)
                )
            
            # Very short delay (simulates rapid attack)
            delay = random.uniform(delay_range[0], delay_range[1])
            time.sleep(delay)
        
        self.stats['brute_force_attempts'] += count
        logger.warning(f"Brute force attack simulation complete: {count} attempts sent")
    
    def _send_login_request(self, username, password, is_brute_force=False):
        """
        Send HTTP login request to target
        
        Args:
            username: Username to attempt
            password: Password to attempt
            is_brute_force: Whether this is part of brute force attack
            
        Returns:
            Response object
        """
        payload = {
            'username': username,
            'password': password
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        try:
            response = requests.post(
                self.login_endpoint,
                json=payload,
                headers=headers,
                timeout=5,
                verify=False  # For testing against self-signed certs
            )
            return response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise
    
    def _record_traffic(self, username, password, status_code, is_brute_force, success, error=None):
        """Record traffic event for analysis"""
        record = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'password': password[:3] + '*' * len(password[3:]),  # Masked password
            'status_code': status_code,
            'is_brute_force': is_brute_force,
            'success': success,
            'error': error
        }
        self.traffic_log.append(record)
        
        # Update statistics
        if is_brute_force:
            self.stats['brute_force_success' if success else 'brute_force_failed'] += 1
        else:
            self.stats['normal_success' if success else 'normal_failed'] += 1
    
    def generate_mixed_traffic(self, normal_count=20, brute_force_count=100, 
                              concurrent=False, target_user='admin'):
        """
        Generate a realistic mix of normal and brute force traffic
        
        Args:
            normal_count: Number of normal login attempts
            brute_force_count: Number of brute force attempts
            concurrent: If True, run attacks in parallel threads
            target_user: User to target in brute force attack
        """
        logger.info("Starting mixed traffic generation")
        
        if concurrent:
            # Run in parallel threads
            thread1 = Thread(target=self.generate_normal_login, args=(normal_count,))
            thread2 = Thread(target=self.generate_brute_force_attack, 
                           args=(brute_force_count, (0.1, 0.3), target_user))
            
            thread1.start()
            time.sleep(5)  # Stagger the start
            thread2.start()
            
            thread1.join()
            thread2.join()
        else:
            # Sequential: normal traffic first, then brute force
            self.generate_normal_login(normal_count)
            time.sleep(5)
            self.generate_brute_force_attack(brute_force_count, target_user=target_user)
        
        logger.info("Mixed traffic generation complete")
    
    def save_analysis(self):
        """Save traffic data to JSON file"""
        output_data = {
            'generated_at': datetime.now().isoformat(),
            'statistics': dict(self.stats),
            'traffic_log': self.traffic_log
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"Traffic analysis saved to: {self.output_file}")
        return output_data
    
    def print_summary(self):
        """Print traffic generation summary"""
        print("\n" + "="*60)
        print("TRAFFIC GENERATION SUMMARY")
        print("="*60)
        print(f"Total Normal Attempts: {self.stats['normal_attempts']}")
        print(f"  ├─ Successful: {self.stats['normal_success']}")
        print(f"  └─ Failed: {self.stats['normal_failed']}")
        print(f"\nTotal Brute Force Attempts: {self.stats['brute_force_attempts']}")
        print(f"  ├─ Successful: {self.stats['brute_force_success']}")
        print(f"  └─ Failed: {self.stats['brute_force_failed']}")
        print(f"\nTotal Requests: {sum([self.stats['normal_attempts'], self.stats['brute_force_attempts']])}")
        print(f"Output File: {self.output_file}")
        print(f"Log File: honeypot_traffic.log")
        print("="*60 + "\n")


def main():
    """Main execution function"""
    
    # Configuration
    TARGET_URL = "http://localhost:5000"  # Change to your honeypot URL
    
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║   Banking Honeypot - Brute Force Attack Simulator          ║
    ║   Educational Tool for Security Testing                    ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize generator
    generator = TrafficGenerator(TARGET_URL)
    
    print("\nConfiguration:")
    print(f"  Target URL: {TARGET_URL}")
    print(f"  Output File: traffic_analysis.json")
    print(f"  Log File: honeypot_traffic.log")
    print("\nStarting traffic generation...\n")
    
    try:
        # Generate mixed traffic (normal + brute force)
        # This will run 20 normal login attempts, then 100 brute force attempts
        generator.generate_mixed_traffic(
            normal_count=20,
            brute_force_count=100,
            concurrent=False,  # Set to True for parallel execution
            target_user='admin'
        )
        
        # Save analysis
        analysis = generator.save_analysis()
        
        # Print summary
        generator.print_summary()
        
        print("✓ Traffic generation completed successfully!")
        print("✓ Check 'traffic_analysis.json' for detailed analysis")
        print("✓ Check 'honeypot_traffic.log' for full request logs")
        
    except KeyboardInterrupt:
        logger.warning("Traffic generation interrupted by user")
        generator.save_analysis()
        generator.print_summary()
        print("\n⚠ Generation stopped by user")
    
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        print(f"\n✗ Error during traffic generation: {str(e)}")


if __name__ == "__main__":
    main()
