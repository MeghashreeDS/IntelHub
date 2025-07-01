import os
import json
import time
import datetime
import requests
import pymongo
from dotenv import load_dotenv
from typing import Dict, List, Any, Optional

# Load environment variables
load_dotenv()

# MongoDB connection
def connect_to_mongodb():
    """Connect to MongoDB and return database connection"""
    mongo_uri = os.getenv("MONGODB_URI")
    client = pymongo.MongoClient(mongo_uri)
    db = client.get_database("threat_intelligence")
    return db

# Initialize database collections
def initialize_collections(db):
    """Initialize database collections with proper indexes"""
    # Malicious IPs collection
    if "malicious_ips" not in db.list_collection_names():
        db.create_collection("malicious_ips")
        db.malicious_ips.create_index("ip", unique=True)
        db.malicious_ips.create_index("last_updated")
    
    # Malicious domains collection
    if "malicious_domains" not in db.list_collection_names():
        db.create_collection("malicious_domains")
        db.malicious_domains.create_index("domain", unique=True)
        db.malicious_domains.create_index("last_updated")
    
    # Vulnerabilities collection
    if "vulnerabilities" not in db.list_collection_names():
        db.create_collection("vulnerabilities")
        db.vulnerabilities.create_index("cve_id", unique=True)
        db.vulnerabilities.create_index("last_updated")
    
    # Threat actors collection
    if "threat_actors" not in db.list_collection_names():
        db.create_collection("threat_actors")
        db.threat_actors.create_index("actor_id", unique=True)
        db.threat_actors.create_index("last_updated")
    
    # IOCs collection (Indicators of Compromise)
    if "iocs" not in db.list_collection_names():
        db.create_collection("iocs")
        db.iocs.create_index([("indicator", 1), ("type", 1)], unique=True)
        db.iocs.create_index("last_updated")

    return {
        "malicious_ips": db.malicious_ips,
        "malicious_domains": db.malicious_domains,
        "vulnerabilities": db.vulnerabilities,
        "threat_actors": db.threat_actors,
        "iocs": db.iocs
    }

# API Data Collectors
class ThreatIntelligenceCollector:
    def __init__(self, db_collections):
        self.collections = db_collections
        # API Keys - store these in .env file
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.alienvault_api_key = os.getenv("ALIENVAULT_API_KEY")
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        self.misp_api_key = os.getenv("MISP_API_KEY")
        self.circl_api_key = os.getenv("CIRCL_API_KEY")
        self.nvd_api_key = os.getenv("NVD_API_KEY")
        self.threatfox_api_key = os.getenv("THREATFOX_API_KEY")

    def collect_all(self):
        """Run all collectors"""
        self.collect_malicious_ips()
        self.collect_malicious_domains()
        self.collect_vulnerabilities()
        self.collect_threat_actors()
        self.collect_iocs()
        
    def collect_malicious_ips(self):
        """Collect malicious IPs from various sources"""
        # AlienVault OTX
        self._collect_alienvault_ips()
        # AbuseIPDB
        self._collect_abuseipdb()
        # Shodan
        self._collect_shodan_ips()
        # ThreatFox
        self._collect_threatfox_ips()
        
    def collect_malicious_domains(self):
        """Collect malicious domains from various sources"""
        # VirusTotal
        self._collect_virustotal_domains()
        # AlienVault OTX
        self._collect_alienvault_domains()
        # URLhaus
        self._collect_urlhaus_domains()
        
    def collect_vulnerabilities(self):
        """Collect vulnerability data"""
        # NVD (National Vulnerability Database)
        self._collect_nvd_vulnerabilities()
        # CIRCL CVE
        self._collect_circl_vulnerabilities()
        
    def collect_threat_actors(self):
        """Collect threat actor information"""
        # MITRE ATT&CK
        self._collect_mitre_threat_actors()
        
    def collect_iocs(self):
        """Collect various Indicators of Compromise"""
        # MISP
        self._collect_misp_iocs()
        # ThreatFox
        self._collect_threatfox_iocs()
        # AlienVault OTX
        self._collect_alienvault_iocs()

    # Individual API collectors
    def _collect_alienvault_ips(self):
        """Collect malicious IPs from AlienVault OTX"""
        if not self.alienvault_api_key:
            print("AlienVault API key not found, skipping...")
            return
            
        try:
            url = "https://otx.alienvault.com/api/v1/indicators/IPv4/reputation"
            headers = {"X-OTX-API-KEY": self.alienvault_api_key}
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                for ip_data in data.get("data", []):
                    ip_address = ip_data.get("indicator")
                    if ip_address:
                        self.collections["malicious_ips"].update_one(
                            {"ip": ip_address},
                            {"$set": {
                                "ip": ip_address,
                                "source": "AlienVault OTX",
                                "reputation": ip_data.get("reputation", 0),
                                "categories": ip_data.get("category", []),
                                "last_updated": datetime.datetime.utcnow()
                            }},
                            upsert=True
                        )
                print(f"Collected {len(data.get('data', []))} IPs from AlienVault")
            else:
                print(f"AlienVault API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting AlienVault IPs: {str(e)}")
            
    def _collect_abuseipdb(self):
        """Collect malicious IPs from AbuseIPDB"""
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            print("AbuseIPDB API key not found, skipping...")
            return
            
        try:
            url = "https://api.abuseipdb.com/api/v2/blacklist"
            headers = {
                "Key": api_key,
                "Accept": "application/json"
            }
            params = {"limit": 1000}  # Adjust as needed
            
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                for ip_data in data.get("data", []):
                    ip_address = ip_data.get("ipAddress")
                    if ip_address:
                        self.collections["malicious_ips"].update_one(
                            {"ip": ip_address},
                            {"$set": {
                                "ip": ip_address,
                                "source": "AbuseIPDB",
                                "confidence": ip_data.get("abuseConfidenceScore"),
                                "reports": ip_data.get("totalReports", 0),
                                "last_updated": datetime.datetime.utcnow()
                            }},
                            upsert=True
                        )
                print(f"Collected {len(data.get('data', []))} IPs from AbuseIPDB")
            else:
                print(f"AbuseIPDB API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting AbuseIPDB data: {str(e)}")
            
    def _collect_shodan_ips(self):
        """Collect malicious IPs from Shodan"""
        if not self.shodan_api_key:
            print("Shodan API key not found, skipping...")
            return
            
        try:
            # Example query for potentially malicious IPs
            query = "category:malware"
            url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_api_key}&query={query}"
            
            response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                for match in data.get("matches", []):
                    ip_address = match.get("ip_str")
                    if ip_address:
                        self.collections["malicious_ips"].update_one(
                            {"ip": ip_address},
                            {"$set": {
                                "ip": ip_address,
                                "source": "Shodan",
                                "ports": match.get("ports", []),
                                "hostnames": match.get("hostnames", []),
                                "country": match.get("location", {}).get("country_name"),
                                "last_updated": datetime.datetime.utcnow()
                            }},
                            upsert=True
                        )
                print(f"Collected {len(data.get('matches', []))} IPs from Shodan")
            else:
                print(f"Shodan API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting Shodan data: {str(e)}")
            
    def _collect_virustotal_domains(self):
        """Collect malicious domains from VirusTotal"""
        if not self.virustotal_api_key:
            print("VirusTotal API key not found, skipping...")
            return
            
        try:
            # Example: Get feed of recently detected malicious domains
            url = "https://www.virustotal.com/api/v3/domains/feed"
            headers = {"x-apikey": self.virustotal_api_key}
            
            # In a real scenario, you'd need to handle pagination
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                domains = data.get("data", [])
                for domain_data in domains:
                    domain = domain_data.get("id")
                    attributes = domain_data.get("attributes", {})
                    
                    if domain:
                        self.collections["malicious_domains"].update_one(
                            {"domain": domain},
                            {"$set": {
                                "domain": domain,
                                "source": "VirusTotal",
                                "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                                "reputation": attributes.get("reputation", 0),
                                "categories": attributes.get("categories", {}),
                                "last_updated": datetime.datetime.utcnow()
                            }},
                            upsert=True
                        )
                print(f"Collected {len(domains)} domains from VirusTotal")
            else:
                print(f"VirusTotal API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting VirusTotal data: {str(e)}")
    
    def _collect_alienvault_domains(self):
        """Collect malicious domains from AlienVault OTX"""
        if not self.alienvault_api_key:
            print("AlienVault API key not found, skipping...")
            return
            
        try:
            url = "https://otx.alienvault.com/api/v1/indicators/domain/malicious"
            headers = {"X-OTX-API-KEY": self.alienvault_api_key}
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                for domain_data in data.get("data", []):
                    domain = domain_data.get("indicator")
                    if domain:
                        self.collections["malicious_domains"].update_one(
                            {"domain": domain},
                            {"$set": {
                                "domain": domain,
                                "source": "AlienVault OTX",
                                "pulse_info": domain_data.get("pulse_info", {}),
                                "last_updated": datetime.datetime.utcnow()
                            }},
                            upsert=True
                        )
                print(f"Collected {len(data.get('data', []))} domains from AlienVault")
            else:
                print(f"AlienVault API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting AlienVault domains: {str(e)}")
            
    def _collect_urlhaus_domains(self):
        """Collect malicious domains from URLhaus"""
        try:
            url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            data = {"limit": 100}  # Adjust as needed
            
            response = requests.post(url, data=data)
            
            if response.status_code == 200:
                data = response.json()
                for url_data in data.get("urls", []):
                    domain = url_data.get("host")
                    if domain:
                        self.collections["malicious_domains"].update_one(
                            {"domain": domain},
                            {"$set": {
                                "domain": domain,
                                "source": "URLhaus",
                                "url": url_data.get("url"),
                                "status": url_data.get("url_status"),
                                "threat": url_data.get("threat"),
                                "tags": url_data.get("tags", []),
                                "last_updated": datetime.datetime.utcnow()
                            }},
                            upsert=True
                        )
                print(f"Collected {len(data.get('urls', []))} domains from URLhaus")
            else:
                print(f"URLhaus API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting URLhaus data: {str(e)}")
            
    def _collect_nvd_vulnerabilities(self):
        """Collect vulnerability data from NVD"""
        api_key = self.nvd_api_key
        headers = {}
        if api_key:
            headers["apiKey"] = api_key
            
        try:
            # Get recent vulnerabilities
            current_time = int(time.time())
            # 30 days ago
            thirty_days_ago = current_time - (30 * 24 * 60 * 60)
            
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "pubStartDate": f"{datetime.datetime.fromtimestamp(thirty_days_ago).isoformat()}",
                "pubEndDate": f"{datetime.datetime.fromtimestamp(current_time).isoformat()}",
                "resultsPerPage": 50
            }
            
            response = requests.get(url, params=params, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id")
                    
                    if cve_id:
                        metrics = cve.get("metrics", {})
                        cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if "cvssMetricV31" in metrics else {}
                        if not cvss_data and "cvssMetricV30" in metrics:
                            cvss_data = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                        
                        self.collections["vulnerabilities"].update_one(
                            {"cve_id": cve_id},
                            {"$set": {
                                "cve_id": cve_id,
                                "source": "NVD",
                                "description": cve.get("descriptions", [{}])[0].get("value", "") if cve.get("descriptions") else "",
                                "cvss_score": cvss_data.get("baseScore", 0),
                                "cvss_vector": cvss_data.get("vectorString", ""),
                                "severity": cvss_data.get("baseSeverity", ""),
                                "published": cve.get("published"),
                                "last_modified": cve.get("lastModified"),
                                "last_updated": datetime.datetime.utcnow()
                            }},
                            upsert=True
                        )
                print(f"Collected {len(data.get('vulnerabilities', []))} vulnerabilities from NVD")
            else:
                print(f"NVD API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting NVD data: {str(e)}")
            
    def _collect_circl_vulnerabilities(self):
        """Collect vulnerability data from CIRCL CVE"""
        if not self.circl_api_key:
            print("CIRCL API key not found, skipping...")
            return
            
        try:
            # Get recent CVEs
            url = "https://cve.circl.lu/api/last/100"  # Last 100 CVEs
            
            response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                for vuln in data:
                    cve_id = vuln.get("id")
                    
                    if cve_id:
                        self.collections["vulnerabilities"].update_one(
                            {"cve_id": cve_id},
                            {"$set": {
                                "cve_id": cve_id,
                                "source": "CIRCL",
                                "summary": vuln.get("summary", ""),
                                "cvss_score": vuln.get("cvss", 0),
                                "references": vuln.get("references", []),
                                "published": vuln.get("Published", ""),
                                "last_updated": datetime.datetime.utcnow()
                            }},
                            upsert=True
                        )
                print(f"Collected {len(data)} vulnerabilities from CIRCL")
            else:
                print(f"CIRCL API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting CIRCL data: {str(e)}")
            
    def _collect_mitre_threat_actors(self):
        """Collect threat actor information from MITRE ATT&CK"""
        try:
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            
            response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                threat_actors = [obj for obj in data.get("objects", []) if obj.get("type") == "intrusion-set"]
                
                for actor in threat_actors:
                    actor_id = actor.get("id")
                    
                    if actor_id:
                        self.collections["threat_actors"].update_one(
                            {"actor_id": actor_id},
                            {"$set": {
                                "actor_id": actor_id,
                                "source": "MITRE ATT&CK",
                                "name": actor.get("name", ""),
                                "description": actor.get("description", ""),
                                "aliases": actor.get("aliases", []),
                                "techniques": [ref for ref in actor.get("external_references", []) if ref.get("source_name") == "mitre-attack"],
                                "last_updated": datetime.datetime.utcnow()
                            }},
                            upsert=True
                        )
                print(f"Collected {len(threat_actors)} threat actors from MITRE ATT&CK")
            else:
                print(f"MITRE ATT&CK API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting MITRE ATT&CK data: {str(e)}")
            
    def _collect_misp_iocs(self):
        """Collect IOCs from MISP"""
        if not self.misp_api_key:
            print("MISP API key not found, skipping...")
            return
            
        try:
            # You would need to specify your MISP instance URL
            misp_url = os.getenv("MISP_URL")
            if not misp_url:
                print("MISP URL not found, skipping...")
                return
                
            url = f"{misp_url}/events/restSearch"
            headers = {
                "Authorization": self.misp_api_key,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            
            # Get events from last 30 days
            data = {
                "returnFormat": "json",
                "limit": 100,
                "page": 1,
                "timestamp": "30d"  # Last 30 days
            }
            
            response = requests.post(url, headers=headers, json=data)
            
            if response.status_code == 200:
                events = response.json()
                ioc_count = 0
                
                for event in events.get("response", []):
                    for attribute in event.get("Event", {}).get("Attribute", []):
                        indicator = attribute.get("value")
                        indicator_type = attribute.get("type")
                        
                        if indicator and indicator_type:
                            self.collections["iocs"].update_one(
                                {"indicator": indicator, "type": indicator_type},
                                {"$set": {
                                    "indicator": indicator,
                                    "type": indicator_type,
                                    "source": "MISP",
                                    "event_id": event.get("Event", {}).get("id"),
                                    "category": attribute.get("category"),
                                    "to_ids": attribute.get("to_ids"),
                                    "timestamp": attribute.get("timestamp"),
                                    "last_updated": datetime.datetime.utcnow()
                                }},
                                upsert=True
                            )
                            ioc_count += 1
                            
                print(f"Collected {ioc_count} IOCs from MISP")
            else:
                print(f"MISP API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting MISP data: {str(e)}")
            
    def _collect_threatfox_iocs(self):
        """Collect IOCs from ThreatFox"""
        if not self.threatfox_api_key:
            print("ThreatFox API key not found, skipping...")
            return
            
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            headers = {"API-KEY": self.threatfox_api_key}
            
            # Get recent IOCs
            data = {"query": "get_iocs", "days": 30}
            
            response = requests.post(url, headers=headers, json=data)
            
            if response.status_code == 200:
                data = response.json()
                iocs = data.get("data", [])
                for ioc_data in iocs:
                    indicator = ioc_data.get("ioc")
                    indicator_type = ioc_data.get("ioc_type")
                    
                    if indicator and indicator_type:
                        self.collections["iocs"].update_one(
                            {"indicator": indicator, "type": indicator_type},
                            {"$set": {
                                "indicator": indicator,
                                "type": indicator_type,
                                "source": "ThreatFox",
                                "threat_type": ioc_data.get("threat_type"),
                                "malware": ioc_data.get("malware"),
                                "confidence": ioc_data.get("confidence_level"),
                                "tags": ioc_data.get("tags", []),
                                "last_updated": datetime.datetime.utcnow()
                            }},
                            upsert=True
                        )
                            
                        # If it's an IP, also add to malicious_ips collection
                        if indicator_type == "ip:port" or indicator_type == "ip":
                            ip = indicator.split(":")[0] if ":" in indicator else indicator
                            self.collections["malicious_ips"].update_one(
                                {"ip": ip},
                                {"$set": {
                                    "ip": ip,
                                    "source": "ThreatFox",
                                    "threat_type": ioc_data.get("threat_type"),
                                    "malware": ioc_data.get("malware"),
                                    "last_updated": datetime.datetime.utcnow()
                                }},
                                upsert=True
                            )
                            
                print(f"Collected {len(iocs)} IOCs from ThreatFox")
            else:
                print(f"ThreatFox API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting ThreatFox data: {str(e)}")
            
    def _collect_threatfox_ips(self):
        """This is a subset of collect_threatfox_iocs specifically for IPs"""
        # This function can be skipped if _collect_threatfox_iocs is already called
        pass
            
    def _collect_alienvault_iocs(self):
        """Collect IOCs from AlienVault OTX"""
        if not self.alienvault_api_key:
            print("AlienVault API key not found, skipping...")
            return
            
        try:
            # Get recent pulses
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            headers = {"X-OTX-API-KEY": self.alienvault_api_key}
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                ioc_count = 0
                
                for pulse in data.get("results", []):
                    for indicator in pulse.get("indicators", []):
                        indicator_value = indicator.get("indicator")
                        indicator_type = indicator.get("type")
                        
                        if indicator_value and indicator_type:
                            self.collections["iocs"].update_one(
                                {"indicator": indicator_value, "type": indicator_type},
                                {"$set": {
                                    "indicator": indicator_value,
                                    "type": indicator_type,
                                    "source": "AlienVault OTX",
                                    "pulse_id": pulse.get("id"),
                                    "pulse_name": pulse.get("name"),
                                    "description": indicator.get("description", ""),
                                    "created": indicator.get("created"),
                                    "last_updated": datetime.datetime.utcnow()
                                }},
                                upsert=True
                            )
                            ioc_count += 1
                            
                print(f"Collected {ioc_count} IOCs from AlienVault OTX")
            else:
                print(f"AlienVault OTX API error: {response.status_code}")
        except Exception as e:
            print(f"Error collecting AlienVault OTX IOCs: {str(e)}")

# Data Export Utilities
class ThreatIntelligenceExporter:
    def __init__(self, db_collections):
        self.collections = db_collections
        
    def export_to_json(self, output_dir="exports"):
        """Export all collections to JSON files"""
        os.makedirs(output_dir, exist_ok=True)
        
        for collection_name, collection in self.collections.items():
            output_file = os.path.join(output_dir, f"{collection_name}.json")
            
            # Get all documents from collection
            documents = list(collection.find({}, {"_id": 0}))
            
            # Convert datetime objects to strings
            for doc in documents:
                for key, value in doc.items():
                    if isinstance(value, datetime.datetime):
                        doc[key] = value.isoformat()
            
            # Write to file
            with open(output_file, "w") as f:
                json.dump(documents, f, indent=2)
                
            print(f"Exported {len(documents)} records to {output_file}")
    
    def export_by_type(self, type_name, output_dir="exports"):
        """Export specific collection by type"""
        if type_name not in self.collections:
            print(f"Collection {type_name} not found")
            return
            
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"{type_name}.json")
        
        # Get all documents from collection
        documents = list(self.collections[type_name].find({}, {"_id": 0}))
        
        # Convert datetime objects to strings
        for doc in documents:
            for key, value in doc.items():
                if isinstance(value, datetime.datetime):
                    doc[key] = value.isoformat()
        
        # Write to file
        with open(output_file, "w") as f:
            json.dump(documents, f, indent=2)
            
        print(f"Exported {len(documents)} records to {output_file}")
        
    def export_recent(self, days=30, output_dir="exports"):
        """Export recent data across all collections"""
        os.makedirs(output_dir, exist_ok=True)
        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=days)
        
        for collection_name, collection in self.collections.items():
            output_file = os.path.join(output_dir, f"{collection_name}_recent.json")
            
            # Get recent documents
            documents = list(collection.find(
                {"last_updated": {"$gte": cutoff_date}},
                {"_id": 0}
            ))
            
            # Convert datetime objects to strings
            for doc in documents:
                for key, value in doc.items():
                    if isinstance(value, datetime.datetime):
                        doc[key] = value.isoformat()
            
            # Write to file
            with open(output_file, "w") as f:
                json.dump(documents, f, indent=2)
                
            print(f"Exported {len(documents)} recent records to {output_file}")

# Command Line Interface
# Command Line Interface
def main():
    """Main function to run the threat intelligence collector"""
    print("Initializing Threat Intelligence Collection System...")
    
    # Connect to MongoDB
    db = connect_to_mongodb()
    print("Connected to MongoDB")
    
    # Initialize collections
    collections = initialize_collections(db)
    print("Initialized database collections")
    
    # Create collector
    collector = ThreatIntelligenceCollector(collections)
    
    # Collect data
    print("Starting data collection...")
    collector.collect_all()
    print("Data collection completed")
    
    # Create exporter
    exporter = ThreatIntelligenceExporter(collections)
    
    # Export data
    print("Exporting collected data...")
    exporter.export_to_json()
    print("Data export completed")
    
    print("Threat intelligence collection and export completed successfully")

# Data retrieval utilities for reuse in other projects
class ThreatIntelligenceRetriever:
    """Utility class to retrieve threat intelligence data from MongoDB"""
    
    def __init__(self, db_name="threat_intelligence", connection_string=None):
        """Initialize the retriever with MongoDB connection"""
        if connection_string:
            self.client = pymongo.MongoClient(connection_string)
        else:
            self.client = pymongo.MongoClient("mongodb://localhost:27017")
        
        self.db = self.client[db_name]
    
    def get_malicious_ips(self, limit=100, source=None):
        """Retrieve malicious IPs from the database"""
        query = {"source": source} if source else {}
        return list(self.db.malicious_ips.find(query, {"_id": 0}).limit(limit))
    
    def get_malicious_domains(self, limit=100, source=None):
        """Retrieve malicious domains from the database"""
        query = {"source": source} if source else {}
        return list(self.db.malicious_domains.find(query, {"_id": 0}).limit(limit))
    
    def get_vulnerabilities(self, limit=100, min_cvss=None):
        """Retrieve vulnerabilities from the database"""
        query = {}
        if min_cvss:
            query["cvss_score"] = {"$gte": min_cvss}
        return list(self.db.vulnerabilities.find(query, {"_id": 0}).limit(limit))
    
    def get_threat_actors(self, limit=100):
        """Retrieve threat actor information from the database"""
        return list(self.db.threat_actors.find({}, {"_id": 0}).limit(limit))
    
    def get_iocs(self, limit=100, ioc_type=None):
        """Retrieve indicators of compromise from the database"""
        query = {"type": ioc_type} if ioc_type else {}
        return list(self.db.iocs.find(query, {"_id": 0}).limit(limit))
    
    def search_iocs(self, search_term, limit=100):
        """Search IOCs by keyword"""
        query = {"indicator": {"$regex": search_term, "$options": "i"}}
        return list(self.db.iocs.find(query, {"_id": 0}).limit(limit))
    
    def get_recent_data(self, collection_name, days=30, limit=100):
        """Retrieve recent data from specified collection"""
        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=days)
        query = {"last_updated": {"$gte": cutoff_date}}
        
        if collection_name not in ["malicious_ips", "malicious_domains", "vulnerabilities", "threat_actors", "iocs"]:
            return {"error": "Invalid collection name"}
            
        return list(self.db[collection_name].find(query, {"_id": 0}).limit(limit))
    
    def close(self):
        """Close the MongoDB connection"""
        self.client.close()

# Data import utility for other projects
class ThreatIntelligenceImporter:
    """Utility class to import threat intelligence data from JSON files"""
    
    def __init__(self, db_name="threat_intelligence", connection_string=None):
        """Initialize the importer with MongoDB connection"""
        if connection_string:
            self.client = pymongo.MongoClient(connection_string)
        else:
            self.client = pymongo.MongoClient("mongodb://localhost:27017")
        
        self.db = self.client[db_name]
        
        # Initialize collections
        self.collections = initialize_collections(self.db)
    
    def import_from_json(self, input_dir="exports"):
        """Import data from JSON files into MongoDB"""
        files = {
            "malicious_ips.json": self.db.malicious_ips,
            "malicious_domains.json": self.db.malicious_domains,
            "vulnerabilities.json": self.db.vulnerabilities,
            "threat_actors.json": self.db.threat_actors,
            "iocs.json": self.db.iocs
        }
        
        for filename, collection in files.items():
            file_path = os.path.join(input_dir, filename)
            if not os.path.exists(file_path):
                print(f"File {file_path} not found, skipping...")
                continue
                
            with open(file_path, "r") as f:
                try:
                    documents = json.load(f)
                    
                    # Convert ISO datetime strings back to datetime objects
                    for doc in documents:
                        for key, value in doc.items():
                            if isinstance(value, str) and "T" in value and "Z" in value:
                                try:
                                    doc[key] = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
                                except ValueError:
                                    pass  # Leave as string if not a valid datetime
                    
                    if documents:
                        # For each document, use upsert to avoid duplicates
                        if filename == "malicious_ips.json":
                            for doc in documents:
                                collection.update_one({"ip": doc["ip"]}, {"$set": doc}, upsert=True)
                        elif filename == "malicious_domains.json":
                            for doc in documents:
                                collection.update_one({"domain": doc["domain"]}, {"$set": doc}, upsert=True)
                        elif filename == "vulnerabilities.json":
                            for doc in documents:
                                collection.update_one({"cve_id": doc["cve_id"]}, {"$set": doc}, upsert=True)
                        elif filename == "threat_actors.json":
                            for doc in documents:
                                collection.update_one({"actor_id": doc["actor_id"]}, {"$set": doc}, upsert=True)
                        elif filename == "iocs.json":
                            for doc in documents:
                                collection.update_one(
                                    {"indicator": doc["indicator"], "type": doc["type"]},
                                    {"$set": doc},
                                    upsert=True
                                )
                                
                        print(f"Imported {len(documents)} records from {filename}")
                except json.JSONDecodeError:
                    print(f"Error parsing JSON from {file_path}")
    
    def close(self):
        """Close the MongoDB connection"""
        self.client.close()

# Example usage of the system in other projects
def example_usage():
    """Example of how to use the threat intelligence data in other projects"""
    # Create a retriever to get data from MongoDB
    retriever = ThreatIntelligenceRetriever()
    
    # Get recent malicious IPs
    malicious_ips = retriever.get_malicious_ips(limit=10)
    print(f"Retrieved {len(malicious_ips)} malicious IPs")
    
    # Get high-severity vulnerabilities
    high_severity_vulns = retriever.get_vulnerabilities(min_cvss=7.0, limit=5)
    print(f"Retrieved {len(high_severity_vulns)} high-severity vulnerabilities")
    
    # Search for IOCs related to a specific term
    ransomware_iocs = retriever.search_iocs("ransomware", limit=10)
    print(f"Found {len(ransomware_iocs)} IOCs related to ransomware")
    
    # Close the connection when done
    retriever.close()

# Scheduling utility for regular updates
def schedule_collection():
    """Schedule regular collection of threat intelligence data"""
    db = connect_to_mongodb()
    collections = initialize_collections(db)
    collector = ThreatIntelligenceCollector(collections)
    exporter = ThreatIntelligenceExporter(collections)
    
    # Collect and export data
    collector.collect_all()
    exporter.export_to_json()
    
    print(f"Scheduled collection completed at {datetime.datetime.now()}")

# API for accessing the threat intelligence data
def create_api_server():
    """Create a Flask API server for accessing the threat intelligence data"""
    from flask import Flask, jsonify, request
    
    app = Flask(__name__)
    retriever = ThreatIntelligenceRetriever()
    
    @app.route('/api/malicious-ips', methods=['GET'])
    def get_malicious_ips():
        limit = int(request.args.get('limit', 100))
        source = request.args.get('source')
        return jsonify(retriever.get_malicious_ips(limit=limit, source=source))
    
    @app.route('/api/malicious-domains', methods=['GET'])
    def get_malicious_domains():
        limit = int(request.args.get('limit', 100))
        source = request.args.get('source')
        return jsonify(retriever.get_malicious_domains(limit=limit, source=source))
    
    @app.route('/api/vulnerabilities', methods=['GET'])
    def get_vulnerabilities():
        limit = int(request.args.get('limit', 100))
        min_cvss = request.args.get('min_cvss')
        if min_cvss:
            min_cvss = float(min_cvss)
        return jsonify(retriever.get_vulnerabilities(limit=limit, min_cvss=min_cvss))
    
    @app.route('/api/threat-actors', methods=['GET'])
    def get_threat_actors():
        limit = int(request.args.get('limit', 100))
        return jsonify(retriever.get_threat_actors(limit=limit))
    
    @app.route('/api/iocs', methods=['GET'])
    def get_iocs():
        limit = int(request.args.get('limit', 100))
        ioc_type = request.args.get('type')
        search = request.args.get('search')
        
        if search:
            return jsonify(retriever.search_iocs(search, limit=limit))
        else:
            return jsonify(retriever.get_iocs(limit=limit, ioc_type=ioc_type))
    
    @app.route('/api/recent/<collection_name>', methods=['GET'])
    def get_recent_data(collection_name):
        limit = int(request.args.get('limit', 100))
        days = int(request.args.get('days', 30))
        return jsonify(retriever.get_recent_data(collection_name, days=days, limit=limit))
    
    # Start the server
    app.run(debug=True, port=5000)

if __name__ == "__main__":
    main()
