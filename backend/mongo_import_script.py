import os
import json
import datetime
import argparse
import pymongo
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def import_threat_data(import_dir, db_connection_string=None):
    """Import threat intelligence data into MongoDB"""
    # Connect to MongoDB
    if db_connection_string:
        client = pymongo.MongoClient(db_connection_string)
    else:
        mongo_uri = os.getenv("MONGODB_URI")
        client = pymongo.MongoClient(mongo_uri)
    
    db = client.get_database("your_project_db")  # Change to your project's database name
    
    # Initialize collections if they don't exist
    collections = {
        "malicious_ips": db.malicious_ips,
        "malicious_domains": db.malicious_domains,
        "vulnerabilities": db.vulnerabilities,
        "threat_actors": db.threat_actors,
        "iocs": db.iocs
    }
    
    # Create indexes
    collections["malicious_ips"].create_index("ip", unique=True)
    collections["malicious_domains"].create_index("domain", unique=True)
    collections["vulnerabilities"].create_index("cve_id", unique=True)
    collections["threat_actors"].create_index("actor_id", unique=True)
    collections["iocs"].create_index([("indicator", 1), ("type", 1)], unique=True)
    
    # Import each JSON file
    for filename, collection in collections.items():
        file_path = os.path.join(import_dir, f"{filename}.json")
        if not os.path.exists(file_path):
            print(f"File {file_path} not found, skipping...")
            continue
            
        with open(file_path, "r") as f:
            try:
                documents = json.load(f)
                
                # Convert ISO datetime strings back to datetime objects
                for doc in documents:
                    for key, value in doc.items():
                        if isinstance(value, str) and "T" in value:
                            try:
                                doc[key] = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
                            except ValueError:
                                pass  # Leave as string if not a valid datetime
                
                if documents:
                    # For each document, use upsert to avoid duplicates
                    if filename == "malicious_ips":
                        for doc in documents:
                            collection.update_one({"ip": doc["ip"]}, {"$set": doc}, upsert=True)
                    elif filename == "malicious_domains":
                        for doc in documents:
                            collection.update_one({"domain": doc["domain"]}, {"$set": doc}, upsert=True)
                    elif filename == "vulnerabilities":
                        for doc in documents:
                            collection.update_one({"cve_id": doc["cve_id"]}, {"$set": doc}, upsert=True)
                    elif filename == "threat_actors":
                        for doc in documents:
                            collection.update_one({"actor_id": doc["actor_id"]}, {"$set": doc}, upsert=True)
                    elif filename == "iocs":
                        for doc in documents:
                            collection.update_one(
                                {"indicator": doc["indicator"], "type": doc["type"]},
                                {"$set": doc},
                                upsert=True
                            )
                            
                    print(f"Imported {len(documents)} records from {filename}.json")
            except json.JSONDecodeError:
                print(f"Error parsing JSON from {file_path}")
    
    print("Import completed successfully")
    client.close()

def query_examples(db_connection_string=None):
    """Examples of how to query the imported threat intelligence data"""
    # Connect to MongoDB
    if db_connection_string:
        client = pymongo.MongoClient(db_connection_string)
    else:
        mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        client = pymongo.MongoClient(mongo_uri)
    
    db = client.get_database("your_project_db")  # Change to your project's database name
    
    # Example 1: Get high severity vulnerabilities
    high_severity_vulns = list(db.vulnerabilities.find(
        {"cvss_score": {"$gte": 8.0}},
        {"_id": 0, "cve_id": 1, "description": 1, "cvss_score": 1}
    ).limit(5))
    
    print("\nHigh Severity Vulnerabilities:")
    for vuln in high_severity_vulns:
        print(f"- {vuln['cve_id']}: {vuln['cvss_score']} - {vuln['description'][:100]}...")
    
    # Example 2: Find malicious domains related to a keyword
    keyword = "phishing"
    malicious_domains = list(db.malicious_domains.find(
        {"$or": [
            {"domain": {"$regex": keyword, "$options": "i"}},
            {"threat": {"$regex": keyword, "$options": "i"}},
            {"tags": keyword}
        ]},
        {"_id": 0, "domain": 1, "source": 1}
    ).limit(5))
    
    print(f"\nMalicious Domains related to '{keyword}':")
    for domain in malicious_domains:
        print(f"- {domain['domain']} (Source: {domain['source']})")
    
    # Example 3: Get recent IOCs
    recent_date = datetime.datetime.utcnow() - datetime.timedelta(days=30)
    recent_iocs = list(db.iocs.find(
        {"last_updated": {"$gte": recent_date}},
        {"_id": 0, "indicator": 1, "type": 1, "source": 1}
    ).limit(5))
    
    print("\nRecent IOCs:")
    for ioc in recent_iocs:
        print(f"- {ioc['indicator']} ({ioc['type']}) from {ioc['source']}")
    
    client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import threat intelligence data into MongoDB")
    parser.add_argument("--import-dir", default="exports", help="Directory containing JSON export files")
    parser.add_argument("--connection", help="MongoDB connection string")
    parser.add_argument("--examples", action="store_true", help="Show query examples after import")
    
    args = parser.parse_args()
    
    import_threat_data(args.import_dir, args.connection)
    
    if args.examples:
        query_examples(args.connection)
