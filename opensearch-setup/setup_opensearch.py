#!/usr/bin/env python3
"""
OpenSearch Index Setup Script

Creates the secure-documents index with:
- Proper field mappings for security attributes
- Sample documents with varying classification levels
- Cell-level security metadata
- Compartmentalized content

Run: python setup_opensearch.py
"""
import os
import sys
import time
import json
from datetime import datetime, timedelta
import random

try:
    from opensearchpy import OpenSearch
except ImportError:
    print("Installing opensearch-py...")
    os.system(f"{sys.executable} -m pip install opensearch-py")
    from opensearchpy import OpenSearch


# ─── Configuration ──────────────────────────────────────────────────────────
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
INDEX_NAME = os.getenv("OPENSEARCH_INDEX", "secure-documents")


# ─── Index Mapping ──────────────────────────────────────────────────────────
INDEX_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "analysis": {
            "analyzer": {
                "content_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase", "stop", "snowball"]
                }
            }
        }
    },
    "mappings": {
        "properties": {
            # Core document fields
            "title": {
                "type": "text",
                "analyzer": "content_analyzer",
                "fields": {
                    "keyword": {"type": "keyword"}
                }
            },
            "summary": {
                "type": "text",
                "analyzer": "content_analyzer"
            },
            "content": {
                "type": "text",
                "analyzer": "content_analyzer"
            },
            "category": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword"}
                }
            },
            "author": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword"}
                }
            },
            "created_at": {
                "type": "date"
            },
            "updated_at": {
                "type": "date"
            },
            
            # Security fields (document-level)
            "classification": {
                "type": "keyword"
            },
            "compartments": {
                "type": "keyword"
            },
            "owner_org": {
                "type": "keyword"
            },
            
            # Cell-level security metadata
            # Stores per-field security requirements
            "field_security": {
                "type": "object",
                "enabled": False  # Not indexed, just stored
            },
            
            # Additional metadata
            "tags": {
                "type": "keyword"
            },
            "related_documents": {
                "type": "keyword"
            },
            "version": {
                "type": "integer"
            }
        }
    }
}


# ─── Sample Documents ───────────────────────────────────────────────────────
SAMPLE_DOCUMENTS = [
    # UNCLASSIFIED - No compartments (accessible to everyone)
    {
        "title": "Annual Public Report 2024",
        "summary": "Publicly available annual organizational report covering achievements and future plans.",
        "content": """This annual report details the organization's public activities, 
        community outreach programs, and transparency initiatives. All information 
        contained herein is approved for public release.""",
        "category": "Reports",
        "author": "Public Affairs Office",
        "classification": "UNCLASSIFIED",
        "compartments": [],
        "owner_org": "agency-alpha",
        "tags": ["public", "annual", "report"],
        "version": 1,
    },
    {
        "title": "Employee Onboarding Guide",
        "summary": "Standard onboarding procedures and welcome information for new employees.",
        "content": """Welcome to the organization! This guide covers basic procedures,
        facilities information, and general policies applicable to all staff.""",
        "category": "HR",
        "author": "Human Resources",
        "classification": "UNCLASSIFIED",
        "compartments": [],
        "owner_org": "agency-alpha",
        "tags": ["hr", "onboarding", "procedures"],
        "version": 2,
    },
    
    # CONFIDENTIAL - No compartments
    {
        "title": "Internal Budget Overview Q4",
        "summary": "Quarterly budget allocation and spending analysis for internal review.",
        "content": """This document contains internal budget figures and allocation 
        strategies. Not for public distribution but available to all cleared personnel.""",
        "category": "Finance",
        "author": "Finance Department",
        "classification": "CONFIDENTIAL",
        "compartments": [],
        "owner_org": "agency-alpha",
        "tags": ["budget", "finance", "quarterly"],
        "version": 1,
    },
    {
        "title": "Infrastructure Security Assessment",
        "summary": "Assessment of physical and digital infrastructure security measures.",
        "content": """Comprehensive review of security protocols, identified vulnerabilities,
        and recommended improvements. Contains sensitive infrastructure details.""",
        "category": "Security",
        "author": "Security Division",
        "classification": "CONFIDENTIAL",
        "compartments": [],
        "owner_org": "agency-alpha",
        "tags": ["security", "infrastructure", "assessment"],
        "version": 3,
    },
    
    # SECRET - No compartments
    {
        "title": "Strategic Initiative Planning Document",
        "summary": "Multi-year strategic planning document with organizational objectives.",
        "content": """This strategic plan outlines sensitive organizational objectives,
        resource allocation strategies, and coordination with partner agencies.""",
        "category": "Strategy",
        "author": "Executive Office",
        "classification": "SECRET",
        "compartments": [],
        "owner_org": "agency-alpha",
        "tags": ["strategy", "planning", "executive"],
        "version": 2,
    },
    {
        "title": "Partner Agency Coordination Protocol",
        "summary": "Protocols for inter-agency coordination and information sharing.",
        "content": """Detailed procedures for coordinating operations and sharing
        information with partner agencies. Includes communication channels and
        escalation procedures.""",
        "category": "Operations",
        "author": "Operations Center",
        "classification": "SECRET",
        "compartments": [],
        "owner_org": "agency-alpha",
        "tags": ["coordination", "protocols", "inter-agency"],
        "version": 1,
    },
    
    # SECRET - PROJECT_ALPHA compartment
    {
        "title": "Project Alpha Technical Specifications",
        "summary": "Technical specifications and requirements for Project Alpha systems.",
        "content": """Detailed technical specifications for Project Alpha including
        system architecture, integration requirements, and performance benchmarks.
        ALPHA-SPECIFIC SENSITIVE DATA: System operates on frequencies 2.4-2.5 GHz.""",
        "category": "Technical",
        "author": "Alpha Team Lead",
        "classification": "SECRET",
        "compartments": ["PROJECT_ALPHA"],
        "owner_org": "agency-alpha",
        "tags": ["technical", "specifications", "alpha"],
        "version": 4,
        "field_security": {
            "content": {
                "classification": "SECRET",
                "compartments": ["PROJECT_ALPHA"]
            }
        }
    },
    {
        "title": "Project Alpha Progress Report",
        "summary": "Monthly progress update on Project Alpha milestones and deliverables.",
        "content": """Current status: Phase 2 complete. Key achievements include
        successful integration testing and preliminary field trials. Next milestone
        targets Q2 deployment. ALPHA METRICS: 94.7% success rate in trials.""",
        "category": "Reports",
        "author": "Alpha Project Manager",
        "classification": "SECRET",
        "compartments": ["PROJECT_ALPHA"],
        "owner_org": "agency-alpha",
        "tags": ["progress", "report", "alpha"],
        "version": 6,
    },
    
    # SECRET - PROJECT_OMEGA compartment
    {
        "title": "Project Omega Research Findings",
        "summary": "Research outcomes and analysis from Project Omega investigations.",
        "content": """Research findings from Omega investigations reveal significant
        patterns in target behavior. Methodology details and raw data analysis included.
        OMEGA-SPECIFIC: Pattern recognition accuracy improved to 89.3%.""",
        "category": "Research",
        "author": "Omega Research Lead",
        "classification": "SECRET",
        "compartments": ["PROJECT_OMEGA"],
        "owner_org": "agency-alpha",
        "tags": ["research", "findings", "omega"],
        "version": 3,
    },
    {
        "title": "Project Omega Asset Inventory",
        "summary": "Inventory and status of assets allocated to Project Omega.",
        "content": """Complete inventory of Omega-assigned assets including equipment,
        personnel allocations, and facility assignments. Asset utilization at 78%.""",
        "category": "Operations",
        "author": "Omega Operations",
        "classification": "SECRET",
        "compartments": ["PROJECT_OMEGA"],
        "owner_org": "agency-alpha",
        "tags": ["inventory", "assets", "omega"],
        "version": 2,
    },
    
    # TOP_SECRET - No compartments
    {
        "title": "Executive Threat Assessment",
        "summary": "High-level threat assessment for executive leadership review.",
        "content": """Comprehensive threat assessment covering national and international
        threat vectors. Analysis of adversary capabilities and intentions.
        For executive leadership only.""",
        "category": "Intelligence",
        "author": "Intelligence Division",
        "classification": "TOP_SECRET",
        "compartments": [],
        "owner_org": "agency-alpha",
        "tags": ["threat", "assessment", "executive"],
        "version": 1,
    },
    
    # TOP_SECRET - OPERATION_DELTA compartment
    {
        "title": "Operation Delta Mission Brief",
        "summary": "Mission briefing document for Operation Delta participants.",
        "content": """OPERATION DELTA MISSION BRIEF - EYES ONLY
        Objective: [REDACTED IN SUMMARY]
        Timeline: Active
        Assets: Classified
        This document contains mission-critical information for Delta operatives.""",
        "category": "Operations",
        "author": "Delta Commander",
        "classification": "TOP_SECRET",
        "compartments": ["OPERATION_DELTA"],
        "owner_org": "agency-alpha",
        "tags": ["mission", "brief", "delta"],
        "version": 1,
        "field_security": {
            "content": {
                "classification": "TOP_SECRET",
                "compartments": ["OPERATION_DELTA"]
            },
            "author": {
                "classification": "SECRET",
                "compartments": ["OPERATION_DELTA"]
            }
        }
    },
    {
        "title": "Operation Delta Personnel Roster",
        "summary": "Authorized personnel list for Operation Delta access.",
        "content": """Personnel authorized for Delta operations. Includes clearance
        verification status and access levels. DO NOT DISTRIBUTE.""",
        "category": "Administration",
        "author": "Delta Security Officer",
        "classification": "TOP_SECRET",
        "compartments": ["OPERATION_DELTA"],
        "owner_org": "agency-alpha",
        "tags": ["personnel", "roster", "delta"],
        "version": 5,
    },
    
    # TOP_SECRET - Multiple compartments (PROJECT_ALPHA + OPERATION_DELTA)
    {
        "title": "Alpha-Delta Integration Plan",
        "summary": "Integration plan for combining Project Alpha capabilities with Operation Delta.",
        "content": """HIGHLY RESTRICTED: Plan for integrating Alpha technology into
        Delta operations. Requires both compartment accesses. Technical integration
        points, timeline, and risk assessment included.""",
        "category": "Strategy",
        "author": "Joint Program Office",
        "classification": "TOP_SECRET",
        "compartments": ["PROJECT_ALPHA", "OPERATION_DELTA"],
        "owner_org": "agency-alpha",
        "tags": ["integration", "alpha", "delta", "joint"],
        "version": 2,
        "field_security": {
            "content": {
                "classification": "TOP_SECRET",
                "compartments": ["PROJECT_ALPHA", "OPERATION_DELTA"]
            }
        }
    },
    
    # Documents from agency-bravo (federated partner)
    {
        "title": "Bravo Agency Liaison Protocol",
        "summary": "Protocol document for liaison activities with partner organization Bravo.",
        "content": """Coordination protocols established between Alpha and Bravo agencies.
        Communication procedures, point-of-contact information, and joint operation guidelines.""",
        "category": "Coordination",
        "author": "Bravo Liaison Office",
        "classification": "CONFIDENTIAL",
        "compartments": [],
        "owner_org": "agency-bravo",
        "tags": ["liaison", "protocol", "bravo", "coordination"],
        "version": 1,
    },
    {
        "title": "Bravo Shared Intelligence Report",
        "summary": "Intelligence shared by Agency Bravo under information sharing agreement.",
        "content": """Intelligence product shared under bilateral agreement. Contains
        Bravo's analysis of regional activities. For authorized Alpha personnel only.""",
        "category": "Intelligence",
        "author": "Bravo Intelligence",
        "classification": "SECRET",
        "compartments": ["PROJECT_OMEGA"],
        "owner_org": "agency-bravo",
        "tags": ["intelligence", "shared", "bravo"],
        "version": 1,
    },
]


def wait_for_opensearch(client: OpenSearch, max_retries: int = 30) -> bool:
    """Wait for OpenSearch to be available."""
    for i in range(max_retries):
        try:
            if client.ping():
                print("✓ OpenSearch is available")
                return True
        except Exception as e:
            print(f"  Waiting for OpenSearch... ({i+1}/{max_retries})")
        time.sleep(2)
    return False


def create_index(client: OpenSearch) -> bool:
    """Create the secure-documents index with mappings."""
    try:
        if client.indices.exists(index=INDEX_NAME):
            print(f"  Index '{INDEX_NAME}' already exists. Deleting...")
            client.indices.delete(index=INDEX_NAME)
        
        print(f"  Creating index '{INDEX_NAME}'...")
        client.indices.create(index=INDEX_NAME, body=INDEX_MAPPING)
        print(f"✓ Index '{INDEX_NAME}' created successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to create index: {e}")
        return False


def index_documents(client: OpenSearch) -> int:
    """Index sample documents with security attributes."""
    indexed = 0
    base_date = datetime.now() - timedelta(days=90)
    
    print(f"  Indexing {len(SAMPLE_DOCUMENTS)} documents...")
    
    for i, doc in enumerate(SAMPLE_DOCUMENTS):
        # Add timestamps
        doc["created_at"] = (base_date + timedelta(days=random.randint(0, 90))).isoformat()
        doc["updated_at"] = datetime.now().isoformat()
        
        try:
            client.index(
                index=INDEX_NAME,
                id=f"doc-{i+1:04d}",
                body=doc,
                refresh=True,
            )
            indexed += 1
            
            # Print document info
            compartments = doc.get("compartments", [])
            comp_str = ", ".join(compartments) if compartments else "none"
            print(f"    [{doc['classification']:12}] [{comp_str:30}] {doc['title'][:50]}")
            
        except Exception as e:
            print(f"✗ Failed to index document '{doc['title']}': {e}")
    
    return indexed


def print_summary(client: OpenSearch):
    """Print index summary statistics."""
    try:
        # Get document count
        count = client.count(index=INDEX_NAME)["count"]
        
        # Get classification distribution
        agg_result = client.search(
            index=INDEX_NAME,
            body={
                "size": 0,
                "aggs": {
                    "by_classification": {
                        "terms": {"field": "classification"}
                    },
                    "by_compartment": {
                        "terms": {"field": "compartments"}
                    },
                    "by_category": {
                        "terms": {"field": "category.keyword"}
                    }
                }
            }
        )
        
        print("\n" + "=" * 60)
        print("INDEX SUMMARY")
        print("=" * 60)
        print(f"Total documents: {count}")
        
        print("\nBy Classification:")
        for bucket in agg_result["aggregations"]["by_classification"]["buckets"]:
            print(f"  {bucket['key']:15} {bucket['doc_count']}")
        
        print("\nBy Compartment:")
        for bucket in agg_result["aggregations"]["by_compartment"]["buckets"]:
            print(f"  {bucket['key']:20} {bucket['doc_count']}")
        
        print("\nBy Category:")
        for bucket in agg_result["aggregations"]["by_category"]["buckets"]:
            print(f"  {bucket['key']:20} {bucket['doc_count']}")
        
        print("=" * 60)
        
    except Exception as e:
        print(f"✗ Failed to get summary: {e}")


def main():
    """Main setup function."""
    print("=" * 60)
    print("OpenSearch Secure Documents Setup")
    print("=" * 60)
    print(f"Host: {OPENSEARCH_HOST}:{OPENSEARCH_PORT}")
    print(f"Index: {INDEX_NAME}")
    print("=" * 60)
    
    # Create client
    client = OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        use_ssl=False,
        verify_certs=False,
    )
    
    # Wait for OpenSearch
    if not wait_for_opensearch(client):
        print("✗ OpenSearch not available. Exiting.")
        sys.exit(1)
    
    # Create index
    if not create_index(client):
        sys.exit(1)
    
    # Index documents
    indexed = index_documents(client)
    print(f"✓ Indexed {indexed}/{len(SAMPLE_DOCUMENTS)} documents")
    
    # Print summary
    print_summary(client)
    
    print("\n✓ Setup complete!")
    print("\nAccess patterns:")
    print("  UNCLASSIFIED user: Can see 2 documents")
    print("  CONFIDENTIAL user: Can see 4 documents")
    print("  SECRET user (no compartments): Can see 6 documents")
    print("  SECRET user + PROJECT_ALPHA: Can see 8 documents")
    print("  SECRET user + PROJECT_OMEGA: Can see 8 documents")
    print("  TOP_SECRET user (no compartments): Can see 7 documents")
    print("  TOP_SECRET + OPERATION_DELTA: Can see 9 documents")
    print("  TOP_SECRET + all compartments: Can see all 16 documents")


if __name__ == "__main__":
    main()
