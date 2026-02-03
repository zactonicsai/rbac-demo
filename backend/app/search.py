"""
OpenSearch Routes with RBAC + Cell-Level Security

Implements secure document search with:
- Classification-based filtering (clearance levels)
- Compartment-based access (need-to-know)
- Cell-level field masking
- Comprehensive audit logging
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional
from enum import IntEnum
from datetime import datetime

from app.opensearch_client import get_opensearch_client, OpenSearchConfig, check_opensearch_health
from app.auth import get_current_user, CurrentUser


router = APIRouter(prefix="/api/search", tags=["Search"])


# ─── Classification Levels (Hierarchical) ───────────────────────────────────
class ClearanceLevel(IntEnum):
    """Security clearance levels in ascending order of access."""
    UNCLASSIFIED = 0
    CONFIDENTIAL = 1
    SECRET = 2
    TOP_SECRET = 3


CLEARANCE_MAP = {
    "UNCLASSIFIED": ClearanceLevel.UNCLASSIFIED,
    "CONFIDENTIAL": ClearanceLevel.CONFIDENTIAL,
    "SECRET": ClearanceLevel.SECRET,
    "TOP_SECRET": ClearanceLevel.TOP_SECRET,
}


# ─── Request/Response Models ────────────────────────────────────────────────
class SearchRequest(BaseModel):
    """Search request with optional filters."""
    query: str = Field(..., min_length=1, max_length=500, description="Search query text")
    category: Optional[str] = Field(None, description="Filter by document category")
    date_from: Optional[datetime] = Field(None, description="Filter documents from this date")
    date_to: Optional[datetime] = Field(None, description="Filter documents until this date")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(10, ge=1, le=100, description="Results per page")


class DocumentHit(BaseModel):
    """A single search result with security-filtered fields."""
    id: str
    title: str
    summary: Optional[str] = None
    category: Optional[str] = None
    classification: str
    compartments: list[str] = []
    created_at: Optional[datetime] = None
    author: Optional[str] = None
    score: float
    # Cell-level security: fields that were masked
    masked_fields: list[str] = []


class SearchResponse(BaseModel):
    """Search response with metadata."""
    total: int
    page: int
    page_size: int
    total_pages: int
    results: list[DocumentHit]
    query_time_ms: float
    user_clearance: str
    user_compartments: list[str]
    filters_applied: dict


# ─── Security Filter Builder ────────────────────────────────────────────────
def build_security_filter(user: CurrentUser) -> list[dict]:
    """
    Build OpenSearch query filters based on user's security attributes.
    
    This implements:
    1. Classification filtering: User can only see documents at or below their clearance
    2. Compartment filtering: User must have ALL required compartments for a document
    
    Args:
        user: Current authenticated user with security attributes
        
    Returns:
        List of OpenSearch filter clauses
    """
    filters = []
    
    # Get user's clearance level (default to UNCLASSIFIED if not set)
    user_clearance = CLEARANCE_MAP.get(
        user.clearance_level.upper() if user.clearance_level else "UNCLASSIFIED",
        ClearanceLevel.UNCLASSIFIED
    )
    
    # Classification filter: user can see documents at or below their clearance
    allowed_classifications = [
        level.name for level in ClearanceLevel 
        if level <= user_clearance
    ]
    
    filters.append({
        "terms": {
            "classification.keyword": allowed_classifications
        }
    })
    
    # Compartment filter: 
    # Documents with NO compartments are visible to all (at appropriate clearance)
    # Documents WITH compartments require user to have ALL of them
    user_compartments = user.compartments or []
    
    # This filter allows documents where:
    # - document has no compartments (empty array), OR
    # - all document compartments are in user's compartments
    compartment_filter = {
        "bool": {
            "should": [
                # Option 1: Document has no compartment restrictions
                {
                    "bool": {
                        "must_not": {
                            "exists": {"field": "compartments"}
                        }
                    }
                },
                # Option 2: Document compartments is empty array
                {
                    "term": {
                        "compartments": []
                    }
                },
            ],
            "minimum_should_match": 1
        }
    }
    
    # If user has compartments, also allow documents they have access to
    if user_compartments:
        # Add condition: all document compartments must be in user's list
        compartment_filter["bool"]["should"].append({
            "script": {
                "script": {
                    "source": """
                        if (doc['compartments'].size() == 0) return true;
                        def userCompartments = params.userCompartments;
                        for (comp in doc['compartments']) {
                            if (!userCompartments.contains(comp)) return false;
                        }
                        return true;
                    """,
                    "params": {
                        "userCompartments": user_compartments
                    }
                }
            }
        })
    
    filters.append(compartment_filter)
    
    return filters


def apply_cell_level_security(doc: dict, user: CurrentUser) -> tuple[dict, list[str]]:
    """
    Apply cell-level security to mask fields the user cannot access.
    
    Each field can have its own classification and compartment requirements
    stored in a 'field_security' metadata object.
    
    Args:
        doc: Raw document from OpenSearch
        user: Current authenticated user
        
    Returns:
        Tuple of (filtered document, list of masked field names)
    """
    masked_fields = []
    filtered_doc = doc.copy()
    
    # Get field-level security metadata if present
    field_security = doc.get("_source", {}).get("field_security", {})
    
    user_clearance = CLEARANCE_MAP.get(
        user.clearance_level.upper() if user.clearance_level else "UNCLASSIFIED",
        ClearanceLevel.UNCLASSIFIED
    )
    user_compartments = set(user.compartments or [])
    
    source = filtered_doc.get("_source", {})
    
    for field_name, security in field_security.items():
        # Check field classification
        field_classification = CLEARANCE_MAP.get(
            security.get("classification", "UNCLASSIFIED"),
            ClearanceLevel.UNCLASSIFIED
        )
        
        # Check field compartments
        field_compartments = set(security.get("compartments", []))
        
        # Mask field if user doesn't have sufficient clearance or compartments
        should_mask = False
        
        if field_classification > user_clearance:
            should_mask = True
        elif field_compartments and not field_compartments.issubset(user_compartments):
            should_mask = True
        
        if should_mask and field_name in source:
            source[field_name] = "[REDACTED]"
            masked_fields.append(field_name)
    
    filtered_doc["_source"] = source
    return filtered_doc, masked_fields


# ─── API Endpoints ──────────────────────────────────────────────────────────
@router.get("/health")
async def search_health():
    """Check OpenSearch connection health."""
    return await check_opensearch_health()


@router.post("/documents", response_model=SearchResponse)
async def search_documents(
    request: SearchRequest,
    user: CurrentUser = Depends(get_current_user),
):
    """
    Search documents with RBAC and cell-level security filtering.
    
    Security enforcement:
    1. Document-level: Only returns documents user has clearance + compartments for
    2. Cell-level: Masks individual fields user cannot access within visible documents
    
    The user's JWT token provides:
    - clearance_level: Maximum classification they can view
    - compartments: List of need-to-know compartments they belong to
    - roles: RBAC roles (viewer, analyst, manager, admin, auditor)
    """
    import time
    start_time = time.time()
    
    client = get_opensearch_client()
    config = OpenSearchConfig()
    
    # Build the secure query
    security_filters = build_security_filter(user)
    
    # Build the main query
    must_clauses = [
        {
            "multi_match": {
                "query": request.query,
                "fields": ["title^3", "summary^2", "content", "author", "category"],
                "type": "best_fields",
                "fuzziness": "AUTO",
            }
        }
    ]
    
    # Optional category filter
    if request.category:
        must_clauses.append({
            "term": {"category.keyword": request.category}
        })
    
    # Optional date range filter
    if request.date_from or request.date_to:
        date_range = {"range": {"created_at": {}}}
        if request.date_from:
            date_range["range"]["created_at"]["gte"] = request.date_from.isoformat()
        if request.date_to:
            date_range["range"]["created_at"]["lte"] = request.date_to.isoformat()
        must_clauses.append(date_range)
    
    # Combine into final query with security filters
    query_body = {
        "query": {
            "bool": {
                "must": must_clauses,
                "filter": security_filters,
            }
        },
        "from": (request.page - 1) * request.page_size,
        "size": request.page_size,
        "sort": [
            {"_score": {"order": "desc"}},
            {"created_at": {"order": "desc", "unmapped_type": "date"}},
        ],
        "_source": {
            "excludes": ["content"]  # Don't return full content in search results
        },
    }
    
    try:
        response = await client.search(
            index=config.INDEX_NAME,
            body=query_body,
        )
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Search service unavailable: {str(e)}"
        )
    
    # Process results with cell-level security
    hits = response.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    
    results = []
    for hit in hits.get("hits", []):
        # Apply cell-level security
        filtered_hit, masked_fields = apply_cell_level_security(hit, user)
        source = filtered_hit.get("_source", {})
        
        results.append(DocumentHit(
            id=hit["_id"],
            title=source.get("title", "Untitled"),
            summary=source.get("summary"),
            category=source.get("category"),
            classification=source.get("classification", "UNCLASSIFIED"),
            compartments=source.get("compartments", []),
            created_at=source.get("created_at"),
            author=source.get("author"),
            score=hit.get("_score", 0.0),
            masked_fields=masked_fields,
        ))
    
    query_time_ms = (time.time() - start_time) * 1000
    
    # Log the search for audit (would integrate with your audit system)
    await log_search_audit(user, request, total, query_time_ms)
    
    return SearchResponse(
        total=total,
        page=request.page,
        page_size=request.page_size,
        total_pages=(total + request.page_size - 1) // request.page_size,
        results=results,
        query_time_ms=round(query_time_ms, 2),
        user_clearance=user.clearance_level or "UNCLASSIFIED",
        user_compartments=user.compartments or [],
        filters_applied={
            "classification_filter": f"<= {user.clearance_level or 'UNCLASSIFIED'}",
            "compartment_filter": user.compartments or [],
            "category": request.category,
            "date_range": {
                "from": request.date_from.isoformat() if request.date_from else None,
                "to": request.date_to.isoformat() if request.date_to else None,
            }
        },
    )


@router.get("/documents/{document_id}")
async def get_document(
    document_id: str,
    user: CurrentUser = Depends(get_current_user),
):
    """
    Retrieve a single document by ID with security filtering.
    
    Returns the full document content (not just summary) if user has access.
    Cell-level security is applied to mask restricted fields.
    """
    client = get_opensearch_client()
    config = OpenSearchConfig()
    
    try:
        response = await client.get(
            index=config.INDEX_NAME,
            id=document_id,
        )
    except Exception as e:
        if "not_found" in str(e).lower():
            raise HTTPException(status_code=404, detail="Document not found")
        raise HTTPException(status_code=503, detail=f"Search service error: {str(e)}")
    
    source = response.get("_source", {})
    
    # Check document-level access
    doc_classification = CLEARANCE_MAP.get(
        source.get("classification", "UNCLASSIFIED"),
        ClearanceLevel.UNCLASSIFIED
    )
    user_clearance = CLEARANCE_MAP.get(
        user.clearance_level.upper() if user.clearance_level else "UNCLASSIFIED",
        ClearanceLevel.UNCLASSIFIED
    )
    
    # Classification check
    if doc_classification > user_clearance:
        await log_access_denied(user, document_id, "insufficient_clearance")
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: Document requires {source.get('classification')} clearance"
        )
    
    # Compartment check
    doc_compartments = set(source.get("compartments", []))
    user_compartments = set(user.compartments or [])
    
    if doc_compartments and not doc_compartments.issubset(user_compartments):
        missing = doc_compartments - user_compartments
        await log_access_denied(user, document_id, f"missing_compartments: {missing}")
        raise HTTPException(
            status_code=403,
            detail="Access denied: You lack required compartment access"
        )
    
    # Apply cell-level security
    filtered_response, masked_fields = apply_cell_level_security(response, user)
    
    # Log successful access
    await log_document_access(user, document_id)
    
    return {
        "id": document_id,
        "document": filtered_response.get("_source", {}),
        "masked_fields": masked_fields,
        "access_granted": True,
    }


@router.get("/categories")
async def list_categories(
    user: CurrentUser = Depends(get_current_user),
):
    """
    List all document categories the user can access.
    
    Returns aggregated category counts filtered by user's security level.
    """
    client = get_opensearch_client()
    config = OpenSearchConfig()
    
    security_filters = build_security_filter(user)
    
    query_body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": security_filters
            }
        },
        "aggs": {
            "categories": {
                "terms": {
                    "field": "category.keyword",
                    "size": 50,
                }
            }
        }
    }
    
    try:
        response = await client.search(
            index=config.INDEX_NAME,
            body=query_body,
        )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Search service error: {str(e)}")
    
    buckets = response.get("aggregations", {}).get("categories", {}).get("buckets", [])
    
    return {
        "categories": [
            {"name": bucket["key"], "count": bucket["doc_count"]}
            for bucket in buckets
        ],
        "user_clearance": user.clearance_level,
    }


# ─── Audit Logging Helpers ──────────────────────────────────────────────────
async def log_search_audit(user: CurrentUser, request: SearchRequest, total: int, query_time_ms: float):
    """Log search action for audit trail."""
    # This would integrate with your existing audit system
    # For now, just print to demonstrate
    print(f"[AUDIT] Search: user={user.username}, query='{request.query}', "
          f"results={total}, time={query_time_ms:.2f}ms, "
          f"clearance={user.clearance_level}, compartments={user.compartments}")


async def log_document_access(user: CurrentUser, document_id: str):
    """Log document access for audit trail."""
    print(f"[AUDIT] Document access: user={user.username}, doc_id={document_id}, "
          f"clearance={user.clearance_level}")


async def log_access_denied(user: CurrentUser, document_id: str, reason: str):
    """Log access denial for audit trail."""
    print(f"[AUDIT] Access DENIED: user={user.username}, doc_id={document_id}, "
          f"reason={reason}, clearance={user.clearance_level}")
