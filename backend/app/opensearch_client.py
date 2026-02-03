"""
OpenSearch Client Configuration

Provides async OpenSearch client with connection pooling and retry logic.
"""
import os
from opensearchpy import AsyncOpenSearch
from functools import lru_cache


class OpenSearchConfig:
    """OpenSearch connection configuration."""
    
    HOST: str = os.getenv("OPENSEARCH_HOST", "opensearch")
    PORT: int = int(os.getenv("OPENSEARCH_PORT", "9200"))
    INDEX_NAME: str = os.getenv("OPENSEARCH_INDEX", "secure-documents")
    USE_SSL: bool = os.getenv("OPENSEARCH_USE_SSL", "false").lower() == "true"
    VERIFY_CERTS: bool = os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"
    
    # Optional authentication
    USERNAME: str | None = os.getenv("OPENSEARCH_USERNAME")
    PASSWORD: str | None = os.getenv("OPENSEARCH_PASSWORD")


@lru_cache()
def get_opensearch_client() -> AsyncOpenSearch:
    """
    Create and return a cached AsyncOpenSearch client.
    
    Returns:
        AsyncOpenSearch: Configured OpenSearch client
    """
    config = OpenSearchConfig()
    
    client_kwargs = {
        "hosts": [{"host": config.HOST, "port": config.PORT}],
        "use_ssl": config.USE_SSL,
        "verify_certs": config.VERIFY_CERTS,
        "ssl_show_warn": False,
    }
    
    # Add authentication if configured
    if config.USERNAME and config.PASSWORD:
        client_kwargs["http_auth"] = (config.USERNAME, config.PASSWORD)
    
    return AsyncOpenSearch(**client_kwargs)


async def check_opensearch_health() -> dict:
    """
    Check OpenSearch cluster health.
    
    Returns:
        dict: Cluster health information
    """
    client = get_opensearch_client()
    try:
        health = await client.cluster.health()
        return {
            "status": "connected",
            "cluster_name": health.get("cluster_name"),
            "cluster_status": health.get("status"),
            "number_of_nodes": health.get("number_of_nodes"),
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
        }
