"""Email authentication validation module (SPF, DKIM, DMARC, CAA).

Uses checkdmarc library for comprehensive email authentication validation
and dns.resolver for CAA record checking.
"""

import logging
from typing import Optional

import checkdmarc
import dns.resolver

logger = logging.getLogger(__name__)

# Default DKIM selectors to check (common providers)
DEFAULT_DKIM_SELECTORS = ["default", "mailgun", "mx", "smtp", "k1", "google", "selector1", "selector2"]


def _extract_apex_domain(domain: str) -> str:
    """Extract apex domain from a possibly full subdomain.
    
    Simple heuristic: take the last two parts for common TLDs.
    For waldo.click, waldoclick.dev this works correctly.
    """
    parts = domain.lower().strip().split(".")
    if len(parts) <= 2:
        return domain.lower().strip()
    # Handle common TLDs - take last 2 parts
    return ".".join(parts[-2:])


def check_email_security(
    domain: str, dkim_selectors: Optional[list] = None
) -> dict:
    """Check SPF, DKIM, and DMARC records for a domain.
    
    Args:
        domain: Domain to check (can be subdomain - will extract apex)
        dkim_selectors: List of DKIM selectors to check (optional)
    
    Returns:
        dict with keys: domain, spf, dkim, dmarc, issues
    """
    apex_domain = _extract_apex_domain(domain)
    selectors = dkim_selectors or DEFAULT_DKIM_SELECTORS
    issues = []
    
    result = {
        "domain": apex_domain,
        "spf": {},
        "dkim": {},
        "dmarc": {},
        "issues": issues,
    }
    
    try:
        # checkdmarc.check_domains returns DomainCheckResult dict directly for single domain
        # Pass domain as list for consistent API behavior
        check_result = checkdmarc.check_domains(
            [apex_domain],
            skip_tls=True,
            timeout=5.0,
        )
        
        # For single domain, result is the dict directly (not nested by domain)
        domain_data = check_result if isinstance(check_result, dict) else {}
        
        # Process SPF
        spf_data = domain_data.get("spf", {})
        result["spf"] = {
            "record": spf_data.get("record", ""),
            "valid": spf_data.get("valid", False),
            "dns_lookups": spf_data.get("dns_lookups", 0),
            "warnings": spf_data.get("warnings", []),
            "errors": spf_data.get("errors", []),
        }
        
        # Add issues for SPF warnings
        for warning in spf_data.get("warnings", []):
            issues.append({
                "severity": "warning",
                "type": "spf",
                "message": str(warning),
            })
        for error in spf_data.get("errors", []):
            issues.append({
                "severity": "error",
                "type": "spf",
                "message": str(error),
            })
        
        # Check SPF lookup count
        lookups = spf_data.get("dns_lookups", 0)
        if lookups >= 9:
            issues.append({
                "severity": "warning",
                "type": "spf",
                "message": f"SPF record uses {lookups} DNS lookups (limit is 10)",
            })
        
        # Process DKIM
        dkim_data = domain_data.get("dkim", {})
        result["dkim"] = {
            "selectors": dkim_data.get("selectors", {}),
            "warnings": dkim_data.get("warnings", []),
            "errors": dkim_data.get("errors", []),
        }
        
        # Process DMARC
        dmarc_data = domain_data.get("dmarc", {})
        # Extract policy from tags (new checkdmarc structure)
        tags = dmarc_data.get("tags", {})
        policy = tags.get("p", {}).get("value", "") if tags else dmarc_data.get("policy", "")
        pct = tags.get("pct", {}).get("value", 100) if tags else dmarc_data.get("pct", 100)
        
        result["dmarc"] = {
            "record": dmarc_data.get("record", ""),
            "policy": policy,
            "pct": pct,
            "valid": dmarc_data.get("valid", False),
            "warnings": dmarc_data.get("warnings", []),
            "errors": dmarc_data.get("errors", []),
        }
        
        # Add issues for DMARC
        for warning in dmarc_data.get("warnings", []):
            issues.append({
                "severity": "warning",
                "type": "dmarc",
                "message": str(warning),
            })
        for error in dmarc_data.get("errors", []):
            issues.append({
                "severity": "error",
                "type": "dmarc",
                "message": str(error),
            })
        
        # Check for ineffective DMARC policy
        if policy == "none":
            issues.append({
                "severity": "warning",
                "type": "dmarc",
                "message": "DMARC policy p=none provides no protection against spoofing",
            })
        
    except Exception as e:
        logger.warning(f"Error checking email security for {apex_domain}: {e}")
        result["error"] = str(e)
        issues.append({
            "severity": "error",
            "type": "general",
            "message": f"Failed to check email security: {e}",
        })
    
    return result


def check_caa_records(domain: str, expected_ca: str = "pki.goog") -> dict:
    """Check CAA records for a domain.
    
    Args:
        domain: Domain to check
        expected_ca: Expected Certificate Authority (default: pki.goog for Google Trust Services)
    
    Returns:
        dict with keys: records, expected_ca, valid, issues
    """
    apex_domain = _extract_apex_domain(domain)
    records = []
    issues = []
    valid = False
    
    result = {
        "domain": apex_domain,
        "records": records,
        "expected_ca": expected_ca,
        "valid": valid,
        "issues": issues,
    }
    
    try:
        answers = dns.resolver.resolve(apex_domain, "CAA")
        
        for rdata in answers:
            # CAA record has flags, tag, and value
            tag = rdata.tag.decode("utf-8") if isinstance(rdata.tag, bytes) else str(rdata.tag)
            value = rdata.value.decode("utf-8") if isinstance(rdata.value, bytes) else str(rdata.value)
            
            record_entry = {
                "flags": rdata.flags,
                "tag": tag,
                "value": value,
            }
            records.append(record_entry)
            
            # Check if this record authorizes the expected CA
            if tag == "issue" and expected_ca in value:
                valid = True
        
        result["records"] = records
        result["valid"] = valid
        
        if not valid and records:
            issues.append({
                "severity": "warning",
                "type": "caa",
                "message": f"Expected CA '{expected_ca}' not found in CAA records",
            })
        elif not records:
            issues.append({
                "severity": "info",
                "type": "caa",
                "message": "No CAA records found (any CA can issue certificates)",
            })
        
    except dns.resolver.NoAnswer:
        issues.append({
            "severity": "info",
            "type": "caa",
            "message": "No CAA records found (any CA can issue certificates)",
        })
    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain does not exist"
        issues.append({
            "severity": "error",
            "type": "caa",
            "message": f"Domain {apex_domain} does not exist",
        })
    except dns.resolver.LifetimeTimeout:
        result["error"] = "DNS timeout"
        issues.append({
            "severity": "error",
            "type": "caa",
            "message": "DNS timeout while checking CAA records",
        })
    except Exception as e:
        logger.warning(f"Error checking CAA records for {apex_domain}: {e}")
        result["error"] = str(e)
        issues.append({
            "severity": "error",
            "type": "caa",
            "message": f"Failed to check CAA records: {e}",
        })
    
    return result


def analyze_domain(domain: str, expected_ca: str = "pki.goog") -> dict:
    """Comprehensive domain analysis combining email security and CAA checks.
    
    This is the main entry point for Phase 3 report integration.
    
    Args:
        domain: Domain to analyze
        expected_ca: Expected Certificate Authority for CAA validation
    
    Returns:
        dict with keys: domain, spf, dkim, dmarc, caa, issues
    """
    apex_domain = _extract_apex_domain(domain)
    
    # Get email security results
    email_result = check_email_security(domain)
    
    # Get CAA results
    caa_result = check_caa_records(domain, expected_ca)
    
    # Combine all issues
    all_issues = email_result.get("issues", []) + caa_result.get("issues", [])
    
    return {
        "domain": apex_domain,
        "spf": email_result.get("spf", {}),
        "dkim": email_result.get("dkim", {}),
        "dmarc": email_result.get("dmarc", {}),
        "caa": {
            "records": caa_result.get("records", []),
            "expected_ca": expected_ca,
            "valid": caa_result.get("valid", False),
        },
        "issues": all_issues,
    }
