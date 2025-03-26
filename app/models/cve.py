"""Models for CVE data processing."""
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

@dataclass
class BaseNode:
    """Base class for all nodes."""
    id: str = field(default="")
    Type: str = field(default="NODE")
    NodeType: str = field(default="")

@dataclass
class BaseRelationship:
    """Base class for all relationships."""
    id: str = field(default="")
    source_id: str = field(default="")
    target_id: str = field(default="")
    Type: str = field(default="RELATIONSHIP")
    Relationship: str = field(default="")

@dataclass
class CVENode:
    """CVE node with vulnerability information."""
    id: str
    title: str
    description: str
    published_date: str
    modified_date: str
    reserved_date: str
    state: str
    assigner_id: str
    assigner_name: str
    severity: str
    cvss_score: float
    cvss_vector: str
    Type: str = field(default="NODE")
    NodeType: str = field(default="CVE")
    # Additional CVSS fields
    impact_confidentiality: str = field(default="")
    impact_integrity: str = field(default="")
    impact_availability: str = field(default="")
    attack_complexity: str = field(default="")
    attack_vector: str = field(default="")
    privileges_required: str = field(default="")
    scope: str = field(default="")
    user_interaction: str = field(default="")

    def __post_init__(self):
        """Set node type after initialization."""
        self.NodeType = "CVE"

    def to_dict(self) -> dict:
        """Convert CVE node to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'NodeType': self.NodeType,
            'Title': self.title,
            'Description': self.description,
            'PublishedDate': self.published_date,
            'ModifiedDate': self.modified_date,
            'ReservedDate': self.reserved_date,
            'State': self.state,
            'AssignerID': self.assigner_id,
            'AssignerName': self.assigner_name,
            'Severity': self.severity,
            'CVSSScore': self.cvss_score,
            'CVSSVector': self.cvss_vector,
            'ImpactConfidentiality': self.impact_confidentiality,
            'ImpactIntegrity': self.impact_integrity,
            'ImpactAvailability': self.impact_availability,
            'AttackComplexity': self.attack_complexity,
            'AttackVector': self.attack_vector,
            'PrivilegesRequired': self.privileges_required,
            'Scope': self.scope,
            'UserInteraction': self.user_interaction
        }

@dataclass
class ProductNode:
    """Product node with version information."""
    id: str
    name: str
    vendor: str
    version: str
    status: str
    Type: str = field(default="NODE")
    NodeType: str = field(default="PRODUCT")
    cpes: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    program_files: List[str] = field(default_factory=list)
    program_routines: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Set node type and initialize lists."""
        self.NodeType = "PRODUCT"
        self.platforms = self.platforms or []
        self.modules = self.modules or []
        self.program_files = self.program_files or []
        self.program_routines = self.program_routines or []

    def to_dict(self) -> dict:
        """Convert product node to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'NodeType': self.NodeType,
            'Name': self.name,
            'Vendor': self.vendor,
            'Version': self.version,
            'Status': self.status,
            'CPEs': ','.join(self.cpes),
            'Platforms': ','.join(self.platforms),
            'Modules': ','.join(self.modules),
            'ProgramFiles': ','.join(self.program_files),
            'ProgramRoutines': ','.join(self.program_routines)
        }

@dataclass
class CPENode:
    """CPE node with version information."""
    id: str
    cpe_string: str
    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str
    Type: str = field(default="NODE")
    NodeType: str = field(default="CPE")

    def __post_init__(self):
        """Set node type after initialization."""
        self.NodeType = "CPE"

    def to_dict(self) -> dict:
        """Convert CPE node to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'NodeType': self.NodeType,
            'CPEString': self.cpe_string,
            'Part': self.part,
            'Vendor': self.vendor,
            'Product': self.product,
            'Version': self.version,
            'Update': self.update,
            'Edition': self.edition,
            'Language': self.language,
            'SWEdition': self.sw_edition,
            'TargetSW': self.target_sw,
            'TargetHW': self.target_hw,
            'Other': self.other
        }

@dataclass
class VendorNode:
    """Vendor node with company information."""
    id: str
    name: str
    industry: str
    location: str
    website: str
    Type: str = field(default="NODE")
    NodeType: str = field(default="VENDOR")

    def __post_init__(self):
        """Set node type after initialization."""
        self.NodeType = "VENDOR"

    def to_dict(self) -> dict:
        """Convert vendor node to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'NodeType': self.NodeType,
            'Name': self.name,
            'Industry': self.industry,
            'Location': self.location,
            'Website': self.website
        }

@dataclass
class CWENode:
    """CWE node with weakness information."""
    id: str
    name: str
    description: str
    language: str
    Type: str = field(default="NODE")
    NodeType: str = field(default="CWE")

    def __post_init__(self):
        """Set node type after initialization."""
        self.NodeType = "CWE"

    def to_dict(self) -> dict:
        """Convert CWE node to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'NodeType': self.NodeType,
            'Name': self.name,
            'Description': self.description,
            'Language': self.language
        }

@dataclass
class ReferenceNode:
    """Reference node with URL information."""
    id: str
    url: str
    name: str
    source: str
    Type: str = field(default="NODE")
    NodeType: str = field(default="REFERENCE")
    reference_tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Set node type and initialize lists."""
        self.NodeType = "REFERENCE"
        self.reference_tags = self.reference_tags or []

    def to_dict(self) -> dict:
        """Convert reference node to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'NodeType': self.NodeType,
            'URL': self.url,
            'Name': self.name,
            'Source': self.source,
            'ReferenceTags': ','.join(self.reference_tags)
        }

@dataclass
class EventNode:
    """Event node with timeline information."""
    id: str
    time: str
    value: str
    language: str
    Type: str = field(default="NODE")
    NodeType: str = field(default="EVENT")

    def __post_init__(self):
        """Set node type after initialization."""
        self.NodeType = "EVENT"

    def to_dict(self) -> dict:
        """Convert event node to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'NodeType': self.NodeType,
            'Time': self.time,
            'Value': self.value,
            'Language': self.language
        }

@dataclass
class AffectsRelationship:
    """Relationship between CVE and affected product."""
    id: str
    source_id: str
    target_id: str
    version_range: str
    attack_vector: str
    cve_status: str
    patch_status: str
    Type: str = field(default="RELATIONSHIP")
    Relationship: str = field(default="AFFECTS")

    def __post_init__(self):
        """Set relationship type after initialization."""
        self.Relationship = "AFFECTS"

    def to_dict(self) -> dict:
        """Convert affects relationship to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'Relationship': self.Relationship,
            'SourceID': self.source_id,
            'TargetID': self.target_id,
            'VersionRange': self.version_range,
            'AttackVector': self.attack_vector,
            'CVEStatus': self.cve_status,
            'PatchStatus': self.patch_status
        }

@dataclass
class HasCPERelationship:
    """Relationship between Product and CPE."""
    id: str
    source_id: str
    target_id: str
    Type: str = field(default="RELATIONSHIP")
    Relationship: str = field(default="HAS_CPE")

    def __post_init__(self):
        """Set relationship type after initialization."""
        self.Relationship = "HAS_CPE"

    def to_dict(self) -> dict:
        """Convert has CPE relationship to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'Relationship': self.Relationship,
            'SourceID': self.source_id,
            'TargetID': self.target_id
        }

@dataclass
class BelongsToRelationship:
    """Relationship between product and vendor."""
    id: str
    source_id: str
    target_id: str
    license: str
    support_status: str
    Type: str = field(default="RELATIONSHIP")
    Relationship: str = field(default="BELONGS_TO")

    def __post_init__(self):
        """Set relationship type after initialization."""
        self.Relationship = "BELONGS_TO"

    def to_dict(self) -> dict:
        """Convert belongs to relationship to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'Relationship': self.Relationship,
            'SourceID': self.source_id,
            'TargetID': self.target_id,
            'License': self.license,
            'SupportStatus': self.support_status
        }

@dataclass
class HasCWERelationship:
    """Relationship between CVE and CWE."""
    id: str
    source_id: str
    target_id: str
    Type: str = field(default="RELATIONSHIP")
    Relationship: str = field(default="HAS_CWE")

    def __post_init__(self):
        """Set relationship type after initialization."""
        self.Relationship = "HAS_CWE"

    def to_dict(self) -> dict:
        """Convert has CWE relationship to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'Relationship': self.Relationship,
            'SourceID': self.source_id,
            'TargetID': self.target_id
        }

@dataclass
class HasReferenceRelationship:
    """Relationship between CVE and reference."""
    id: str
    source_id: str
    target_id: str
    Type: str = field(default="RELATIONSHIP")
    Relationship: str = field(default="HAS_REFERENCE")

    def __post_init__(self):
        """Set relationship type after initialization."""
        self.Relationship = "HAS_REFERENCE"

    def to_dict(self) -> dict:
        """Convert has reference relationship to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'Relationship': self.Relationship,
            'SourceID': self.source_id,
            'TargetID': self.target_id
        }

@dataclass
class HasEventRelationship:
    """Relationship between CVE and event."""
    id: str
    source_id: str
    target_id: str
    Type: str = field(default="RELATIONSHIP")
    Relationship: str = field(default="HAS_EVENT")

    def __post_init__(self):
        """Set relationship type after initialization."""
        self.Relationship = "HAS_EVENT"

    def to_dict(self) -> dict:
        """Convert has event relationship to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.Type,
            'Relationship': self.Relationship,
            'SourceID': self.source_id,
            'TargetID': self.target_id
        } 