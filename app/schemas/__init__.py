"""API-related Pydantic models."""
from pydantic import BaseModel

class QueryRequestSchema(BaseModel):
    query: str

    class Config:
        from_attributes = True

class QueryResponseSchema(BaseModel):
    result: str

    class Config:
        from_attributes = True

class ErrorResponseSchema(BaseModel):
    error: str

    class Config:
        from_attributes = True 