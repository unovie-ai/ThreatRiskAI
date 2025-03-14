from marshmallow import Schema, fields, validate


class QueryRequestSchema(Schema):
    query = fields.String(required=True, description="The query string to search the database")

class QueryResponseSchema(Schema):
    result = fields.String(required=True, description="The query result")

class ErrorResponseSchema(Schema):
    error = fields.String(required=True, description="Error message")
