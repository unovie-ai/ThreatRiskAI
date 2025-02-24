from marshmallow import Schema, fields, validate

class UploadRequestSchema(Schema):
    data_type = fields.String(required=True, validate=validate.OneOf(["CVE", "MITRE"]), description="Type of data (CVE or MITRE)")
    platform = fields.String(required=True, description="Target platform (e.g., containers, Windows)")
    file_content = fields.String(required=True, description="JSON file content as a string")

class QueryRequestSchema(Schema):
    query = fields.String(required=True, description="The query string to search the database")

class QueryResponseSchema(Schema):
    result = fields.String(required=True, description="The query result")

class ErrorResponseSchema(Schema):
    error = fields.String(required=True, description="Error message")
