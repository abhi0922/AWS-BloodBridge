"""
AWS DynamoDB-backed data store.

NOTE: This module is not currently wired into the main Flask routes,
but it has been refactored away from MongoDB so that any future use
will already rely on DynamoDB and boto3 instead of PyMongo.

IAM ROLE-BASED AUTHENTICATION:
- Uses EC2 Instance IAM Role for AWS authentication
- NO hardcoded AWS credentials (access keys/secrets) are used
- boto3 automatically uses EC2 instance's IAM role credentials via
  the default credential chain (EC2 instance metadata service)
- Required IAM permissions: dynamodb:GetItem, PutItem, UpdateItem, DeleteItem, Scan, Query
"""

import os
import uuid

import boto3
from boto3.dynamodb.conditions import Attr

class DataStore:
    def __init__(self, region_name=None):
        region = region_name or os.environ.get("AWS_REGION", "us-east-1")
        # AWS PERMISSION REQUIRED: DynamoDB read/write access
        # boto3 will automatically use EC2 IAM role credentials (no explicit credentials passed)
        self.dynamodb = boto3.resource("dynamodb", region_name=region)
        self.users = self.dynamodb.Table(os.environ.get("USERS_TABLE", "BloodBridgeUsers"))
        self.requests = self.dynamodb.Table(os.environ.get("REQUESTS_TABLE", "BloodBridgeRequests"))
        self.donations = self.dynamodb.Table(os.environ.get("DONATIONS_TABLE", "BloodBridgeDonations"))

    # --- User Operations ---
    def add_user(self, user_data):
        """Inserts a new user into DynamoDB."""
        # AWS PERMISSION REQUIRED: dynamodb:PutItem on users table
        if "user_id" not in user_data:
            user_id = str(uuid.uuid4())
            user_data["user_id"] = user_id
            user_data["_id"] = user_id
        self.users.put_item(Item=user_data)
        return user_data

    def find_user_by_email(self, email):
        """Finds a single user by their email address."""
        # AWS PERMISSION REQUIRED: dynamodb:Scan on users table
        items = self.users.scan(FilterExpression=Attr("email").eq(email)).get("Items", [])
        return items[0] if items else None

    def get_all_users(self):
        """Returns a list of all users."""
        # AWS PERMISSION REQUIRED: dynamodb:Scan on users table
        items = []
        resp = self.users.scan()
        items.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = self.users.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []))
        return items

    def delete_user(self, user_id):
        """Deletes a user by their user_id."""
        # AWS PERMISSION REQUIRED: dynamodb:DeleteItem on users table
        self.users.delete_item(Key={"user_id": user_id})

    # --- Blood Request Operations ---
    def create_request(self, request_data):
        """Stores a new blood request."""
        # AWS PERMISSION REQUIRED: dynamodb:PutItem on requests table
        if "request_id" not in request_data:
            rid = str(uuid.uuid4())
            request_data["request_id"] = rid
            request_data["_id"] = rid
        self.requests.put_item(Item=request_data)
        return request_data

    def get_all_requests(self):
        """Fetches all blood requests, sorted by newest first (by timestamp)."""
        # AWS PERMISSION REQUIRED: dynamodb:Scan on requests table
        items = []
        resp = self.requests.scan()
        items.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = self.requests.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []))
        return sorted(items, key=lambda r: r.get("timestamp") or "", reverse=True)

    def get_requests_by_type(self, blood_group):
        """Filters requests by blood group."""
        # AWS PERMISSION REQUIRED: dynamodb:Scan on requests table
        items = self.requests.scan(
            FilterExpression=Attr("blood_group").eq(blood_group)
        ).get("Items", [])
        return items

    def update_request_status(self, request_id, new_status):
        """Updates the status (e.g., pending to fulfilled)."""
        # AWS PERMISSION REQUIRED: dynamodb:UpdateItem on requests table
        self.requests.update_item(
            Key={"request_id": request_id},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": new_status},
        )
        return True

    # --- Inventory Operations (derived from donations) ---
    def calculate_inventory_from_donations(self):
        """
        Calculates inventory by counting completed donations grouped by blood group.
        This mirrors the application-level helper in app.py, but exposed here in case
        you want a reusable abstraction.
        
        AWS PERMISSION REQUIRED: dynamodb:Scan on donations table
        """
        blood_groups = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
        counts = {bg: 0 for bg in blood_groups}
        items = []
        resp = self.donations.scan()
        items.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = self.donations.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []))

        for d in items:
            bg = d.get("blood_group")
            status = d.get("status")
            if bg in counts and status in ("Scheduled", "Completed"):
                counts[bg] += 1

        # Return a list of {group, units} for convenience
        return [{"group": bg, "units": units} for bg, units in counts.items()]