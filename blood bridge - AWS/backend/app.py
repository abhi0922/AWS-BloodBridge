import logging
import os
import uuid
from datetime import datetime

import boto3
# CloudWatch removed: watchtower import was here
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static",
)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "blood_bridge_secret_key")

# -------------------- AWS CONFIGURATION --------------------
# IAM ROLE-BASED AUTHENTICATION:
# This application uses EC2 Instance IAM Role for AWS authentication.
# NO hardcoded AWS credentials (access keys/secrets) are used.
#
# CREDENTIAL HANDLING:
# - boto3 automatically uses the EC2 instance's IAM role credentials via
#   the default credential chain (EC2 instance metadata service)
# - No explicit credentials are passed to boto3 clients/resources
# - When running on EC2, the instance must have an IAM role attached
#
# REQUIRED IAM ROLE PERMISSIONS:
# The EC2 instance IAM role must have the following permissions:
#
# 1. DynamoDB (Read/Write access for user table and other tables):
#    - dynamodb:GetItem
#    - dynamodb:PutItem
#    - dynamodb:UpdateItem
#    - dynamodb:DeleteItem
#    - dynamodb:Scan
#    - dynamodb:Query
#    Resource: arn:aws:dynamodb:<region>:<account>:table/BloodBridge*
#
# 2. SNS (Publish access for blood request notifications):
#    - sns:Publish
#    Resource: <SNS_TOPIC_ARN> (configured via BLOOD_REQUEST_SNS_TOPIC_ARN env var)
#
# CloudWatch Logs permissions removed - no longer using CloudWatch logging
#
# SETUP INSTRUCTIONS:
# 1. Create an IAM role with the above permissions
# 2. Attach the IAM role to your EC2 instance
# 3. Ensure environment variables are set (see below)
# 4. The application will automatically use the IAM role credentials
#
# ENVIRONMENT VARIABLES:
# - AWS_REGION: AWS region (default: us-east-1)
# - USERS_TABLE: DynamoDB table name for users (default: BloodBridgeUsers)
# - DONATIONS_TABLE: DynamoDB table name for donations (default: BloodBridgeDonations)
# - REQUESTS_TABLE: DynamoDB table name for requests (default: BloodBridgeRequests)
# - MESSAGES_TABLE: DynamoDB table name for messages (default: BloodBridgeMessages)
# - BLOOD_REQUEST_SNS_TOPIC_ARN: SNS topic ARN for blood request notifications
# CloudWatch environment variables removed: CLOUDWATCH_LOG_GROUP, CLOUDWATCH_LOG_STREAM

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# AWS PERMISSION REQUIRED: DynamoDB read/write access
# boto3 will automatically use EC2 IAM role credentials (no explicit credentials passed)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
users_table = dynamodb.Table(os.environ.get("USERS_TABLE", "BloodBridgeUsers"))
donations_table = dynamodb.Table(
    os.environ.get("DONATIONS_TABLE", "BloodBridgeDonations")
)
requests_table = dynamodb.Table(
    os.environ.get("REQUESTS_TABLE", "BloodBridgeRequests")
)
messages_table = dynamodb.Table(
    os.environ.get("MESSAGES_TABLE", "BloodBridgeMessages")
)

# AWS PERMISSION REQUIRED: SNS Publish access
# boto3 will automatically use EC2 IAM role credentials (no explicit credentials passed)
sns_client = boto3.client("sns", region_name=AWS_REGION)
SNS_TOPIC_ARN = os.environ.get("BLOOD_REQUEST_SNS_TOPIC_ARN")

# -------------------- LOGGING CONFIGURATION --------------------
# CloudWatch logging removed - now using standard Python logging to stdout/stderr
# Logs can be captured by EC2 CloudWatch agent or container logging if needed
logger = logging.getLogger("bloodbridge")
logger.setLevel(logging.INFO)

if not logger.handlers:
    # Stream to stdout (useful for local/dev and when EC2 logging agent is used)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    # CloudWatch direct logging removed - watchtower handler was here


# -------------------- DynamoDB HELPERS --------------------

def _scan_all(table, filter_expression=None, projection_expression=None):
    """
    Small wrapper to scan a DynamoDB table and return all items.
    For small to moderate data sizes this is acceptable; if your
    data grows, replace with appropriate Query + indexes.
    
    AWS PERMISSION REQUIRED: dynamodb:Scan on the specified table
    """
    import boto3.dynamodb.conditions as cond  # local import to avoid polluting top-level

    scan_kwargs = {}
    if filter_expression is not None:
        scan_kwargs["FilterExpression"] = filter_expression
    if projection_expression is not None:
        scan_kwargs["ProjectionExpression"] = projection_expression

    items = []
    response = table.scan(**scan_kwargs)
    items.extend(response.get("Items", []))
    while "LastEvaluatedKey" in response:
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
        response = table.scan(**scan_kwargs)
        items.extend(response.get("Items", []))
    return items


def get_user_by_email(email):
    """Fetch a single user by email. Uses a Scan for simplicity."""
    # AWS PERMISSION REQUIRED: dynamodb:Scan on users table
    from boto3.dynamodb.conditions import Attr

    users = _scan_all(users_table, Attr("email").eq(email))
    return users[0] if users else None


def get_user_by_id(user_id):
    """Fetch a single user by their unique user_id."""
    # AWS PERMISSION REQUIRED: dynamodb:GetItem on users table
    resp = users_table.get_item(Key={"user_id": user_id})
    return resp.get("Item")


def put_user(user_item):
    """Insert or overwrite a user record."""
    # AWS PERMISSION REQUIRED: dynamodb:PutItem on users table
    users_table.put_item(Item=user_item)


def delete_user_by_id(user_id):
    """Delete a user by user_id."""
    # AWS PERMISSION REQUIRED: dynamodb:DeleteItem on users table
    users_table.delete_item(Key={"user_id": user_id})


def get_user_donations(user_id):
    """Return all donations for a specific donor, newest first."""
    from boto3.dynamodb.conditions import Attr

    items = _scan_all(donations_table, Attr("donor_id").eq(user_id))
    # Sort by date (string) descending; ISO dates sort lexicographically
    return sorted(items, key=lambda d: (d.get("date") or "", d.get("donation_id", "")), reverse=True)


def get_user_requests(user_id):
    """Return all blood requests created by a specific user, newest first."""
    from boto3.dynamodb.conditions import Attr

    items = _scan_all(requests_table, Attr("requester_id").eq(user_id))
    return sorted(
        items,
        key=lambda r: (r.get("timestamp") or "", r.get("request_id", "")),
        reverse=True,
    )


def get_pending_requests():
    """Return all pending blood requests."""
    from boto3.dynamodb.conditions import Attr

    return _scan_all(requests_table, Attr("status").eq("pending"))


def get_all_requests():
    """Return all blood requests."""
    return _scan_all(requests_table)


def get_all_donations():
    """Return all donations."""
    return _scan_all(donations_table)


def get_inventory_from_donations():
    """
    Compute inventory per blood group by counting donations with
    status Scheduled or Completed. This mimics the previous
    MongoDB-based aggregation, but done in Python.
    """
    all_dons = get_all_donations()
    blood_groups = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
    inventory = {bg: 0 for bg in blood_groups}

    for d in all_dons:
        bg = d.get("blood_group")
        status = d.get("status")
        if bg in inventory and status in ("Scheduled", "Completed"):
            inventory[bg] += 1
    return inventory


# Helper to ensure users have blood_group populated based on donations
def enrich_users_with_blood_group(users):
    """
    DynamoDB variant of the previous helper.
    To keep this refactor minimal and avoid expensive per-user scans,
    we simply return users as-is. If you want to infer blood_group
    from latest donation, you can extend this function using
    get_user_donations(user_id) and an UpdateItem call.
    """
    return users
# -------------------- Routes --------------------

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        account_type = request.form.get('account_type')  # '' or 'bloodbank'
        hashed_password = generate_password_hash(request.form['password'])

        # Generate a stable string ID for DynamoDB; we expose it to templates as _id
        user_id = str(uuid.uuid4())

        user_doc = {
            "user_id": user_id,
            "_id": user_id,  # keep legacy attribute name for templates
            "name": request.form["name"],
            "email": request.form["email"],
            "password": hashed_password,
            # no role stored at signup for normal users
            "blood_group": request.form.get("blood_group"),
        }

        # If account type is bloodbank, assign special role
        if account_type == "bloodbank":
            user_doc["role"] = "bloodbank"

        # Persist user in DynamoDB
        put_user(user_doc)
        logger.info("New user signed up", extra={"email": user_doc["email"], "role": user_doc.get("role")})

        flash("Registration successful!")
        return redirect(url_for("login"))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = get_user_by_email(request.form["email"])

        if user and check_password_hash(user["password"], request.form["password"]):
            # Normalise ID fields for backwards compatibility
            uid = user.get("user_id") or user.get("_id")
            session["user_id"] = uid
            session["name"] = user["name"]
            session["user_email"] = user.get("email")
            # Preserve any special roles (admin / bloodbank) if they exist
            session["role"] = user.get("role")

            logger.info(
                "User logged in",
                extra={"user_id": uid, "email": user.get("email"), "role": user.get("role")},
            )

            # Normal users: go to role selection page
            if user.get("role") in ["admin", "bloodbank"]:
                return redirect(url_for("dashboard"))
            else:
                return redirect(url_for("choose_role"))

        flash("Invalid email or password")

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    # Always fetch the latest user document from DynamoDB
    user = get_user_by_id(user_id)
    if not user:
        session.clear()
        return redirect(url_for('login'))

    role = user.get("role")  # only used for special accounts (admin / bloodbank)
    current_role = user.get("current_role") or session.get("current_role")
    logger.info(
        "Dashboard accessed",
        extra={"user_id": user_id, "role": role, "current_role": current_role},
    )

    # -------- Normal user flows: donor / recipient via current_role --------
    if role not in ['admin', 'bloodbank']:
        if current_role == 'donor':
            # Fetch all donations for this user, sorted by date (newest first)
            user_donations = get_user_donations(user_id)
            session['current_role'] = 'donor'
            return render_template('donor_dashboard.html', donations=user_donations)

        if current_role == 'recipient':
            # Fetch this user's blood requests
            user_requests = get_user_requests(user_id)

            # Calculate inventory for availability check
            inventory = get_inventory_from_donations()

            # Add availability info to each request
            requests_with_availability = []
            for req in user_requests:
                requested_bg = req.get('blood_group', '') or ''

                # Safely convert units to int
                try:
                    units_value = req.get('units', 0)
                    if isinstance(units_value, str):
                        requested_units = int(units_value) if units_value.isdigit() else 0
                    else:
                        requested_units = int(units_value) if units_value else 0
                except (ValueError, TypeError):
                    requested_units = 0

                available_units = inventory.get(requested_bg, 0)

                # Format timestamp safely
                timestamp_raw = req.get('timestamp')
                if timestamp_raw:
                    # We store timestamp as ISO string in DynamoDB
                    timestamp_str = str(timestamp_raw)[:10] if len(str(timestamp_raw)) >= 10 else 'N/A'
                else:
                    timestamp_str = 'N/A'

                req_dict = {
                    '_id': str(req.get('_id', '')),
                    'patient_name': req.get('patient_name', 'N/A'),
                    'blood_group': requested_bg,
                    'units': requested_units,
                    'hospital': req.get('hospital', 'N/A'),
                    'status': req.get('status', 'pending'),
                    'timestamp': timestamp_str,
                    'timestamp_obj': timestamp_raw,  # Keep original for sorting if needed
                    'available_units': available_units,
                    'is_available': available_units >= requested_units if requested_units > 0 else False
                }
                requests_with_availability.append(req_dict)

            session['current_role'] = 'recipient'
            return render_template(
                'recipient_dashboard.html',
                requests=requests_with_availability,
                inventory=inventory
            )

        # If no current_role chosen yet, send user to role-selection
        return redirect(url_for('choose_role'))

    # -------- Blood bank & admin flows (special accounts) --------
    if role == 'bloodbank':
        # Fetch latest 5 donors from donations table
        all_donations = get_all_donations()
        recent_donors_list = sorted(
            all_donations,
            key=lambda d: d.get("date") or "",
            reverse=True
        )[:5]
        
        # Format donors data for template
        formatted_donors = []
        for d in recent_donors_list:
            formatted_donors.append({
                'name': d.get('donor_name', 'Unknown'),
                'blood_group': d.get('blood_group', 'N/A'),
                'last_donation': d.get('date', 'N/A')
            })

        # Calculate inventory from donations
        inventory_counts = get_inventory_from_donations()
        inventory = []
        total_units = 0

        for bg, units in inventory_counts.items():
            total_units += units
            inventory.append({"group": bg, "units": units})

        # Get today's date string for filtering
        today_str = datetime.now().strftime("%Y-%m-%d")
        today_donations = sum(
            1 for d in all_donations if (d.get("date") or "") == today_str
        )
        
        # Get recent requests
        recent_requests = get_pending_requests()[:10]

        donors_count = len({d.get("donor_id") for d in all_donations if d.get("donor_id")})

        stats = {
            'total_donors': donors_count,
            'pending_requests': len([r for r in get_all_requests() if r.get('status') == 'pending']),
            'total_units': total_units,
            'today_donations': today_donations
        }

        return render_template(
            'bloodbank_dashboard.html',
            stats=stats,
            donors=formatted_donors,
            inventory=inventory,
            requests=recent_requests,
            today=datetime.now().strftime("%d %b %Y")
        )

    else:  # admin
        users = _scan_all(users_table)
        users = enrich_users_with_blood_group(users)
        blood_requests = sorted(
            get_all_requests(),
            key=lambda r: r.get("timestamp") or "",
            reverse=True,
        )
        all_donations = sorted(
            get_all_donations(),
            key=lambda d: d.get("date") or "",
            reverse=True,
        )

        # Calculate inventory
        inventory_counts = get_inventory_from_donations()
        inventory = []
        total_inventory_units = 0

        for bg, units in inventory_counts.items():
            total_inventory_units += units
            inventory.append({"group": bg, "units": units})

        # Calculate today's donations
        today_str = datetime.now().strftime("%Y-%m-%d")
        today_donations_count = sum(
            1 for d in all_donations if (d.get("date") or "") == today_str
        )
        
        # Pending requests count
        pending_requests_count = len(
            [r for r in blood_requests if r.get("status") == "pending"]
        )
        completed_requests_count = len(
            [r for r in blood_requests if r.get("status") == "fulfilled"]
        )

        donors_count = len({d.get("donor_id") for d in all_donations if d.get("donor_id")})
        recipients_count = len({r.get("requester_id") for r in blood_requests if r.get("requester_id")})

        stats = {
            'total_users': len(users),
            'donors_count': donors_count,
            'recipients_count': recipients_count,
            'banks_count': len([u for u in users if u.get('role') == 'bloodbank']),
            'total_requests': len(blood_requests),
            'pending_requests': pending_requests_count,
            'completed_requests': completed_requests_count,
            'total_donations': len(all_donations),
            'today_donations': today_donations_count,
            'total_inventory': total_inventory_units
        }

        return render_template('admin_dashboard.html', 
                             users=users, 
                             requests=blood_requests, 
                             donations=all_donations[:10],  # Latest 10 donations
                             inventory=inventory,
                             stats=stats)


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access!")
        return redirect(url_for('login'))

    all_users = _scan_all(users_table)
    all_users = enrich_users_with_blood_group(all_users)
    all_requests = sorted(
        get_all_requests(),
        key=lambda r: r.get("timestamp") or "",
        reverse=True,
    )
    all_donations = sorted(
        get_all_donations(),
        key=lambda d: d.get("date") or "",
        reverse=True,
    )

    # Calculate inventory
    inventory_counts = get_inventory_from_donations()
    inventory = []
    total_inventory_units = 0

    for bg, units in inventory_counts.items():
        total_inventory_units += units
        inventory.append({"group": bg, "units": units})

    # Calculate today's donations
    today_str = datetime.now().strftime("%Y-%m-%d")
    today_donations_count = sum(
        1 for d in all_donations if (d.get("date") or "") == today_str
    )
    
    # Pending requests count
    pending_requests_count = len(
        [r for r in all_requests if r.get("status") == "pending"]
    )
    completed_requests_count = len(
        [r for r in all_requests if r.get("status") == "fulfilled"]
    )

    donors_count = len({d.get("donor_id") for d in all_donations if d.get("donor_id")})
    recipients_count = len({r.get("requester_id") for r in all_requests if r.get("requester_id")})

    dashboard_stats = {
        'total_users': len(all_users),
        'donors_count': donors_count,
        'recipients_count': recipients_count,
        'banks_count': len([u for u in all_users if u.get('role') == 'bloodbank']),
        'total_requests': len(all_requests),
        'pending_requests': pending_requests_count,
        'completed_requests': completed_requests_count,
        'total_donations': len(all_donations),
        'today_donations': today_donations_count,
        'total_inventory': total_inventory_units
    }

    return render_template(
        'admin_dashboard.html',
        users=all_users,
        requests=all_requests,
        donations=all_donations[:10],  # Latest 10 donations
        inventory=inventory,
        stats=dashboard_stats
    )


@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('role') == 'admin':
        delete_user_by_id(user_id)
        logger.info("User deleted by admin", extra={"deleted_user_id": user_id, "admin_id": session.get("user_id")})
        flash("User removed successfully.")
    return redirect(url_for('admin_dashboard'))


@app.route('/choose_role', methods=['GET', 'POST'])
def choose_role():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # Special accounts skip role selection
    if user.get('role') in ['admin', 'bloodbank']:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        role_choice = request.form.get('role_choice')
        if role_choice not in ['donor', 'recipient']:
            flash('Please choose how you want to use BloodBridge.')
            return redirect(url_for('choose_role'))

        # AWS PERMISSION REQUIRED: dynamodb:UpdateItem on users table
        users_table.update_item(
            Key={"user_id": user.get("user_id") or user.get("_id")},
            UpdateExpression="SET current_role = :r",
            ExpressionAttributeValues={":r": role_choice},
        )
        session['current_role'] = role_choice
        return redirect(url_for('dashboard'))

    return render_template('choose_role.html')

@app.route('/request_blood')
def request_blood():
    if 'user_id' not in session:
        flash("Please login to request blood.")
        return redirect(url_for('login'))
    return render_template('request_blood.html')


@app.route('/submit_blood_request', methods=['POST'])
def submit_blood_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    request_id = str(uuid.uuid4())
    timestamp_iso = datetime.utcnow().isoformat()

    # Normalize units to integer where possible
    units_raw = request.form.get('units')
    try:
        units_value = int(units_raw) if units_raw is not None else 0
    except (TypeError, ValueError):
        units_value = 0

    new_request = {
        "request_id": request_id,
        "_id": request_id,  # legacy name for templates if needed
        "requester_id": session['user_id'],
        "patient_name": request.form.get('patient_name'),
        "blood_group": request.form.get('blood_group'),
        "units": units_value,
        "hospital": request.form.get('hospital'),
        "status": "pending",
        "timestamp": timestamp_iso,
    }

    # AWS PERMISSION REQUIRED: dynamodb:PutItem on requests table
    # Store request in DynamoDB
    requests_table.put_item(Item=new_request)

    # AWS PERMISSION REQUIRED: sns:Publish on SNS topic
    # Publish notification via SNS (topic configured by env var)
    # Uses EC2 IAM role credentials automatically
    if SNS_TOPIC_ARN:
        try:
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="New Blood Request Posted",
                Message=(
                    f"New blood request for patient {new_request['patient_name']} "
                    f"({new_request['blood_group']}, {new_request['units']} units) "
                    f"at {new_request['hospital']}."
                ),
            )
            logger.info(
                "SNS notification sent for blood request",
                extra={"request_id": request_id, "requester_id": session['user_id']},
            )
        except Exception as e:
            # Do not block the user flow if SNS fails; log the error instead.
            logger.error(
                "Failed to publish SNS notification for blood request",
                extra={"error": str(e), "request_id": request_id},
            )

    flash("Blood request has been posted successfully!")
    return redirect(url_for('dashboard'))


@app.route('/schedule_donation')
def schedule_donation():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('schedule_donation.html')
@app.route('/submit_donation_slot', methods=['POST'])
def submit_donation_slot():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Read blood group from form, fallback to None if not selected
    blood_group = request.form.get('blood_group')
    if not blood_group:
        flash("Please select a blood group!")
        return redirect(url_for('schedule_donation'))

    donation_id = str(uuid.uuid4())
    donation_data = {
        "donation_id": donation_id,
        "donor_id": session['user_id'],
        "donor_name": session['name'],
        "blood_group": blood_group,  # <-- use the form value
        "date": request.form.get('donation_date'),
        "location": request.form.get('location'),
        "time_slot": request.form.get('time_slot'),
        "status": "Scheduled",
    }

    # AWS PERMISSION REQUIRED: dynamodb:PutItem on donations table
    donations_table.put_item(Item=donation_data)
    # CloudWatch logging removed - using standard logger
    logger.info(
        "Donation slot scheduled",
        extra={"donation_id": donation_id, "donor_id": session['user_id'], "blood_group": blood_group},
    )
    flash("Success! Your donation slot has been scheduled.")
    return redirect(url_for('dashboard'))




@app.route('/view_requests')
def view_requests():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    from boto3.dynamodb.conditions import Attr

    # Show all pending requests to donors
    requests = _scan_all(requests_table, Attr("status").eq("pending"))
    return render_template('view_requests_for_donors.html', requests=requests)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        message_id = str(uuid.uuid4())
        contact_data = {
            "message_id": message_id,
            "name": request.form.get('name'),
            "email": request.form.get('email'),
            "subject": request.form.get('subject'),
            "message": request.form.get('message'),
            "timestamp": datetime.utcnow().isoformat(),
        }

        # AWS PERMISSION REQUIRED: dynamodb:PutItem on messages table
        messages_table.put_item(Item=contact_data)
        # CloudWatch logging removed - using standard logger
        logger.info("Contact message stored", extra={"message_id": message_id, "email": contact_data.get("email")})
        flash("Thank you! Your message has been sent successfully.")
        return redirect(url_for('contact'))

    return render_template('contact.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    # Bind to 0.0.0.0 so the app is reachable on EC2.
    # In production, disable debug and run behind a WSGI server like gunicorn.
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=bool(os.environ.get("FLASK_DEBUG", False)), use_reloader=False)
