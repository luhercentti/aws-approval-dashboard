# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import boto3
from botocore.exceptions import ClientError
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import uuid

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Only for the admin user
    is_approver = db.Column(db.Boolean, default=False)  # For approvers

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
class PendingChange(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # 'add' or 'delete'
    protocol = db.Column(db.String(10), nullable=False)
    from_port = db.Column(db.Integer, nullable=True)
    to_port = db.Column(db.Integer, nullable=True)
    cidr_ip = db.Column(db.String(20), nullable=False)
    description = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'
    
    user = db.relationship('User', backref=db.backref('changes', lazy=True))

# AWS session setup
def get_aws_client():
    try:
        ec2_client = boto3.client('ec2')
        return ec2_client
    except Exception as e:
        print(f"Error connecting to AWS: {str(e)}")
        return None

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def approver_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or (not user.is_approver and not user.is_admin):  # Allow approvers and admin
            flash('Approver or Admin privileges required', 'danger')
            return redirect(url_for('index'))
            
        return f(*args, **kwargs)
    return decorated_function

# Auth routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            session['is_approver'] = user.is_approver  # Store the approver flag
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Routes
@app.route('/')
@login_required
def index():
    """Main page that lists all security groups"""
    try:
        ec2_client = get_aws_client()
        if not ec2_client:
            flash("Could not connect to AWS", "danger")
            return render_template('error.html')
            
        response = ec2_client.describe_security_groups()
        security_groups = response['SecurityGroups']
        
        # Get pending changes count for each security group
        for sg in security_groups:
            sg['pending_changes'] = PendingChange.query.filter_by(
                group_id=sg['GroupId'], 
                status='pending'
            ).count()
            
        return render_template('index.html', security_groups=security_groups)
    except ClientError as e:
        flash(f"AWS Error: {str(e)}", "danger")
        return render_template('error.html')

@app.route('/security_group/<group_id>')
@login_required
def security_group_detail(group_id):
    """View detailed information about a specific security group"""
    try:
        ec2_client = get_aws_client()
        if not ec2_client:
            flash("Could not connect to AWS", "danger")
            return render_template('error.html')
            
        response = ec2_client.describe_security_groups(GroupIds=[group_id])
        security_group = response['SecurityGroups'][0]
        
        # Get pending changes for this security group
        pending_changes = PendingChange.query.filter_by(
            group_id=group_id,
            status='pending'
        ).all()
        
        return render_template(
            'security_group_detail.html', 
            security_group=security_group,
            pending_changes=pending_changes,
            is_admin=session.get('is_admin', False)
        )
    except ClientError as e:
        flash(f"AWS Error: {str(e)}", "danger")
        return render_template('error.html')

@app.route('/request_delete_rule', methods=['POST'])
@login_required
def request_delete_rule():
    """Request to delete a security group rule"""
    group_id = request.form.get('group_id')
    protocol = request.form.get('protocol')
    from_port = request.form.get('from_port')
    to_port = request.form.get('to_port')
    cidr_ip = request.form.get('cidr_ip')

    if from_port:
        from_port = int(from_port)
    if to_port:
        to_port = int(to_port)

    # Check if the current user is an admin
    user = User.query.get(session['user_id'])
    if user.is_admin:
        # Admin users can directly delete the rule
        try:
            ec2_client = get_aws_client()
            if not ec2_client:
                flash("Could not connect to AWS", "danger")
                return redirect(url_for('security_group_detail', group_id=group_id))

            ec2_client.revoke_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[
                    {
                        'IpProtocol': protocol,
                        'FromPort': from_port if protocol != '-1' else -1,
                        'ToPort': to_port if protocol != '-1' else -1,
                        'IpRanges': [{'CidrIp': cidr_ip}]
                    }
                ]
            )
            flash("Rule deleted successfully", "success")
        except ClientError as e:
            flash(f"AWS Error: {str(e)}", "danger")
    else:
        # Non-admin users create a pending change request
        change = PendingChange(
            id=str(uuid.uuid4()),
            user_id=session['user_id'],
            group_id=group_id,
            action='delete',
            protocol=protocol,
            from_port=from_port,
            to_port=to_port,
            cidr_ip=cidr_ip,
            status='pending'
        )
        db.session.add(change)
        db.session.commit()
        flash("Rule deletion request submitted for approval", "info")

    return redirect(url_for('security_group_detail', group_id=group_id))

@app.route('/request_add_rule', methods=['POST'])
@login_required
def request_add_rule():
    """Request to add a new security group rule"""
    group_id = request.form.get('group_id')
    protocol = request.form.get('protocol')
    from_port = int(request.form.get('from_port'))
    to_port = int(request.form.get('to_port'))
    cidr_ip = request.form.get('cidr_ip')
    description = request.form.get('description', '')

    # Check if the current user is an admin
    user = User.query.get(session['user_id'])
    if user.is_admin:
        # Admin users can directly apply the rule
        try:
            ec2_client = get_aws_client()
            if not ec2_client:
                flash("Could not connect to AWS", "danger")
                return redirect(url_for('security_group_detail', group_id=group_id))

            ec2_client.authorize_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[
                    {
                        'IpProtocol': protocol,
                        'FromPort': from_port if protocol != '-1' else -1,
                        'ToPort': to_port if protocol != '-1' else -1,
                        'IpRanges': [{'CidrIp': cidr_ip, 'Description': description or ''}]
                    }
                ]
            )
            flash("Rule added successfully", "success")
        except ClientError as e:
            flash(f"AWS Error: {str(e)}", "danger")
    else:
        # Non-admin users create a pending change request
        change = PendingChange(
            id=str(uuid.uuid4()),
            user_id=session['user_id'],
            group_id=group_id,
            action='add',
            protocol=protocol,
            from_port=from_port,
            to_port=to_port,
            cidr_ip=cidr_ip,
            description=description,
            status='pending'
        )
        db.session.add(change)
        db.session.commit()
        flash("Rule addition request submitted for approval", "info")

    return redirect(url_for('security_group_detail', group_id=group_id))

@app.route('/approve_change/<change_id>', methods=['POST'])
@approver_required
def approve_change(change_id):
    """Approve a pending change"""
    change = PendingChange.query.get_or_404(change_id)
    
    try:
        ec2_client = get_aws_client()
        if not ec2_client:
            flash("Could not connect to AWS", "danger")
            return redirect(url_for('security_group_detail', group_id=change.group_id))
        
        if change.action == 'add':
            # Add the rule
            ec2_client.authorize_security_group_ingress(
                GroupId=change.group_id,
                IpPermissions=[
                    {
                        'IpProtocol': change.protocol,
                        'FromPort': change.from_port if change.protocol != '-1' else -1,
                        'ToPort': change.to_port if change.protocol != '-1' else -1,
                        'IpRanges': [{'CidrIp': change.cidr_ip, 'Description': change.description or ''}]
                    }
                ]
            )
        elif change.action == 'delete':
            # Delete the rule
            ec2_client.revoke_security_group_ingress(
                GroupId=change.group_id,
                IpPermissions=[
                    {
                        'IpProtocol': change.protocol,
                        'FromPort': change.from_port if change.protocol != '-1' else -1,
                        'ToPort': change.to_port if change.protocol != '-1' else -1,
                        'IpRanges': [{'CidrIp': change.cidr_ip}]
                    }
                ]
            )
        
        # Update the change status
        change.status = 'approved'
        db.session.commit()
        
        flash("Change approved and applied successfully", "success")
    except ClientError as e:
        flash(f"AWS Error: {str(e)}", "danger")
    
    return redirect(url_for('security_group_detail', group_id=change.group_id))

@app.route('/reject_change/<change_id>', methods=['POST'])
@approver_required
def reject_change(change_id):
    """Reject a pending change"""
    change = PendingChange.query.get_or_404(change_id)
    
    # Update the change status
    change.status = 'rejected'
    db.session.commit()
    
    flash("Change rejected", "warning")
    return redirect(url_for('security_group_detail', group_id=change.group_id))

@app.route('/pending_changes')
@approver_required  # Use the new decorator
def pending_changes():
    """View all pending changes"""
    pending = PendingChange.query.filter_by(status='pending').all()
    return render_template('pending_changes.html', pending_changes=pending)

# User management routes
@app.route('/users')
@approver_required
def manage_users():
    """View and manage users (admin only)"""
    users = User.query.all()
    return render_template('users.html', users=users)


@app.route('/create_user', methods=['GET', 'POST'])
@approver_required
def create_user():
    """Create a new user (admin only)"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_approver = request.form.get('is_approver') == 'on'

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('create_user'))

        # Create the new user
        new_user = User(username=username, is_approver=is_approver)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash(f'User {username} created successfully', 'success')
        return redirect(url_for('manage_users'))

    return render_template('create_user.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@approver_required
def edit_user(user_id):
    """Edit an existing user (admin only)"""
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_approver = request.form.get('is_approver') == 'on'

        # Update user details
        user.username = username
        user.is_approver = is_approver
        if password:
            user.set_password(password)

        db.session.commit()
        flash(f'User {username} updated successfully', 'success')
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@approver_required
def delete_user(user_id):
    """Delete a user (admin only)"""
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted successfully', 'success')
    return redirect(url_for('manage_users'))

# Initialize the database and create admin user
@app.before_first_request
def initialize_db():
    db.create_all()
    
    # Check if admin user exists, if not create one
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', is_admin=True, is_approver=True)  # Admin is also an approver
        admin.set_password('admin123')
        db.session.add(admin)
        
        # Also create a regular user
        user = User(username='user', is_admin=False, is_approver=False)
        user.set_password('user123')
        db.session.add(user)
        
        db.session.commit()
        print("Default users created: admin/admin123 and user/user123")
        
if __name__ == '__main__':
    app.run(debug=True)