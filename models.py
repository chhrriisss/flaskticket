from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    username = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    name = db.Column(db.String(100), nullable=False)
    can_assign = db.Column(db.Boolean, default=False)
    permissions = db.Column(db.Text)  # Store as JSON string

    
    def get_permissions(self):
        return json.loads(self.permissions) if self.permissions else {}
    
    def set_permissions(self, perms):
        self.permissions = json.dumps(perms)

class FieldConfig(db.Model):
    __tablename__ = 'field_configs'
    
    field_name = db.Column(db.String(100), primary_key=True)
    field_type = db.Column(db.String(50), nullable=False)
    label = db.Column(db.String(100), nullable=False)
    editable = db.Column(db.Boolean, default=True)
    options = db.Column(db.Text)  # Store as JSON string
    permissions = db.Column(db.Text)  # Store as JSON string
    
    def get_options(self):
        return json.loads(self.options) if self.options else []
    
    def set_options(self, opts):
        self.options = json.dumps(opts)
    
    def get_permissions(self):
        return json.loads(self.permissions) if self.permissions else {}
    
    def set_permissions(self, perms):
        self.permissions = json.dumps(perms)

class Package(db.Model):
    __tablename__ = 'packages'
    
    id = db.Column(db.String(50), primary_key=True)
    created_by = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_by = db.Column(db.String(50))
    updated_at = db.Column(db.DateTime)
    assigned_users = db.Column(db.Text)  # Store as JSON string
    gantt_columns = db.Column(db.Text)  # Store as JSON string
    data_timeline = db.Column(db.Text)  # Store as JSON string
    data = db.Column(db.Text)  # Store as JSON string (legacy)
    user_permissions = db.Column(db.Text) 
    
    def get_assigned_users(self):
        return json.loads(self.assigned_users) if self.assigned_users else []
    
    def set_assigned_users(self, users):
        self.assigned_users = json.dumps(users)
    
    def get_gantt_columns(self):
        return json.loads(self.gantt_columns) if self.gantt_columns else []
    
    def set_gantt_columns(self, cols):
        self.gantt_columns = json.dumps(cols)
    
    def get_data_timeline(self):
        return json.loads(self.data_timeline) if self.data_timeline else {}
    
    def set_data_timeline(self, timeline):
        self.data_timeline = json.dumps(timeline)
    
    def get_data(self):
        return json.loads(self.data) if self.data else {}
    
    def set_data(self, pkg_data):
        self.data = json.dumps(pkg_data)

    def get_user_permissions(self):
        return json.loads(self.user_permissions) if self.user_permissions else {}
    
    def set_user_permissions(self, perms):
        self.user_permissions = json.dumps(perms)