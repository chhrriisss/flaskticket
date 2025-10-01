from main import app
from models import db, User, FieldConfig, Package
import json
import os
from datetime import datetime

def parse_datetime(datetime_str):
    """Convert ISO datetime string to datetime object"""
    if not datetime_str:
        return None
    try:
        # Handle ISO format datetime strings
        return datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
    except:
        return None

def migrate_json_to_sqlite():
    """Migrate existing JSON data to SQLite database"""
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        print("Migrating users...")
        if os.path.exists('users.json'):
            with open('users.json', 'r') as f:
                users_data = json.load(f)
            
            for username, user_data in users_data.items():
                existing = db.session.get(User, username)  # Fixed: Use session.get()
                if not existing:
                    user = User(
                        username=username,
                        password=user_data['password'],
                        role=user_data['role'],
                        name=user_data['name'],
                        can_assign=user_data['can_assign']
                    )
                    user.set_permissions(user_data.get('permissions', {}))
                    db.session.add(user)
            
            db.session.commit()
            print(f"Migrated {len(users_data)} users")
        
        print("Migrating field configs...")
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                config_data = json.load(f)
            
            for field_name, field_config in config_data.get('fields', {}).items():
                existing = db.session.get(FieldConfig, field_name)  # Fixed: Use session.get()
                if not existing:
                    field = FieldConfig(
                        field_name=field_name,
                        field_type=field_config['type'],
                        label=field_config['label'],
                        editable=field_config.get('editable', True)
                    )
                    field.set_options(field_config.get('options', []))
                    field.set_permissions(field_config.get('permissions', {}))
                    db.session.add(field)
            
            db.session.commit()
            print(f"Migrated {len(config_data.get('fields', {}))} field configs")
        
        print("Migrating packages...")
        if os.path.exists('packages.json'):
            with open('packages.json', 'r') as f:
                packages_data = json.load(f)
            
            for pkg_id, pkg_data in packages_data.items():
                existing = db.session.get(Package, pkg_id)  # Fixed: Use session.get()
                if not existing:
                    package = Package(
                        id=pkg_id,
                        created_by=pkg_data['created_by'],
                        created_at=parse_datetime(pkg_data.get('created_at')),  # Fixed: Convert to datetime
                        updated_by=pkg_data.get('updated_by'),
                        updated_at=parse_datetime(pkg_data.get('updated_at'))  # Fixed: Convert to datetime
                    )
                    package.set_assigned_users(pkg_data.get('assigned_users', []))
                    package.set_gantt_columns(pkg_data.get('gantt_columns', []))
                    package.set_data_timeline(pkg_data.get('data_timeline', {}))
                    package.set_data(pkg_data.get('data', {}))
                    db.session.add(package)
            
            db.session.commit()
            print(f"Migrated {len(packages_data)} packages")
        
        print("Migration completed successfully!")
        
        # Backup JSON files
        for file in ['users.json', 'config.json', 'packages.json']:
            if os.path.exists(file):
                os.rename(file, f"{file}.backup")
        print("JSON files backed up with .backup extension")

if __name__ == '__main__':
    migrate_json_to_sqlite()