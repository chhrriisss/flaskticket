from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import json
import os
from datetime import datetime
from functools import wraps
from models import db, User, FieldConfig, Package

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your-secret-key-change-this'
db.init_app(app)

# ============= DATABASE HELPER FUNCTIONS =============

def get_all_users():
    """Get all users from database"""
    users = User.query.all()
    return {u.username: {
        'password': u.password,
        'role': u.role,
        'name': u.name,
        'can_assign': u.can_assign,
        'permissions': u.get_permissions()
    } for u in users}

def get_user_by_username(username):
    """Get single user from database"""
    user = db.session.get(User, username)
    if user:
        return {
            'password': user.password,
            'role': user.role,
            'name': user.name,
            'can_assign': user.can_assign,
            'permissions': user.get_permissions()
        }
    return None

def get_all_field_configs():
    """Get all field configs from database"""
    fields = FieldConfig.query.all()
    return {f.field_name: {
        'type': f.field_type,
        'label': f.label,
        'editable': f.editable,
        'options': f.get_options(),
        'permissions': f.get_permissions()
    } for f in fields}

def get_all_packages():
    """Get all packages from database"""
    packages = Package.query.all()
    return {p.id: {
        'id': p.id,
        'created_by': p.created_by,
        'created_at': p.created_at.isoformat() if p.created_at else None,
        'updated_by': p.updated_by,
        'updated_at': p.updated_at.isoformat() if p.updated_at else None,
        'assigned_users': p.get_assigned_users(),
        'gantt_columns': p.get_gantt_columns(),
        'data_timeline': p.get_data_timeline(),
        'data': p.get_data()
    } for p in packages}

def init_default_data():
    """Initialize default data in database"""
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        if not db.session.get(User, 'admin'):
            admin = User(
                username='admin',
                password='admin123',
                role='admin',
                name='Administrator',
                can_assign=True
            )
            admin.set_permissions({
                'package_create': True,
                'package_read': True,
                'package_update': True,
                'package_delete': True
            })
            db.session.add(admin)
        
        # Create default user if not exists
        if not db.session.get(User, 'user1'):
            user1 = User(
                username='user1',
                password='user123',
                role='user',
                name='User One',
                can_assign=False
            )
            user1.set_permissions({
                'package_create': False,
                'package_read': True,
                'package_update': True,
                'package_delete': False
            })
            db.session.add(user1)
        
        db.session.commit()
        print("Default data initialized in database")

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        user = db.session.get(User, session['username'])
        if not user or user.role != 'admin':
            flash('Admin access required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def permission_required(permission_name):
    """Decorator to check if user has specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            
            user = db.session.get(User, session['username'])
            if not user:
                return redirect(url_for('login'))
            
            # Admin always has all permissions
            if user.role == 'admin':
                return f(*args, **kwargs)
            
            # Check specific permission
            permissions = user.get_permissions()
            if not permissions.get(permission_name, False):
                flash(f'Permission denied: You cannot {permission_name.replace("_", " ")}')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.context_processor
def inject_fresh_permissions():
    """Inject fresh permissions and field access checker into all templates"""
    if 'username' in session:
        user = db.session.get(User, session['username'])
        if not user:
            return {'fresh_role': None, 'fresh_permissions': {}, 'can_access_field': lambda f, a: False}
        
        user_role = user.role
        config = {'fields': get_all_field_configs()}
        
        def can_access_field(field_name, action='read'):
            """Check if current user can perform action on field"""
            if user_role == 'admin':
                return True
            
            field_config = config['fields'].get(field_name, {})
            field_permissions = field_config.get('permissions', {})
            role_permissions = field_permissions.get(user_role, {})
            
            return role_permissions.get(action, False)
        
        return {
            'fresh_role': user_role,
            'fresh_permissions': user.get_permissions(),
            'can_access_field': can_access_field
        }
    return {
        'fresh_role': None,
        'fresh_permissions': {},
        'can_access_field': lambda f, a: False
    }

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = db.session.get(User, username)
        
        if user and user.password == password:
            session['username'] = username
            session['role'] = user.role
            session['name'] = user.name
            session['can_assign'] = user.can_assign
            session['permissions'] = user.get_permissions()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    packages = get_all_packages()
    config = {'fields': get_all_field_configs()}
    
    # Filter packages based on user assignments
    if session['role'] != 'admin':
        user_packages = {}
        for pkg_id, pkg_data in packages.items():
            if session['username'] in pkg_data.get('assigned_users', []):
                user_packages[pkg_id] = pkg_data
        packages = user_packages
    
    return render_template('dashboard.html', packages=packages, config=config)

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html')

@app.route('/admin/users')
@admin_required
def admin_users():
    users = get_all_users()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/create', methods=['POST'])
@admin_required
def create_user():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    name = request.form['name']
    can_assign = 'can_assign' in request.form
    
    if db.session.get(User, username):
        flash('Username already exists')
    else:
        user = User(
            username=username,
            password=password,
            role=role,
            name=name,
            can_assign=can_assign
        )
        user.set_permissions({
            'package_create': False,
            'package_read': True,
            'package_update': True,
            'package_delete': False
        })
        db.session.add(user)
        db.session.commit()
        flash('User created successfully')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/edit/<username>', methods=['GET', 'POST'])
@admin_required
def edit_user(username):
    user = db.session.get(User, username)
    
    if not user:
        flash('User not found')
        return redirect(url_for('admin_users'))
    
    if request.method == 'POST':
        # Don't allow changing admin username
        if username == 'admin' and request.form['username'] != 'admin':
            flash('Cannot change admin username')
            return redirect(url_for('edit_user', username=username))
        
        new_username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        name = request.form['name']
        can_assign = 'can_assign' in request.form
        
        # If username changed, create new user and delete old
        if new_username != username:
            if db.session.get(User, new_username):
                flash('Username already exists')
                return redirect(url_for('edit_user', username=username))
            
            # Create new user with same data
            new_user = User(
                username=new_username,
                password=password,
                role=role,
                name=name,
                can_assign=can_assign
            )
            new_user.set_permissions(user.get_permissions())
            db.session.add(new_user)
            db.session.delete(user)
        else:
            # Update existing user
            user.password = password
            user.role = role
            user.name = name
            user.can_assign = can_assign
        
        db.session.commit()
        flash('User updated successfully')
        return redirect(url_for('admin_users'))
    
    user_data = {
        'password': user.password,
        'role': user.role,
        'name': user.name,
        'can_assign': user.can_assign,
        'permissions': user.get_permissions()
    }
    return render_template('edit_user.html', username=username, user_data=user_data)

@app.route('/admin/users/delete/<username>')
@admin_required
def delete_user(username):
    if username == 'admin':
        flash('Cannot delete admin user')
    else:
        user = db.session.get(User, username)
        if user:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully')
        else:
            flash('User not found')
    return redirect(url_for('admin_users'))

@app.route('/admin/config')
@admin_required
def admin_config():
    config = {'fields': get_all_field_configs()}
    return render_template('admin_config.html', config=config)

@app.route('/admin/config/field/edit/<field_name>', methods=['GET', 'POST'])
@admin_required
def edit_field_config(field_name):
    field = db.session.get(FieldConfig, field_name)
    
    if not field:
        flash('Field not found')
        return redirect(url_for('admin_config'))
    
    if request.method == 'POST':
        new_field_name = request.form['field_name']
        field_type = request.form['field_type']
        field_label = request.form['field_label']
        options = request.form.get('options', '').split(',') if request.form.get('options') else []
        
        # If field name changed, create new and delete old
        if new_field_name != field_name:
            if db.session.get(FieldConfig, new_field_name):
                flash('Field name already exists')
                return redirect(url_for('edit_field_config', field_name=field_name))
            
            new_field = FieldConfig(
                field_name=new_field_name,
                field_type=field_type,
                label=field_label,
                editable=field.editable
            )
            new_field.set_options([opt.strip() for opt in options if opt.strip()])
            new_field.set_permissions(field.get_permissions())
            db.session.add(new_field)
            db.session.delete(field)
        else:
            field.field_type = field_type
            field.label = field_label
            field.set_options([opt.strip() for opt in options if opt.strip()])
        
        db.session.commit()
        flash('Field configuration updated successfully')
        return redirect(url_for('admin_config'))
    
    field_config = {
        'type': field.field_type,
        'label': field.label,
        'editable': field.editable,
        'options': field.get_options(),
        'permissions': field.get_permissions()
    }
    return render_template('edit_field.html', field_name=field_name, field_config=field_config)

@app.route('/admin/config/field', methods=['POST'])
@admin_required
def update_field_config():
    field_name = request.form['field_name']
    field_type = request.form['field_type']
    field_label = request.form['field_label']
    editable = 'editable' in request.form
    options = request.form.get('options', '').split(',') if request.form.get('options') else []
    
    if db.session.get(FieldConfig, field_name):
        flash('Field already exists')
        return redirect(url_for('admin_config'))
    
    field = FieldConfig(
        field_name=field_name,
        field_type=field_type,
        label=field_label,
        editable=editable
    )
    field.set_options([opt.strip() for opt in options if opt.strip()])
    
    # Set default permissions for all roles
    users = User.query.all()
    roles = set(u.role for u in users)
    default_perms = {}
    for role in roles:
        if role == 'admin':
            default_perms[role] = {'read': True, 'write': True, 'delete': True}
        else:
            default_perms[role] = {'read': True, 'write': editable, 'delete': False}
    field.set_permissions(default_perms)
    
    db.session.add(field)
    db.session.commit()
    flash('Field configuration updated')
    return redirect(url_for('admin_config'))

@app.route('/admin/config/field/delete/<field_name>')
@admin_required
def delete_field_config(field_name):
    field = db.session.get(FieldConfig, field_name)
    if field:
        db.session.delete(field)
        db.session.commit()
        flash('Field deleted successfully')
    return redirect(url_for('admin_config'))

@app.route('/packages/create', methods=['GET', 'POST'])
@login_required
@permission_required('package_create')
def create_package():
    if request.method == 'POST':
        config = {'fields': get_all_field_configs()}
        
        # Generate package ID
        pkg_count = Package.query.count()
        package_id = f"PKG_{pkg_count + 1:04d}"
        
        # Get assigned users
        assigned_users = request.form.getlist('assigned_users')
        
        # Build package data with initial column
        initial_column_date = datetime.now().strftime('%Y-%m-%d')
        
        data_timeline = {initial_column_date: {}}
        
        # Add field data for initial column
        for field_name, field_config in config['fields'].items():
            if field_config['type'] == 'multiselect':
                data_timeline[initial_column_date][field_name] = request.form.getlist(field_name)
            else:
                data_timeline[initial_column_date][field_name] = request.form.get(field_name, '')
        
        package = Package(
            id=package_id,
            created_by=session['username'],
            created_at=datetime.now()
        )
        package.set_assigned_users(assigned_users)
        package.set_gantt_columns([initial_column_date])
        package.set_data_timeline(data_timeline)
        package.set_data(data_timeline[initial_column_date])
        
        db.session.add(package)
        db.session.commit()
        flash('Package created successfully')
        return redirect(url_for('dashboard'))
    
    config = {'fields': get_all_field_configs()}
    users = get_all_users()
    return render_template('create_package.html', config=config, users=users)

@app.route('/packages/<package_id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('package_update')
def edit_package(package_id):
    package = db.session.get(Package, package_id)
    
    if not package:
        flash('Package not found')
        return redirect(url_for('dashboard'))
    
    user = db.session.get(User, session['username'])
    user_role = user.role
    
    # Check if user can access this package
    if user_role != 'admin' and session['username'] not in package.get_assigned_users():
        flash('Access denied: Package not assigned to you')
        return redirect(url_for('dashboard'))
    
    config = {'fields': get_all_field_configs()}
    
    # Initialize gantt structure if not exists (for legacy packages)
    gantt_columns = package.get_gantt_columns()
    data_timeline = package.get_data_timeline()
    
    if not gantt_columns:
        initial_date = datetime.now().strftime('%Y-%m-%d')
        gantt_columns = [initial_date]
        data_timeline = {initial_date: package.get_data()}
        package.set_gantt_columns(gantt_columns)
        package.set_data_timeline(data_timeline)
    
    if request.method == 'POST':
        action = request.form.get('action', 'update')
        
        if action == 'add_column':
            # Add new column
            new_date = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            gantt_columns.append(new_date)
            
            # Initialize new column data
            data_timeline[new_date] = {}
            
            # Copy from latest column
            latest_column = gantt_columns[-2] if len(gantt_columns) > 1 else gantt_columns[0]
            latest_data = data_timeline[latest_column]
            
            for field_name, field_config in config['fields'].items():
                field_permissions = field_config.get('permissions', {})
                role_permissions = field_permissions.get(user_role, {})
                can_read = user_role == 'admin' or role_permissions.get('read', False)
                
                if not can_read:
                    continue
                
                can_write = user_role == 'admin' or role_permissions.get('write', False)
                
                if not can_write:
                    data_timeline[new_date][field_name] = latest_data.get(field_name, '')
                else:
                    if field_config['type'] == 'multiselect':
                        data_timeline[new_date][field_name] = []
                    else:
                        data_timeline[new_date][field_name] = ''
        else:
            # Update existing columns
            for column_date in gantt_columns:
                for field_name, field_config in config['fields'].items():
                    field_permissions = field_config.get('permissions', {})
                    role_permissions = field_permissions.get(user_role, {})
                    can_write = user_role == 'admin' or role_permissions.get('write', False)
                    
                    if can_write:
                        form_field = f"{field_name}_{column_date}"
                        if field_config['type'] == 'multiselect':
                            data_timeline[column_date][field_name] = request.form.getlist(form_field)
                        else:
                            data_timeline[column_date][field_name] = request.form.get(form_field, '')
            
            # Admin can update assigned users
            if user_role == 'admin':
                package.set_assigned_users(request.form.getlist('assigned_users'))
        
        # Update package
        package.set_gantt_columns(gantt_columns)
        package.set_data_timeline(data_timeline)
        
        # Update legacy data field with latest column data
        if gantt_columns:
            latest_column = gantt_columns[-1]
            package.set_data(data_timeline[latest_column])
        
        package.updated_at = datetime.now()
        package.updated_by = session['username']
        
        db.session.commit()
        
        if action == 'add_column':
            flash('New column added successfully')
        else:
            flash('Package updated successfully')
        
        return redirect(url_for('edit_package', package_id=package_id))
    
    # Prepare package data for template
    package_data = {
        'id': package.id,
        'created_by': package.created_by,
        'created_at': package.created_at.isoformat() if package.created_at else None,
        'updated_by': package.updated_by,
        'updated_at': package.updated_at.isoformat() if package.updated_at else None,
        'assigned_users': package.get_assigned_users(),
        'gantt_columns': gantt_columns,
        'data_timeline': data_timeline,
        'data': package.get_data()
    }
    
    users = get_all_users()
    return render_template('edit_package.html', package=package_data, config=config, users=users)

@app.route('/packages/<package_id>/delete_column/<column_date>')
@login_required
def delete_column(package_id, column_date):
    package = db.session.get(Package, package_id)
    
    if not package:
        flash('Package not found')
        return redirect(url_for('dashboard'))
    
    user = db.session.get(User, session['username'])
    user_role = user.role
    
    # Check package-level access
    if user_role != 'admin' and session['username'] not in package.get_assigned_users():
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    config = {'fields': get_all_field_configs()}
    
    # Check if user has delete permission for ALL fields
    if user_role != 'admin':
        can_delete_column = True
        for field_name, field_config in config['fields'].items():
            field_permissions = field_config.get('permissions', {})
            role_permissions = field_permissions.get(user_role, {})
            if not role_permissions.get('delete', False):
                can_delete_column = False
                break
        
        if not can_delete_column:
            flash('Permission denied: You cannot delete columns')
            return redirect(url_for('edit_package', package_id=package_id))
    
    gantt_columns = package.get_gantt_columns()
    
    # Don't allow deleting if only one column
    if len(gantt_columns) <= 1:
        flash('Cannot delete the last column')
        return redirect(url_for('edit_package', package_id=package_id))
    
    # Remove column
    if column_date in gantt_columns:
        gantt_columns.remove(column_date)
        data_timeline = package.get_data_timeline()
        if column_date in data_timeline:
            del data_timeline[column_date]
        
        package.set_gantt_columns(gantt_columns)
        package.set_data_timeline(data_timeline)
        
        # Update legacy data with latest column
        if gantt_columns:
            latest_column = gantt_columns[-1]
            package.set_data(data_timeline[latest_column])
        
        db.session.commit()
        flash('Column deleted successfully')
    
    return redirect(url_for('edit_package', package_id=package_id))

@app.route('/packages/<package_id>/delete')
@admin_required
@permission_required('package_create')
def delete_package(package_id):
    package = db.session.get(Package, package_id)
    if package:
        db.session.delete(package)
        db.session.commit()
        flash('Package deleted successfully')
    return redirect(url_for('dashboard'))

@app.route('/admin/permissions', methods=['GET', 'POST'])
@admin_required
def admin_permissions():
    users = User.query.all()
    
    if request.method == 'POST':
        # Update permissions for each user
        for user in users:
            if user.username != 'admin':
                user.set_permissions({
                    'package_create': f'create_{user.username}' in request.form,
                    'package_read': f'read_{user.username}' in request.form,
                    'package_update': f'update_{user.username}' in request.form,
                    'package_delete': f'delete_{user.username}' in request.form
                })
        
        db.session.commit()
        flash('Permissions updated successfully')
        return redirect(url_for('admin_permissions'))
    
    users_dict = get_all_users()
    return render_template('admin_permissions.html', users=users_dict)

@app.route('/admin/field-permissions/<field_name>', methods=['GET', 'POST'])
@admin_required
def admin_field_permissions(field_name):
    field = db.session.get(FieldConfig, field_name)
    
    if not field:
        flash('Field not found')
        return redirect(url_for('admin_config'))
    
    users = User.query.all()
    roles = sorted(set(u.role for u in users))
    
    if request.method == 'POST':
        permissions = {}
        for role in roles:
            permissions[role] = {
                'read': f'read_{role}' in request.form,
                'write': f'write_{role}' in request.form,
                'delete': f'delete_{role}' in request.form
            }
        
        field.set_permissions(permissions)
        db.session.commit()
        flash(f'Permissions updated for field: {field_name}')
        return redirect(url_for('admin_config'))
    
    field_config = {
        'type': field.field_type,
        'label': field.label,
        'editable': field.editable,
        'options': field.get_options(),
        'permissions': field.get_permissions()
    }
    current_permissions = field.get_permissions()
    
    return render_template('admin_field_permissions.html', 
                         field_name=field_name,
                         field_config=field_config,
                         roles=roles,
                         current_permissions=current_permissions)

if __name__ == '__main__':
    init_default_data()
    app.run(debug=True)