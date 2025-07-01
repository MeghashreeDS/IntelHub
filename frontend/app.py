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

import stat

app = Flask(__name__)
# Add at the top of your Flask app
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}}, supports_credentials=True)

# Setup MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['project_manager']
users_collection = db['users']
projects_collection = db['projects']
merge_requests_collection = db['merge_requests']

# JWT Config
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this in production!
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
        project = projects_collection.find_one({
            '_id': ObjectId(project_id)
        })
        
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        
        # Check if user has access to this project
        if project['user_id'] != current_user_id and not project['isPublic']:
            return jsonify({'message': 'Access denied'}), 403
        
        # Add user info to project
        user = users_collection.find_one({'_id': ObjectId(project['user_id'])})
        if user:
            project['user'] = {
                '_id': str(user['_id']),
                'name': user['name'],
                'email': user['email']
            }
        
        project = serialize_id(project)
        
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











@app.route('/api/projects/<project_id>/upload', methods=['POST'])
@jwt_required()
def upload_files(project_id):
    current_user_id = get_jwt_identity()
    
    try:
        # Verify project ownership
        project = projects_collection.find_one({
            '_id': ObjectId(project_id),
            'user_id': current_user_id
        })
        
        if not project:
            return jsonify({'message': 'Project not found or access denied'}), 404

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
            '_id': ObjectId(project_id),
            'user_id': current_user_id
        })
        
        if not project:
            return jsonify({'message': 'Project not found or access denied'}), 404

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
        merge_result = repo.merge(source_branch.target)
        
        if merge_result == pygit2.GIT_MERGE_ANALYSIS_FASTFORWARD:
            # Fast-forward merge
            target_ref = f'refs/heads/{target_branch_name}'
            repo.references.set_target(target_ref, source_branch.target)
            repo.state_cleanup()
            
            # Update merge request status
            merge_requests_collection.update_one(
                {'_id': ObjectId(request_id)},
                {'$set': {'status': 'approved'}}
            )
            
            return jsonify({'message': 'Merge request approved and merged successfully'}), 200
            
        elif merge_result & pygit2.GIT_MERGE_ANALYSIS_NORMAL:
            # Regular merge needed
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
            
        else:
            # Can't be merged automatically
            repo.state_cleanup()
            return jsonify({'message': 'Cannot merge automatically, conflicts detected'}), 409
        
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















# Run the server
if __name__ == '__main__':
    app.run(debug=True, port=5000)