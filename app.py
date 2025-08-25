# Web Application Framework Entry Points (Layer: Entry 🚪)
from flask import Flask, request, render_template_string, jsonify
import sqlite3
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/api/user/search', methods=['POST'])
def search_users_api():
    """
    API endpoint for user search - Entry Point
    Expected vulnerability: SQL Injection via user_query parameter
    Attack path: Entry → Transport → Sink
    """
    try:
        user_query = request.form.get('user_query', '')
        logger.info(f"User search API called with query: {user_query}")
        
        # Transport layer: Pass to business logic
        results = process_user_search_request(user_query)
        
        return jsonify({
            'status': 'success',
            'results': results,
            'total': len(results)
        })
    except Exception as e:
        logger.error(f"Search API error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/user/<user_id>')
def admin_user_detail(user_id):
    """
    Admin user detail page - Entry Point with privilege escalation potential
    Expected vulnerability: SQL Injection via URL parameter
    Attack path: Entry → Security → Sink (with security bypass)
    """
    # Simulate admin authentication check (Security Layer)
    if not verify_admin_access(request.headers.get('Authorization', '')):
        return "Access Denied", 403
    
    # Transport to data layer
    user_info = get_user_details_for_admin(user_id)
    
    if user_info:
        # XSS vulnerability in template rendering
        template = '''
        <h2>User Details</h2>
        <p>ID: {{ user_id }}</p>
        <p>Name: {{ name }}</p>
        <p>Email: {{ email }}</p>
        <p>Role: {{ role }}</p>
        '''
        return render_template_string(template, **user_info)
    else:
        return "User not found", 404

@app.route('/public/profile')
def public_profile():
    """
    Public profile viewer - Entry Point
    Expected vulnerability: XSS via profile_name parameter
    Attack path: Entry → Transport → Sink
    """
    profile_name = request.args.get('profile_name', 'Anonymous')
    
    # Transport layer: Process profile request
    profile_data = load_public_profile(profile_name)
    
    # Vulnerable template rendering (Sink)
    unsafe_template = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Profile: {profile_name}</title></head>
    <body>
        <h1>Welcome to {profile_name}'s Profile</h1>
        <div class="profile-content">
            {profile_data.get('content', 'No profile content available')}
        </div>
    </body>
    </html>
    '''
    
    return unsafe_template

@app.route('/api/comments/add', methods=['POST'])
def add_comment_api():
    """
    Comment addition API - Entry Point
    Expected vulnerability: Stored XSS + SQL Injection
    Attack path: Entry → Transport → Security → Sink (complex path)
    """
    comment_text = request.json.get('comment', '')
    user_id = request.json.get('user_id', 0)
    post_id = request.json.get('post_id', 0)
    
    logger.info(f"Adding comment from user {user_id} to post {post_id}")
    
    # Transport layer: Validate and process
    processed_comment = process_comment_submission(comment_text, user_id, post_id)
    
    if processed_comment:
        return jsonify({'status': 'success', 'comment_id': processed_comment['id']})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to add comment'}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)