from flask import Blueprint, request, jsonify, current_app
from services.ai_assistant_service import AIAssistantService
from services.device_security_service import DeviceSecurityService
from database.models import User
from database.connection import SessionLocal

api_bp = Blueprint('api', __name__, url_prefix='/api')

ai_service = AIAssistantService()
device_service = DeviceSecurityService()

def get_leaderboard_list(session):
    users = session.query(User).order_by(User.points.desc()).limit(10).all()
    return [{"username": u.username, "points": u.points} for u in users]

@api_bp.route('/register-user', methods=['POST'])
def register_user():
    data = request.json
    if not data or 'username' not in data:
        return jsonify({"error": "Missing username"}), 400
        
    username = data['username'].strip()
    if not username:
        return jsonify({"error": "Username cannot be empty"}), 400
        
    session = SessionLocal()
    try:
        user = session.query(User).filter_by(username=username).first()
        if not user:
            user = User(username=username, points=0, completed_quests="")
            session.add(user)
            session.commit()
            
        return jsonify({
            "username": user.username,
            "points": user.points,
            "completed_quests": user.completed_quests.split(",") if user.completed_quests else []
        })
    finally:
        session.close()

@api_bp.route('/complete-quest', methods=['POST'])
def complete_quest():
    data = request.json
    if not data or 'username' not in data or 'quest_id' not in data:
        return jsonify({"error": "Missing parameters"}), 400
        
    username = data['username']
    quest_id = data['quest_id']
    
    quest_points = {
        "quest_1": 10, # Shield (Password)
        "quest_2": 10, # Breach Detective (Email check)
        "quest_3": 20, # Scam Buster (AI scan)
        "quest_4": 10  # Secure WiFi (WiFi check)
    }
    
    if quest_id not in quest_points:
        return jsonify({"error": "Invalid quest ID"}), 400
        
    session = SessionLocal()
    try:
        user = session.query(User).filter_by(username=username).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        completed = user.completed_quests.split(",") if user.completed_quests else []
        if quest_id in completed:
            return jsonify({"status": "Already completed", "points": user.points})
            
        # Add to completed list
        completed.append(quest_id)
        user.completed_quests = ",".join(completed)
        user.points += quest_points[quest_id]
        session.commit()
        
        # Broadcast the updated leaderboard in real-time
        try:
            socketio = current_app.extensions['socketio']
            leaderboard_data = get_leaderboard_list(session)
            socketio.emit('leaderboard_update', leaderboard_data)
        except Exception as e:
            print(f"Failed to emit leaderboard update: {e}")
            
        return jsonify({
            "status": "Success",
            "added_points": quest_points[quest_id],
            "total_points": user.points,
            "completed_quests": completed
        })
    finally:
        session.close()

@api_bp.route('/leaderboard', methods=['GET'])
def leaderboard():
    session = SessionLocal()
    try:
        data = get_leaderboard_list(session)
        return jsonify(data)
    finally:
        session.close()

@api_bp.route('/analyze-text', methods=['POST'])
def analyze_text():
    data = request.json
    if not data or 'text' not in data:
        return jsonify({"error": "Missing text parameter"}), 400
    
    result = ai_service.analyze_text(data['text'])
    return jsonify(result)

@api_bp.route('/check-password', methods=['POST'])
def check_password():
    data = request.json
    if not data or 'password' not in data:
        return jsonify({"error": "Missing password parameter"}), 400
        
    result = device_service.check_password_strength(data['password'])
    return jsonify(result)
    
@api_bp.route('/check-breach', methods=['POST'])
def check_breach():
    data = request.json
    if not data or 'email' not in data:
        return jsonify({"error": "Missing email parameter"}), 400
        
    result = device_service.check_data_breach(data['email'])
    return jsonify(result)

@api_bp.route('/device-status', methods=['GET'])
def device_status():
    wifi_status = device_service.check_wifi_security()
    
    score = 100
    if not wifi_status.get('is_secure', True):
        score -= 30
        
    return jsonify({
        "wifi": wifi_status,
        "overall_score": score
    })
