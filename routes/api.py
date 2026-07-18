from flask import Blueprint, request, jsonify
from services.ai_assistant_service import AIAssistantService
from services.device_security_service import DeviceSecurityService

api_bp = Blueprint('api', __name__, url_prefix='/api')

ai_service = AIAssistantService()
device_service = DeviceSecurityService()

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
    
    # Calculate a mock risk score based on wifi status for now
    score = 100
    if not wifi_status.get('is_secure', True):
        score -= 30
        
    return jsonify({
        "wifi": wifi_status,
        "overall_score": score
    })
