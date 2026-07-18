import re
try:
    import pytesseract
    from PIL import Image
    HAS_OCR = True
except ImportError:
    HAS_OCR = False

class AIAssistantService:
    def __init__(self):
        # Heuristics for common scams
        self.scam_keywords = {
            'job': ['pay to work', 'western union', 'no experience required', 'guaranteed income', 'wire transfer', 'money laundering', 'cash checking'],
            'upi': ['scan to receive', 'pin to receive', 'refund processing', 'claim reward', 'lucky draw', 'lottery winner'],
            'phishing': ['verify your account', 'account suspended', 'unauthorized login', 'update billing', 'password expired']
        }
        
    def analyze_text(self, text):
        """Analyzes text for phishing, scams, and dangerous URLs."""
        text = text.lower()
        score = 0
        detected_categories = []
        explanation = []
        
        # Check Job Scams
        job_matches = [kw for kw in self.scam_keywords['job'] if kw in text]
        if job_matches:
            score += 40
            detected_categories.append("Job/Internship Scam")
            explanation.append(f"Contains job scam red flags: {', '.join(job_matches)}.")
            
        # Check UPI Scams
        upi_matches = [kw for kw in self.scam_keywords['upi'] if kw in text]
        if upi_matches:
            score += 50
            detected_categories.append("UPI/Payment Scam")
            explanation.append(f"Contains payment scam red flags (never enter a PIN to RECEIVE money): {', '.join(upi_matches)}.")
            
        # Check Phishing
        phishing_matches = [kw for kw in self.scam_keywords['phishing'] if kw in text]
        if phishing_matches:
            score += 40
            detected_categories.append("Phishing Attempt")
            explanation.append(f"Contains phishing urgency keywords: {', '.join(phishing_matches)}.")
            
        # Check URLs
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        if urls:
            explanation.append(f"Contains links: {', '.join(urls)}. Do not click unless you requested them.")
            for url in urls:
                if "bit.ly" in url or "tinyurl" in url:
                    score += 20
                    explanation.append("Uses a URL shortener which is common in SMS phishing (Smishing).")
                    
        # Determine overall safety
        is_scam = score >= 50
        confidence = min(score, 99)
        
        if score == 0:
            return {
                "is_scam": False,
                "confidence": 0,
                "categories": [],
                "summary": "This message looks safe, but always remain cautious if you don't know the sender."
            }
            
        return {
            "is_scam": is_scam,
            "confidence": confidence,
            "categories": detected_categories,
            "summary": " ".join(explanation) + (" HIGH LIKELIHOOD OF SCAM." if is_scam else " Proceed with caution.")
        }
        
    def analyze_image(self, image_path):
        """Extracts text from a chat screenshot and analyzes it."""
        if not HAS_OCR:
            return {"error": "OCR is not installed. Please install Tesseract-OCR and pytesseract."}
            
        try:
            img = Image.open(image_path)
            text = pytesseract.image_to_string(img)
            return self.analyze_text(text)
        except Exception as e:
            return {"error": f"Failed to process image: {str(e)}"}
