import hashlib
import datetime
import logging
import jwt
import base64
import pyfiglet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class IRISH:
    """
    IRISH - Integrated Repudiation Investigation & Security Handler
    Author: Jasraj Choudhary
    """
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Setup logging
        logging.basicConfig(
            filename='irish_security.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.print_banner()
        
    def print_banner(self):
        """Display the IRISH banner"""
        banner = pyfiglet.figlet_format("IRISH")
        print(banner)
        print("Integrated Repudiation Investigation & Security Handler")
        print("Author: Jasraj Choudhary")
        print("-" * 50)

    def generate_token(self, user_id, action):
        """Generate JWT token for user actions"""
        timestamp = datetime.datetime.utcnow()
        payload = {
            'user_id': user_id,
            'action': action,
            'timestamp': timestamp.isoformat(),
        }
        token = jwt.encode(payload, self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ), algorithm='RS256')
        
        logging.info(f"Token generated for user {user_id} - Action: {action}")
        return token

    def verify_token(self, token):
        """Verify JWT token authenticity"""
        try:
            payload = jwt.decode(token, self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ), algorithms=['RS256'])
            logging.info(f"Token verified successfully for user {payload['user_id']}")
            return True, payload
        except jwt.InvalidTokenError as e:
            logging.warning(f"Invalid token detected: {str(e)}")
            return False, None

    def sign_data(self, data):
        """Create digital signature for data"""
        signature = self.private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def verify_signature(self, data, signature):
        """Verify digital signature"""
        try:
            signature_bytes = base64.b64decode(signature)
            self.public_key.verify(
                signature_bytes,
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logging.info("Signature verified successfully")
            return True
        except InvalidSignature:
            logging.warning("Invalid signature detected")
            return False

    def log_action(self, user_id, action, data):
        """Log user actions with hash for integrity"""
        timestamp = datetime.datetime.utcnow()
        action_hash = hashlib.sha256(
            f"{user_id}{action}{data}{timestamp}".encode()
        ).hexdigest()
        
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'user_id': user_id,
            'action': action,
            'data': data,
            'hash': action_hash
        }
        
        logging.info(f"Action logged: {log_entry}")
        return action_hash

    def detect_replay_attack(self, token_history, new_token):
        """Detect and prevent replay attacks"""
        if new_token in token_history:
            logging.warning(f"Replay attack detected - Token: {new_token}")
            return True
        return False

    def monitor_activity(self, user_id):
        """Monitor user activity for suspicious patterns"""
        with open('irish_security.log', 'r') as log_file:
            user_actions = [line for line in log_file if str(user_id) in line]
            
        if len(user_actions) > 100:  # Threshold for suspicious activity
            logging.warning(f"Suspicious activity detected for user {user_id}")
            return True
        return False