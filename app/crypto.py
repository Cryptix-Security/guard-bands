import hmac
import hashlib
import secrets
import base64
import json
import re

class GuardBandCrypto:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key
    
    def generate_nonce(self) -> str:
        """Generate a random nonce"""
        return secrets.token_urlsafe(16)
    
    def hash_content(self, content: str) -> str:
        """SHA-256 hash of content"""
        h = hashlib.sha256(content.encode('utf-8')).digest()
        return base64.b64encode(h).decode('utf-8')
    
    def generate_mac(self, content: str, context: dict) -> str:
        """Generate HMAC for content + context"""
        # Combine content and context into message
        message = json.dumps({
            'content': content,
            'context': context
        }, sort_keys=True).encode('utf-8')
        
        h = hmac.new(self.secret_key, message, hashlib.sha256)
        return base64.b64encode(h.digest()).decode('utf-8')
    
    def verify_mac(self, content: str, context: dict, provided_mac: str) -> bool:
        """Verify HMAC matches"""
        expected_mac = self.generate_mac(content, context)
        return hmac.compare_digest(expected_mac, provided_mac)
    
    def wrap_content(self, content: str, context: dict, key_id: str = "key001") -> str:
        """Wrap content with guard bands"""
        nonce = self.generate_nonce()
        content_hash = self.hash_content(content)
        mac = self.generate_mac(content, context)
        
        wrapped = (
            f"⟪INERT:START:r:{nonce}:h:{content_hash}⟫\n"
            f"{content}\n"
            f"⟪INERT:END:mac:{mac}:kid:{key_id}⟫"
        )
        return wrapped
    
    def extract_and_verify(self, wrapped: str, context: dict) -> dict:
        """Extract content and verify guard bands"""
        try:
            # Parse guard bands using regex for more reliable extraction
            start_pattern = r'⟪INERT:START:(.+?)⟫\n'
            end_pattern = r'\n⟪INERT:END:(.+?)⟫'
            
            start_match = re.search(start_pattern, wrapped)
            end_match = re.search(end_pattern, wrapped)
            
            if not start_match:
                return {"valid": False, "error": "Missing start marker"}
            
            if not end_match:
                return {"valid": False, "error": "Missing end marker"}
            
            # Extract parameters
            start_params = start_match.group(1)
            end_params = end_match.group(1)
            
            # Extract content between markers
            content_start = start_match.end()
            content_end = end_match.start()
            content = wrapped[content_start:content_end]
            
            # Parse start parameters (format: r:nonce:h:hash)
            start_parts = start_params.split(':')
            start_dict = {}
            i = 0
            while i < len(start_parts) - 1:
                key = start_parts[i]
                value = start_parts[i + 1]
                start_dict[key] = value
                i += 2
            
            # Parse end parameters (format: mac:value:kid:value)
            end_parts = end_params.split(':')
            end_dict = {}
            i = 0
            while i < len(end_parts) - 1:
                key = end_parts[i]
                value = end_parts[i + 1]
                end_dict[key] = value
                i += 2
            
            # Verify hash
            expected_hash = self.hash_content(content)
            provided_hash = start_dict.get('h', '')
            
            if expected_hash != provided_hash:
                return {
                    "valid": False, 
                    "error": f"Content hash mismatch (expected: {expected_hash[:20]}..., got: {provided_hash[:20]}...)"
                }
            
            # Verify MAC
            provided_mac = end_dict.get('mac', '')
            if not self.verify_mac(content, context, provided_mac):
                return {"valid": False, "error": "MAC verification failed"}
            
            return {
                "valid": True,
                "content": content,
                "nonce": start_dict.get('r'),
                "key_id": end_dict.get('kid')
            }
            
        except Exception as e:
            return {"valid": False, "error": f"Parse error: {str(e)}"}
