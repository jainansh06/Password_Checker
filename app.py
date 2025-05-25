from flask import Flask, render_template, request, jsonify, session
import hashlib
import requests
import re
import random
import string
import json
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'my_secret_key_123' 
password_history = []

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_password', methods=['POST'])
def check_password():
    password = request.form.get('password', '')
    
    if not password:
        return jsonify({'error': 'Please enter a password'})
    
    strength_score = calculate_strength(password)
    strength_level = get_strength_level(strength_score)
    
    requirements = check_requirements(password)
    
    return jsonify({
        'strength_score': strength_score,
        'strength_level': strength_level,
        'requirements': requirements,
        'length': len(password)
    })

def calculate_strength(password):
    score = 0
    
    if len(password) >= 8:
        score += 20
    if len(password) >= 12:
        score += 20
    if len(password) >= 16:
        score += 10
    if re.search(r'[A-Z]', password):
        score += 15
    if re.search(r'[a-z]', password):
        score += 15
    if re.search(r'[0-9]', password):
        score += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 10
    if '123' in password or 'abc' in password:
        score -= 10
    if 'password' in password.lower():
        score -= 20
    
    return min(100, max(0, score))

def get_strength_level(score):
    
    if score < 20:
        return 'Very Weak'
    elif score < 40:
        return 'Weak'
    elif score < 60:
        return 'Moderate'
    elif score < 80:
        return 'Strong'
    else:
        return 'Very Strong'

def check_requirements(password):
    requirements = []
    
    requirements.append({
        'text': 'At least 8 characters',
        'met': len(password) >= 8
    })
    
    requirements.append({
        'text': 'Contains uppercase letter',
        'met': bool(re.search(r'[A-Z]', password))
    })
    
    requirements.append({
        'text': 'Contains lowercase letter',
        'met': bool(re.search(r'[a-z]', password))
    })
    
    requirements.append({
        'text': 'Contains number',
        'met': bool(re.search(r'[0-9]', password))
    })
    
    requirements.append({
        'text': 'Contains special character',
        'met': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    })
    
    return requirements

@app.route('/check_breach', methods=['POST'])
def check_breach():
    password = request.form.get('password', '')
    
    if not password:
        return jsonify({'error': 'Please enter a password'})
    
    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        response = requests.get(url)
        
        if response.status_code != 200:
            return jsonify({'error': 'Could not check breaches'})
        
        breach_count = 0
        for line in response.text.split('\n'):
            if line.startswith(suffix):
                breach_count = int(line.split(':')[1])
                break
        
        if breach_count > 0:
            return jsonify({
                'breached': True,
                'count': breach_count,
                'message': f'This password has been found in {breach_count} data breaches!'
            })
        else:
            return jsonify({
                'breached': False,
                'message': 'Good news! This password was not found in any data breaches.'
            })
            
    except Exception as e:
        print(f"Error checking breach: {e}")
        return jsonify({'error': 'Error checking password breaches'})

@app.route('/generate_password', methods=['POST'])
def generate_password():
    length = int(request.form.get('length', 12))
    use_uppercase = request.form.get('uppercase') == 'on'
    use_lowercase = request.form.get('lowercase') == 'on' 
    use_numbers = request.form.get('numbers') == 'on'
    use_symbols = request.form.get('symbols') == 'on'
    
    chars = ''
    if use_lowercase:
        chars += string.ascii_lowercase
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_numbers:
        chars += string.digits
    if use_symbols:
        chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    if not chars:
        return jsonify({'error': 'Please select at least one character type'})
    
    password = ''
    for i in range(length):
        password += random.choice(chars)
    
    return jsonify({'password': password})

@app.route('/save_history', methods=['POST'])
def save_history():
    global password_history
    
    password = request.form.get('password', '')
    if not password:
        return jsonify({'error': 'No password provided'})
    
    entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'length': len(password),
        'strength': get_strength_level(calculate_strength(password)),
        'score': calculate_strength(password)
    }
    
    password_history.append(entry)
    
    if len(password_history) > 10:
        password_history = password_history[-10:]
    
    return jsonify({'message': 'Password analysis saved to history'})

@app.route('/get_history')
def get_history():
    global password_history
    return jsonify({'history': password_history})

@app.route('/clear_history', methods=['POST'])
def clear_history():
    global password_history
    password_history = []
    return jsonify({'message': 'History cleared'})

def is_strong_password(password):
    return calculate_strength(password) >= 60

def get_password_tips():
    tips = [
        "Use at least 12 characters",
        "Mix uppercase and lowercase letters", 
        "Include numbers and symbols",
        "Avoid common words and patterns",
        "Don't reuse passwords across sites"
    ]
    return tips

@app.route('/tips')
def tips():
    return jsonify({'tips': get_password_tips()})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)