#!/usr/bin/env python3
"""
Hackathon Scoring System Setup Script
Run this to set up and start the application
"""

import os
import sys
import subprocess
from pathlib import Path

def create_directories():
    """Create necessary directories"""
    directories = ['templates', 'static', 'instance']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    print("✅ Directories created")

def create_templates():
    """Create template files with placeholder content"""
    templates = {
        'base.html': '''<!-- Base template - Replace with actual content -->
<!DOCTYPE html>
<html><head><title>Hackathon Scorer</title></head>
<body>{% block content %}{% endblock %}</body></html>''',
        
        'login.html': '''<!-- Login template - Replace with actual content -->
{% extends "base.html" %}
{% block content %}<h1>Login</h1>{% endblock %}''',
        
        'admin_dashboard.html': '''<!-- Admin template - Replace with actual content -->
{% extends "base.html" %}
{% block content %}<h1>Admin Dashboard</h1>{% endblock %}''',
        
        'judge_dashboard.html': '''<!-- Judge template - Replace with actual content -->  
{% extends "base.html" %}
{% block content %}<h1>Judge Dashboard</h1>{% endblock %}''',
        
        'team_voting.html': '''<!-- Team voting template - Replace with actual content -->
{% extends "base.html" %}
{% block content %}<h1>Team Voting</h1>{% endblock %}''',
        
        'results.html': '''<!-- Results template - Replace with actual content -->
{% extends "base.html" %}
{% block content %}<h1>Results</h1>{% endblock %}'''
    }
    
    templates_dir = Path('templates')
    templates_dir.mkdir(exist_ok=True)
    
    for filename, content in templates.items():
        template_path = templates_dir / filename
        if not template_path.exists():
            template_path.write_text(content)
    
    print("✅ Template placeholders created")

def install_requirements():
    """Install Python requirements"""
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Requirements installed")
    except subprocess.CalledProcessError:
        print("❌ Failed to install requirements")
        sys.exit(1)

def create_sample_csv():
    """Create a sample CSV file for team uploads"""
    csv_content = """Team Name,Leader Name,Theme
Team Alpha,John Smith,Theme A
Team Beta,Jane Doe,Theme A  
Team Gamma,Bob Johnson,Theme B
Team Delta,Alice Brown,Theme B
Team Echo,Charlie Wilson,Theme C
Team Fox,Diana Davis,Theme C"""
    
    with open('sample_teams.csv', 'w') as f:
        f.write(csv_content)
    
    print("✅ Sample CSV created (sample_teams.csv)")

def main():
    print("🚀 Setting up Hackathon Scoring System...\n")
    
    create_directories()
    create_templates()
    
    if Path('requirements.txt').exists():
        print("📦 Installing requirements...")
        install_requirements()
    else:
        print("⚠️  requirements.txt not found, skipping installation")
    
    create_sample_csv()
    
    print("\n✅ Setup complete!")
    print("\n📋 Next steps:")
    print("1. Replace template placeholders with actual HTML from artifacts")
    print("2. Run: python app.py")
    print("3. Open: http://localhost:5000")
    print("4. Login as admin (admin/admin123) to upload teams")
    print("5. Use sample_teams.csv for testing")
    print("\n🔐 Default accounts:")
    print("   Admin: admin / admin123")
    print("   Judge: judge1 / judge123")
    print("   Teams: leader_name / team_name")

if __name__ == '__main__':
    main()