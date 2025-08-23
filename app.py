from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import csv
import io
import os
from datetime import datetime, UTC
from sqlalchemy import func, case, and_


app = Flask(__name__)
app.config['SECRET_KEY'] = 'f1fbd53703a549d300693c135f4cfad1'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hackathon.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

def flatten_filter(lst):
    """Custom filter to flatten a list of lists"""
    return [item for sublist in lst for item in sublist]

app.jinja_env.filters['flatten'] = flatten_filter

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    logger=True,
    engineio_logger=True,
    ping_timeout=60,
    ping_interval=25
)

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False) 
    role = db.Column(db.String(20), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=True)
    assigned_theme = db.Column(db.String(100), nullable=True)  # For judges' assigned theme
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Team(db.Model):
    __tablename__ = 'teams'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    theme = db.Column(db.String(100), nullable=False)
    leader_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    members = db.Column(db.Text)  # Comma-separated list of member names
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    judge_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Link to assigned judge
    
    # Relationships
    scores = db.relationship('JudgeScore', backref='team', lazy=True)
    votes = db.relationship('Vote', backref='team', lazy=True)
    judge = db.relationship('User', foreign_keys=[judge_id], backref='assigned_teams')

class JudgeScore(db.Model):
    __tablename__ = 'judge_scores'
    id = db.Column(db.Integer, primary_key=True)
    judge_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    idea_score = db.Column(db.Integer)  # 0-10
    solution_score = db.Column(db.Integer)  # 0-10  
    design_score = db.Column(db.Integer)  # 0-10
    prototype_score = db.Column(db.Integer)  # 0-10
    qa_score = db.Column(db.Integer)  # 0-10
    
    @property
    def total_score(self):
        scores = [self.idea_score, self.solution_score, self.design_score,
                 self.prototype_score, self.qa_score]
        return sum(score or 0 for score in scores)

class Vote(db.Model):
    __tablename__ = 'votes'
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False) 
    score = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    
    __table_args__ = (db.UniqueConstraint('voter_id', 'team_id'),)

class Setting(db.Model):
    __tablename__ = 'settings'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(UTC))

class TeamStatus(db.Model):
    __tablename__ = 'team_status'
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    presentation_started = db.Column(db.DateTime, nullable=True)
    presentation_ended = db.Column(db.DateTime, nullable=True)
    judging_completed = db.Column(db.Boolean, default=False)
    
    team = db.relationship('Team', backref='status', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Helper functions
def get_current_team():
    setting = Setting.query.filter_by(key='current_team_id').first()
    if setting and setting.value != 'NULL':
        return Team.query.get(int(setting.value))
    return None

def set_current_team(team_id, start_presentation=False, end_presentation=False):
    setting = Setting.query.filter_by(key='current_team_id').first()
    if setting:
        old_team_id = setting.value if setting.value != 'NULL' else None
        setting.value = str(team_id) if team_id else 'NULL'
        # Always set timestamp when selecting a team or starting presentation
        if team_id:
            setting.timestamp = datetime.now(UTC)
    else:
        setting = Setting(key='current_team_id', value=str(team_id) if team_id else 'NULL')
        if team_id:
            setting.timestamp = datetime.now(UTC)
        db.session.add(setting)
        old_team_id = None
        
    if old_team_id and old_team_id != 'NULL':
        old_status = TeamStatus.query.filter_by(team_id=int(old_team_id)).first()
        if old_status and not old_status.presentation_ended:
            old_status.presentation_ended = datetime.now(UTC)
            
    if team_id:
        status = TeamStatus.query.filter_by(team_id=team_id).first()
        if not status:
            status = TeamStatus(team_id=team_id)
            db.session.add(status)
        if not status.presentation_started:
            status.presentation_started = datetime.now(UTC)
    
    db.session.commit()

def get_team_status(team_id):
    status = TeamStatus.query.filter_by(team_id=team_id).first()
    scores = JudgeScore.query.filter_by(team_id=team_id).all()
    
    if not status:
        status = TeamStatus(team_id=team_id)
        db.session.add(status)
        db.session.commit()
        
    return {
        'presentation_started': status.presentation_started,
        'presentation_ended': status.presentation_ended,
        'judging_completed': bool(scores),
        'total_score': sum(score.total_score for score in scores) if scores else 0
    }

def get_presentation_time():
    current_team = get_current_team()
    if not current_team:
        return None
        
    setting = Setting.query.filter_by(key='current_team_id').first()
    if setting and setting.timestamp:
        # Convert the naive timestamp from DB to UTC aware
        try:
            if setting.timestamp.tzinfo is None:
                db_timestamp = setting.timestamp.replace(tzinfo=UTC)
            else:
                db_timestamp = setting.timestamp
            elapsed = datetime.now(UTC) - db_timestamp
            return int(elapsed.total_seconds())
        except Exception as e:
            print(f"Timer error: {e}")
            return 0
    return None

def get_voting_enabled():
    setting = Setting.query.filter_by(key='voting_enabled').first()
    return setting and setting.value == 'true'

def set_voting_enabled(enabled):
    try:
        setting = Setting.query.filter_by(key='voting_enabled').first()
        if setting:
            setting.value = 'true' if enabled else 'false'
        else:
            setting = Setting(key='voting_enabled', 
                            value='true' if enabled else 'false')
            db.session.add(setting)
        db.session.commit()
        return True
    except:
        db.session.rollback()
        return False

def update_presentation_timer():
    """Send presentation timer updates every second"""
    import time  # Import here to avoid timing issues
    while True:
        try:
            with app.app_context():
                current_team = get_current_team()
                if current_team:
                    presentation_time = get_presentation_time()
                    if presentation_time is not None:
                        try:
                            socketio.emit('timer_update', {
                                'presentation_time': presentation_time
                            }, namespace='/')
                        except Exception as emit_error:
                            print(f"Error emitting timer update: {emit_error}")
        except Exception as e:
            print(f"Timer update error: {e}")
        
        time.sleep(1)



# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'judge':
            return redirect(url_for('judge_dashboard'))
        else:
            return redirect(url_for('team_voting'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('index'))
        
    teams = Team.query.all()
    judges = User.query.filter_by(role='judge').all()
    current_team = get_current_team()
    voting_enabled = get_voting_enabled()
    
    return render_template('admin_dashboard.html',
                         teams=teams,
                         judges=judges,
                         current_team=current_team,
                         voting_enabled=voting_enabled)

@app.route('/toggle_voting', methods=['POST'])
@login_required
def toggle_voting():
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
        
    try:
        data = request.get_json()
        if data is None:
            return jsonify({'error': 'Invalid JSON data'}), 400
            
        enabled = data.get('enabled')
        if enabled is None:
            return jsonify({'error': 'Missing enabled parameter'}), 400
            
        if set_voting_enabled(enabled):
            return jsonify({
                'success': True,
                'enabled': enabled,
                'message': f'Voting {"enabled" if enabled else "disabled"} successfully'
            })
        else:
            return jsonify({'error': 'Failed to update voting status'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/upload_teams', methods=['POST'])
@login_required
def upload_teams():
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
        
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if not file or not file.filename.endswith('.csv'):
        return jsonify({'error': 'Invalid file format. Please upload a CSV file.'}), 400
        
    # Read CSV file
    try:
        content = file.stream.read().decode('UTF8')
        stream = io.StringIO(content)
        csv_reader = csv.DictReader(stream)
        rows = list(csv_reader)
    except Exception as e:
        return jsonify({'error': f'Invalid CSV format: {str(e)}'}), 400
        
    # Validate required columns
    required_fields = ['Team Name', 'Leader Name', 'Theme', 'Assigned Judge']
    if not all(field in csv_reader.fieldnames for field in required_fields):
        return jsonify({
            'error': 'CSV must contain "Team Name", "Leader Name", "Theme", and "Assigned Judge" columns'
        }), 400
    
    # Define valid themes
    valid_themes = ["AIML (Theme_1)", "Cyber security and block chain (Theme_2)", "Open Innovation"]
        
    teams_added = 0
    try:
        # Process rows in transaction
        for row in rows:
            # Skip comment rows (starting with #)
            if row['Team Name'].startswith('#'):
                continue
                
            team_name = row['Team Name'].strip()
            leader_name = row['Leader Name'].strip()
            theme = row['Theme'].strip()
            assigned_judge = row['Assigned Judge'].strip()
            
            if not team_name or not leader_name or not theme or not assigned_judge:
                raise ValueError(f'Empty required field in row: {row}')
                
            if theme not in valid_themes:
                raise ValueError(f'Invalid theme "{theme}". Must be one of: {", ".join(valid_themes)}')
                
            # Find the specified judge
            judge = User.query.filter_by(username=assigned_judge, role='judge').first()
            if not judge:
                raise ValueError(f'Judge not found with username: {assigned_judge}')

            # Create team
            team = Team(
                name=team_name,
                leader_name=leader_name,
                theme=theme,
                members=row.get('Members', '') or '',  # Handle None case
                description=row.get('Description', '') or '',  # Handle None case
                judge_id=judge.id
            )
            
            # Create leader account
            username = leader_name.lower().replace(' ', '_')
            password = team_name.lower().replace(' ', '_')
            
            if User.query.filter_by(username=username).first():
                raise ValueError(f'Username {username} already exists')
                
            leader = User(username=username, role='team_leader')
            leader.set_password(password)
            
            db.session.add(team)
            db.session.add(leader)
            db.session.flush()
            
            leader.team_id = team.id
            teams_added += 1
            
        db.session.commit()
        return jsonify({
            'success': True,
            'message': f'Successfully added {teams_added} teams',
            'teams_added': teams_added
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/judge_score', methods=['POST'])
@login_required
def submit_score():
    if current_user.role != 'judge':
        return jsonify({'error': 'Access denied'}), 403
        
    data = request.get_json()
    if not data or 'team_id' not in data:
        return jsonify({'error': 'Missing team_id'}), 400
        
    team_id = data['team_id']
    
    score = JudgeScore.query.filter_by(
        judge_id=current_user.id,
        team_id=team_id
    ).first()
    
    if not score:
        score = JudgeScore(judge_id=current_user.id, team_id=team_id)
        db.session.add(score)
        
    fields = ['idea_score', 'solution_score', 'design_score', 
              'prototype_score', 'qa_score']
              
    for field in fields:
        if field in data:
            value = data[field]
            if value is not None and (value < 0 or value > 10):
                return jsonify({'error': f'{field} must be between 0 and 10'}), 400
            setattr(score, field, value)
            
    try:
        db.session.commit()
        return jsonify({
            'success': True,
            'total_score': score.total_score
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/export_theme_results/<theme>')
@login_required
def export_theme_results(theme):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Verify if user has access to this theme
    if current_user.role == 'team_leader':
        if not current_user.team_id:
            return jsonify({'error': 'Access denied'}), 403
        user_team = Team.query.get(current_user.team_id)
        if not user_team or user_team.theme != theme:
            return jsonify({'error': 'Access denied'}), 403
    
    teams = Team.query.filter_by(theme=theme).all()
    theme_results = []
    
    for team in teams:
        # Judge scores (70%)
        judge_scores = JudgeScore.query.filter_by(team_id=team.id).all()
        avg_judge_score = 0
        if judge_scores:
            total = sum(score.total_score for score in judge_scores)
            avg_judge_score = (total / len(judge_scores)) / 50 * 100
            
        # Audience votes (30%)
        votes = Vote.query.filter_by(team_id=team.id).all()
        vote_count = len(votes)
        vote_sum = sum(vote.score for vote in votes) if votes else 0
        avg_audience_score = (vote_sum / (vote_count * 5) * 100) if vote_count > 0 else 0
        
        final_score = (avg_judge_score * 0.7) + (avg_audience_score * 0.3)
        
        theme_results.append({
            'team_name': team.name,
            'leader_name': team.leader_name,
            'members': team.members,
            'final_score': round(final_score, 1),
            'judge_score': round(avg_judge_score, 1),
            'audience_score': round(avg_audience_score, 1),
            'vote_count': vote_count
        })
    
    # Sort by final score
    theme_results.sort(key=lambda x: x['final_score'], reverse=True)
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(['Rank', 'Team Name', 'Leader Name', 'Members', 
                    'Final Score (%)', 'Judge Score (%)', 'Audience Score (%)', 
                    'Number of Votes'])
    
    # Write data
    for i, result in enumerate(theme_results, 1):
        writer.writerow([
            i,
            result['team_name'],
            result['leader_name'],
            result['members'],
            result['final_score'],
            result['judge_score'],
            result['audience_score'],
            result['vote_count']
        ])
    
    # Prepare response
    output.seek(0)
    filename = f"{theme.replace(' ', '_')}_results.csv"
    
    return jsonify({
        'success': True,
        'filename': filename,
        'content': output.getvalue()
    })

@app.route('/results')
@login_required
def results():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
        
    # Define the fixed themes
    fixed_themes = ["AIML (Theme_1)", "Cyber security and block chain (Theme_2)", "Open Innovation"]
    results = {}
    
    # Get user's team theme if they are a team leader
    user_theme = None
    if current_user.role == 'team_leader' and current_user.team_id:
        user_team = Team.query.get(current_user.team_id)
        if user_team:
            user_theme = user_team.theme
    
    # Only show all themes to admins and judges
    themes_to_show = fixed_themes
    if current_user.role == 'team_leader':
        themes_to_show = [user_theme] if user_theme else []
    
    for theme in themes_to_show:
        teams = Team.query.filter_by(theme=theme).all()
        theme_results = []
        
        for team in teams:
            # Judge scores (70%)
            judge_scores = JudgeScore.query.filter_by(team_id=team.id).all()
            avg_judge_score = 0
            if judge_scores:
                total = sum(score.total_score for score in judge_scores)
                avg_judge_score = (total / len(judge_scores)) / 50 * 100
                
            # Audience votes (30%)
            votes = Vote.query.filter_by(team_id=team.id).all()
            vote_count = len(votes)
            vote_sum = sum(vote.score for vote in votes) if votes else 0
            avg_audience_score = (vote_sum / (vote_count * 5) * 100) if vote_count > 0 else 0
            
            final_score = (avg_judge_score * 0.7) + (avg_audience_score * 0.3)
            
            theme_results.append({
                'team': team,
                'final_score': round(final_score, 1),
                'judge_percentage': round(avg_judge_score, 1),
                'audience_percentage': round(avg_audience_score, 1),
                'vote_count': vote_count
            })
            
        results[theme] = sorted(
            theme_results,
            key=lambda x: x['final_score'],
            reverse=True
        )
        
    return render_template('results.html', results=results)

@app.route('/judge')
@login_required
def judge_dashboard():
    if current_user.role != 'judge':
        flash('Access denied')
        return redirect(url_for('index'))
    
    # Get only teams assigned to this specific judge
    teams = Team.query.filter_by(judge_id=current_user.id).all()
    
    if not teams:
        flash('No teams assigned to you. Please contact an administrator.')
        return redirect(url_for('index'))
        
    current_team = get_current_team()
    
    # Only show current team if it's assigned to this judge
    if current_team and current_team.judge_id != current_user.id:
        current_team = None
    
    # Get judge's scores
    judge_scores = {}
    scores = JudgeScore.query.filter_by(judge_id=current_user.id).all()
    for score in scores:
        judge_scores[score.team_id] = score
        
    # Get team statuses
    team_statuses = {}
    completed_teams = []
    pending_teams = []
    current_presenting_team = None
    
    for team in teams:
        status = get_team_status(team.id)
        team_statuses[team.id] = status
        
        # If this is the current presenting team
        if current_team and team.id == current_team.id:
            current_presenting_team = team
            continue
            
        if status['judging_completed']:
            completed_teams.append(team)
        else:
            pending_teams.append(team)
            
    # Put current presenting team at the start of pending teams
    if current_presenting_team:
        if team_statuses[current_presenting_team.id]['judging_completed']:
            completed_teams.insert(0, current_presenting_team)
        else:
            pending_teams.insert(0, current_presenting_team)
            
    presentation_time = get_presentation_time()
    
    return render_template('judge_dashboard.html',
                         teams=teams,
                         current_team=current_team, 
                         judge_scores=judge_scores,
                         team_statuses=team_statuses,
                         completed_teams=completed_teams,
                         pending_teams=pending_teams,
                         presentation_time=presentation_time)

@app.route('/set_current_team', methods=['POST'])
@login_required
def set_current_team_route():
    if current_user.role not in ['admin', 'judge']:
        return jsonify({'error': 'Access denied'}), 403
        
    data = request.get_json()
    team_id = data.get('team_id')
    action = data.get('action', 'select')  # 'select', 'start', 'stop', or 'end'
    
    if team_id is not None:
        try:
            team_id = int(team_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid team ID'}), 400
    
    start_presentation = (action == 'start')
    end_presentation = (action == 'end')
    if action == 'stop' or action == 'end':
        team_id = None
        
    set_current_team(team_id, start_presentation, end_presentation)
    current_team = get_current_team()
    
    presentation_time = None
    if current_team:
        if start_presentation or action == 'select':
            presentation_time = 0  # Start timer for both select and start actions
        elif action != 'stop' and action != 'end':
            presentation_time = get_presentation_time()
    
    response_data = {
        'team_id': team_id,
        'team_name': current_team.name if current_team else None,
        'presentation_time': presentation_time,
        'action': action,
        'judge_id': current_user.id if current_user.role == 'judge' else None
    }
    
    try:
        # For judges, emit to judge-specific channel
        if current_user.role == 'judge':
            socketio.emit(f'presentation_update_judge_{current_user.id}', response_data)
        else:
            # Admin events still go to all
            socketio.emit('presenting_team_changed', response_data)
    except Exception as e:
        print(f"Error emitting team change: {e}")
    
    # Update team status when selecting or starting
    if team_id and (action == 'select' or action == 'start'):
        status = TeamStatus.query.filter_by(team_id=team_id).first()
        if not status:
            status = TeamStatus(team_id=team_id)
            db.session.add(status)
        if not status.presentation_started:
            status.presentation_started = datetime.now(UTC)
        db.session.commit()
    
    return jsonify({
        'success': True,
        'team_name': current_team.name if current_team else None,
        'presentation_time': presentation_time,
        'action': action
    })

@app.route('/team_voting')
@login_required
def team_voting():
    current_team = get_current_team()
    voting_enabled = get_voting_enabled()
    
    # Get user's team and assigned judge
    user_team = None
    user_judge_id = None
    if current_user.team_id:
        user_team = Team.query.get(current_user.team_id)
        if user_team:
            user_judge_id = user_team.judge_id
    
    # Check if user can vote (assigned to same judge as current team)
    can_vote = True
    if current_team and current_user.role == 'team_leader':
        # Only teams assigned to the same judge can vote
        can_vote = user_team and user_team.judge_id == current_team.judge_id
    
    has_voted = False
    if current_team:
        has_voted = Vote.query.filter_by(
            voter_id=current_user.id,
            team_id=current_team.id
        ).first() is not None
        
    return render_template('team_voting.html',
                         current_team=current_team,
                         voting_enabled=voting_enabled and can_vote,
                         has_voted=has_voted,
                         user_team_id=current_user.team_id,
                         can_vote=can_vote,
                         judge_id=user_judge_id)

@app.route('/submit_vote', methods=['POST'])
@login_required
def submit_vote():
    if not get_voting_enabled():
        return jsonify({'error': 'Voting is currently disabled'}), 403
        
    data = request.get_json()
    if not data or 'score' not in data:
        return jsonify({'error': 'Missing score'}), 400
        
    score = data['score']
    if not isinstance(score, int) or score < 1 or score > 5:
        return jsonify({'error': 'Score must be between 1 and 5'}), 400
        
    current_team = get_current_team()
    if not current_team:
        return jsonify({'error': 'No team is currently presenting'}), 400
        
    if current_user.team_id == current_team.id:
        return jsonify({'error': 'Cannot vote for your own team'}), 403
    
    # Check if user is voting within their theme
    user_team = Team.query.get(current_user.team_id)
    if user_team and user_team.theme != current_team.theme:
        return jsonify({'error': 'You can only vote for teams in your theme'}), 403
        
    existing_vote = Vote.query.filter_by(
        voter_id=current_user.id,
        team_id=current_team.id
    ).first()
    
    if existing_vote:
        return jsonify({'error': 'Already voted for this team'}), 400
        
    try:
        vote = Vote(
            voter_id=current_user.id,
            team_id=current_team.id,
            score=score
        )
        db.session.add(vote)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Vote submitted successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

def init_db():
    with app.app_context():
        # Only create tables if they don't exist, don't drop existing data
        db.create_all()
        
        # Only create default users if they don't exist
        if not User.query.filter_by(username='admin').first():
            # Create admin user
            admin = User(username='admin', role='admin')
            admin.set_password('jgWxWE)$9V@7Ms4M')
            db.session.add(admin)
            
            # Create multiple judges with specific themes
            judges = [
                # AIML Theme Judges
                {
                    'username': 'aiml_judge1',
                    'password': 'aiml123',
                    'theme': 'AIML (Theme_1)'
                },
                {
                    'username': 'aiml_judge2',
                    'password': 'aiml456',
                    'theme': 'AIML (Theme_1)'
                },
                # Cyber Security Theme Judges
                {
                    'username': 'cyber_judge1',
                    'password': 'cyber123',
                    'theme': 'Cyber security and block chain (Theme_2)'
                },
                {
                    'username': 'cyber_judge2',
                    'password': 'cyber456',
                    'theme': 'Cyber security and block chain (Theme_2)'
                },
                # Open Innovation Theme Judges
                {
                    'username': 'innovation_judge1',
                    'password': 'innovation123',
                    'theme': 'Open Innovation'
                },
                {
                    'username': 'innovation_judge2',
                    'password': 'innovation456',
                    'theme': 'Open Innovation'
                }
            ]
            
            for judge_data in judges:
                judge = User(
                    username=judge_data['username'],
                    role='judge',
                    assigned_theme=judge_data['theme']
                )
                judge.set_password(judge_data['password'])
                db.session.add(judge)
            
            # Initialize settings only if they don't exist
            if not Setting.query.filter_by(key='current_team_id').first():
                settings = [
                    ('current_team_id', 'NULL'),
                    ('voting_enabled', 'false')
                ]
                
                for key, value in settings:
                    setting = Setting(key=key, value=value, timestamp=datetime.now(UTC))
                    db.session.add(setting)
                    
            try:
                db.session.commit()
            except Exception as e:
                print(f"Error initializing database: {e}")
                db.session.rollback()
                raise

if __name__ == '__main__':
    init_db()
    try:
        import threading
        import time  # Ensure time is imported
        timer_thread = threading.Thread(target=update_presentation_timer, daemon=True)
        timer_thread.start()
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"Error starting application: {e}")