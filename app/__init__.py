from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return db.session.get(User, int(user_id))

    with app.app_context():
        from app.auth import auth_bp
        from app.dashboard import dashboard_bp
        from app.logs import logs_bp
        from app.routes import main_bp
        from app.analysis import analysis_bp

        app.register_blueprint(auth_bp, url_prefix='/auth')
        app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
        app.register_blueprint(logs_bp, url_prefix='/logs')
        app.register_blueprint(analysis_bp, url_prefix='/analysis')
        app.register_blueprint(main_bp)

        from app.models import (
            User, LogEntry, Alert, Report,
            AnalysisHistory, URLAnalysis, TextAnalysis,
            PDFAnalysis, IPAnalysis, HashAnalysis,
        )
        db.create_all()

        pass

    @app.route('/health')
    def health():
        return {'status': 'ok', 'app': 'CyberShield AI'}

    
    @app.after_request
    def apply_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https:;"
        return response

    return app
