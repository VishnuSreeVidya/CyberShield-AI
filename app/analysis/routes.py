import json
from datetime import datetime, timezone
from flask import render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import login_required, current_user
from app import db
from app.models import (
    AnalysisHistory, URLAnalysis, TextAnalysis,
    PDFAnalysis, IPAnalysis, HashAnalysis, LogEntry, Alert,
)
from app.detection.url_detector import analyze_url
from app.detection.text_detector import analyze_text
from app.detection.pdf_detector import extract_pdf_metadata
from app.detection.ip_detector import analyze_ip
from app.detection.hash_detector import analyze_hash
from . import analysis_bp


@analysis_bp.route('/')
@login_required
def choose_analysis():
    counts = {
        'url': URLAnalysis.query.count(),
        'text': TextAnalysis.query.count(),
        'pdf': PDFAnalysis.query.count(),
        'ip': IPAnalysis.query.count(),
        'hash': HashAnalysis.query.count(),
        'log': LogEntry.query.count(),
    }
    return render_template('analysis/choose.html', counts=counts)


@analysis_bp.route('/url', methods=['GET', 'POST'])
@login_required
def url_analysis_page():
    result = None
    if request.method == 'POST':
        url_input = request.form.get('url', '').strip()
        if not url_input:
            flash('Please enter a URL to analyze.', 'danger')
            return render_template('analysis/url.html')

        if not url_input.startswith(('http://', 'https://')):
            url_input = 'http://' + url_input

        result = analyze_url(url_input)

        history = AnalysisHistory(
            user_id=current_user.id,
            analysis_type='URL',
            threat_level=result['threat_level'],
            risk_score=result['risk_score'],
            summary=f"Analyzed URL: {url_input[:100]}",
        )
        db.session.add(history)
        db.session.flush()

        url_detail = URLAnalysis(
            history_id=history.id,
            url=result['url'],
            is_https=result['is_https'],
            url_length=result['url_length'],
            has_suspicious_keywords=result['has_suspicious_keywords'],
            is_ip_based=result['is_ip_based'],
            phishing_indicators=result['phishing_indicators'],
            findings=result['findings'],
            recommendations=result['recommendations'],
        )
        db.session.add(url_detail)
        db.session.commit()

        flash(f'URL analysis complete. Threat Level: {result["threat_level"]}', 'success')

    return render_template('analysis/url.html', result=result)


@analysis_bp.route('/text', methods=['GET', 'POST'])
@login_required
def text_analysis_page():
    result = None
    if request.method == 'POST':
        text_input = request.form.get('text', '').strip()
        if not text_input:
            flash('Please enter text to analyze.', 'danger')
            return render_template('analysis/text.html')

        result = analyze_text(text_input)

        history = AnalysisHistory(
            user_id=current_user.id,
            analysis_type='Text',
            threat_level=result['threat_level'],
            risk_score=result['risk_score'],
            summary=f"Classification: {result['classification']}",
        )
        db.session.add(history)
        db.session.flush()

        text_detail = TextAnalysis(
            history_id=history.id,
            input_text=result['input_text'],
            classification=result['classification'],
            confidence_score=result['confidence_score'],
            is_phishing=result['is_phishing'],
            is_scam=result['is_scam'],
            is_spam=result['is_spam'],
            suspicious_words=result['suspicious_words'],
            findings=result['findings'],
            recommendations=result['recommendations'],
        )
        db.session.add(text_detail)
        db.session.commit()

        flash(f'Text analysis complete. Classification: {result["classification"]}', 'success')

    return render_template('analysis/text.html', result=result)


@analysis_bp.route('/pdf', methods=['GET', 'POST'])
@login_required
def pdf_analysis_page():
    result = None
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not file.filename:
            flash('Please select a PDF file.', 'danger')
            return render_template('analysis/pdf.html')

        if not file.filename.lower().endswith('.pdf'):
            flash('Only PDF files are supported.', 'danger')
            return render_template('analysis/pdf.html')

        try:
            file_content = file.read()
        except Exception:
            flash('Could not read the file.', 'danger')
            return render_template('analysis/pdf.html')

        result = extract_pdf_metadata(file_content, file.filename)

        history = AnalysisHistory(
            user_id=current_user.id,
            analysis_type='PDF',
            threat_level=result['threat_level'],
            risk_score=result['risk_score'],
            summary=f"Analyzed PDF: {file.filename}",
        )
        db.session.add(history)
        db.session.flush()

        pdf_detail = PDFAnalysis(
            history_id=history.id,
            filename=result['filename'],
            file_size=result['file_size'],
            author=result['author'],
            creation_date=result['creation_date'],
            page_count=result['page_count'],
            embedded_urls=result['embedded_urls'],
            suspicious_keywords=result['suspicious_keywords'],
            findings=result['findings'],
            recommendations=result['recommendations'],
        )
        db.session.add(pdf_detail)
        db.session.commit()

        flash(f'PDF analysis complete. Threat Level: {result["threat_level"]}', 'success')

    return render_template('analysis/pdf.html', result=result)


@analysis_bp.route('/ip', methods=['GET', 'POST'])
@login_required
def ip_analysis_page():
    result = None
    if request.method == 'POST':
        ip_input = request.form.get('ip', '').strip()
        if not ip_input:
            flash('Please enter an IP address.', 'danger')
            return render_template('analysis/ip.html')

        result = analyze_ip(ip_input)

        history = AnalysisHistory(
            user_id=current_user.id,
            analysis_type='IP',
            threat_level=result['threat_level'],
            risk_score=result['risk_score'],
            summary=f"Analyzed IP: {ip_input}",
        )
        db.session.add(history)
        db.session.flush()

        ip_detail = IPAnalysis(
            history_id=history.id,
            ip_address=result['ip_address'],
            is_public=result['is_public'],
            is_valid=result['is_valid'],
            is_reserved=result['is_reserved'],
            ip_type=result['ip_type'],
            findings=result['findings'],
            recommendations=result['recommendations'],
        )
        db.session.add(ip_detail)
        db.session.commit()

        flash(f'IP analysis complete. Threat Level: {result["threat_level"]}', 'success')

    return render_template('analysis/ip.html', result=result)


@analysis_bp.route('/hash', methods=['GET', 'POST'])
@login_required
def hash_analysis_page():
    result = None
    if request.method == 'POST':
        hash_input = request.form.get('hash', '').strip()
        if not hash_input:
            flash('Please enter a file hash.', 'danger')
            return render_template('analysis/hash.html')

        result = analyze_hash(hash_input)

        history = AnalysisHistory(
            user_id=current_user.id,
            analysis_type='Hash',
            threat_level=result['threat_level'],
            risk_score=result['risk_score'],
            summary=f"Analyzed {result['hash_type']} hash",
        )
        db.session.add(history)
        db.session.flush()

        hash_detail = HashAnalysis(
            history_id=history.id,
            hash_value=result['hash_value'],
            hash_type=result['hash_type'],
            is_valid_format=result['is_valid_format'],
            threat_status=result['threat_status'],
            findings=result['findings'],
            recommendations=result['recommendations'],
        )
        db.session.add(hash_detail)
        db.session.commit()

        flash(f'Hash analysis complete. Status: {result["threat_status"]}', 'success')

    return render_template('analysis/hash.html', result=result)


@analysis_bp.route('/history')
@login_required
def analysis_history():
    page = request.args.get('page', 1, type=int)
    analysis_type = request.args.get('type', '')
    threat_level = request.args.get('threat', '')
    search = request.args.get('search', '')

    query = AnalysisHistory.query.filter_by(user_id=current_user.id)

    if analysis_type:
        query = query.filter_by(analysis_type=analysis_type)
    if threat_level:
        query = query.filter_by(threat_level=threat_level)
    if search:
        query = query.filter(AnalysisHistory.summary.ilike(f'%{search}%'))

    pagination = query.order_by(AnalysisHistory.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    return render_template(
        'analysis/history.html',
        analyses=pagination.items,
        pagination=pagination,
        current_type=analysis_type,
        current_threat=threat_level,
        current_search=search,
    )


@analysis_bp.route('/history/<int:history_id>')
@login_required
def analysis_detail(history_id):
    history = AnalysisHistory.query.get_or_404(history_id)
    if history.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('analysis.analysis_history'))

    detail = None
    if history.analysis_type == 'URL':
        detail = URLAnalysis.query.filter_by(history_id=history.id).first()
    elif history.analysis_type == 'Text':
        detail = TextAnalysis.query.filter_by(history_id=history.id).first()
    elif history.analysis_type == 'PDF':
        detail = PDFAnalysis.query.filter_by(history_id=history.id).first()
    elif history.analysis_type == 'IP':
        detail = IPAnalysis.query.filter_by(history_id=history.id).first()
    elif history.analysis_type == 'Hash':
        detail = HashAnalysis.query.filter_by(history_id=history.id).first()

    return render_template('analysis/detail.html', history=history, detail=detail)


@analysis_bp.route('/history/<int:history_id>/delete', methods=['POST'])
@login_required
def delete_analysis(history_id):
    history = AnalysisHistory.query.get_or_404(history_id)
    if history.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('analysis.analysis_history'))

    if history.analysis_type == 'URL':
        URLAnalysis.query.filter_by(history_id=history.id).delete()
    elif history.analysis_type == 'Text':
        TextAnalysis.query.filter_by(history_id=history.id).delete()
    elif history.analysis_type == 'PDF':
        PDFAnalysis.query.filter_by(history_id=history.id).delete()
    elif history.analysis_type == 'IP':
        IPAnalysis.query.filter_by(history_id=history.id).delete()
    elif history.analysis_type == 'Hash':
        HashAnalysis.query.filter_by(history_id=history.id).delete()

    db.session.delete(history)
    db.session.commit()
    flash('Analysis deleted.', 'info')
    return redirect(url_for('analysis.analysis_history'))
