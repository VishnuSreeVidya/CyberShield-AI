from app import create_app, db
from app.models import (
    User, LogEntry, Alert, Report,
    AnalysisHistory, URLAnalysis, TextAnalysis,
    PDFAnalysis, IPAnalysis, HashAnalysis,
)

app = create_app()


@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'LogEntry': LogEntry,
        'Alert': Alert,
        'Report': Report,
        'AnalysisHistory': AnalysisHistory,
        'URLAnalysis': URLAnalysis,
        'TextAnalysis': TextAnalysis,
        'PDFAnalysis': PDFAnalysis,
        'IPAnalysis': IPAnalysis,
        'HashAnalysis': HashAnalysis,
    }


if __name__ == '__main__':
    app.run(debug=True)
