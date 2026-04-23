# AI Cloud Security Monitor Backend

AI-powered cloud security monitoring system for AWS that detects security vulnerabilities, anomalies, and generates comprehensive reports.

## Features

- 🔍 **AWS Security Scanning**: S3, EC2, IAM resource scanning
- 🤖 **AI-Powered Analysis**: Intelligent risk assessment and recommendations
- 📊 **Anomaly Detection**: CloudTrail log analysis for suspicious activities
- 📈 **Comprehensive Reports**: Auto-generated security reports with AI summaries
- 💾 **Database**: SQLite/PostgreSQL support with SQLAlchemy ORM

## Database Models

- **Finding**: Security vulnerabilities discovered in AWS resources
- **Anomaly**: Suspicious activities detected in CloudTrail logs
- **Report**: Generated security reports with summaries and recommendations
- **Scan**: Security scan records and metadata

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env with your AWS and OpenAI credentials
```

### 3. Initialize Database
```bash
python migrate.py init
```

### 4. Run Application
```bash
python -m app.main
```

API will be available at `http://localhost:8000`
- API Documentation: `http://localhost:8000/docs`
- Alternative Docs: `http://localhost:8000/redoc`

## Database Commands

```bash
# Initialize database tables
python migrate.py init

# Reset database (WARNING: Deletes all data)
python migrate.py reset

# Show all tables
python migrate.py show
```

## API Endpoints

- `GET /api/v1/health` - Health check with database statistics
- `POST /api/v1/scans` - Create new security scan
- `GET /api/v1/scans` - List all scans
- `GET /api/v1/anomalies` - List detected anomalies
- `GET /api/v1/reports` - List security reports

## Technology Stack

- **FastAPI**: Modern web framework
- **SQLAlchemy**: ORM for database operations
- **Pydantic**: Data validation
- **Uvicorn**: ASGI server
- **PostgreSQL/SQLite**: Database options

## Project Structure

```
app/
├── db/
│   ├── database.py    # Database connection and session
│   ├── models.py      # SQLAlchemy ORM models
│   ├── crud.py        # CRUD operations
│   └── schemas.py     # Pydantic schemas
├── routes/            # API route handlers
├── scanners/          # AWS resource scanners
├── detectors/         # Anomaly detection modules
├── services/          # Business logic services
└── main.py           # FastAPI application
```