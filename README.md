# Business Data Scraper

A Python web application that searches for businesses using the Google Places API and scrapes their websites for contact information.

## Features

- 🔍 Search businesses by location and keyword
- 🌐 Automatically detects and categorizes businesses with/without websites
- 📧 Scrapes email addresses from business websites
- 📊 Clean, responsive UI with filtering options
- 📥 Export results to CSV
- 🌙 Dark mode support

## Prerequisites

- Python 3.8 or higher
- Google Places API key

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd [repository-name]
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory with the following content:
```
GOOGLE_PLACES_API_KEY=your_google_places_api_key_here
SECRET_KEY=your_flask_secret_key_here
```

Replace `your_google_places_api_key_here` with your actual Google Places API key.

## Usage

1. Start the Flask application:
```bash
python app.py
```

2. Open your web browser and navigate to `http://localhost:5000`

3. Enter a location and business type to search

4. View results in the tabbed interface:
   - All Results
   - With Website
   - Without Website
   - Emails Found

5. Download results as CSV using the download button

## Features

### Search
- Location-based search using Google Places API
- Keyword filtering for business types
- 45km radius search from specified location

### Data Collection
- Business name
- Address
- Website URL (if available)
- Email addresses (scraped from website)

### UI Features
- Responsive Bootstrap design
- Dark mode toggle
- Progress indicator during searches
- Tabbed interface for filtered views
- Sortable tables
- Toast notifications for status updates

### Export
- CSV export with all collected data
- Timestamp-based file naming

## Rate Limiting and Error Handling

- Timeout handling for website scraping
- Error notifications via toast messages
- Graceful handling of API limits

## Security

- CSRF protection enabled
- Environment variables for sensitive data
- Secure file downloads

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
