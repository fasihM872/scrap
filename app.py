from flask import Flask, render_template, request, jsonify, send_file
from flask_wtf.csrf import CSRFProtect, generate_csrf
# from selenium import webdriver
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from selenium.webdriver.common.by import By
# from webdriver_manager.chrome import ChromeDriverManager
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import re
import pandas as pd
from datetime import datetime
import os
from dotenv import load_dotenv
import json
from urllib.parse import urlparse, quote, urljoin, unquote
import io
import time
# import base64
# from PIL import Image, ImageEnhance


# Initialize thread_local storage
thread_local = threading.local()

# Load environment variables
load_dotenv()

# Debug print for API key
api_key = os.getenv('GOOGLE_PLACES_API_KEY')
if api_key:
    print(f"API Key loaded (first 10 chars): {api_key[:10]}...")
else:
    print("Warning: No API key found in .env file")

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
csrf = CSRFProtect(app)

# Configure requests session with retries and timeouts
session = requests.Session()
retries = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
session.mount('http://', HTTPAdapter(max_retries=retries))
session.mount('https://', HTTPAdapter(max_retries=retries))

# OneDrive Configuration
CLIENT_ID = os.getenv('ONEDRIVE_CLIENT_ID')
CLIENT_SECRET = os.getenv('ONEDRIVE_CLIENT_SECRET')
SCOPES = ['files.readwrite', 'offline_access']

# Dropbox Configuration
DROPBOX_ACCESS_TOKEN = os.getenv('DROPBOX_ACCESS_TOKEN')

def get_onedrive_account():
    """Get or create OneDrive account instance."""
    try:
        # Set up token backend
        token_backend = FileSystemTokenBackend(token_path='.', token_filename='o365_token.txt')
        
        # Create account object
        account = Account((CLIENT_ID, CLIENT_SECRET), token_backend=token_backend)
        
        # If not authenticated, authenticate
        if not account.is_authenticated:
            if not account.authenticate(scopes=SCOPES):
                raise Exception("Failed to authenticate with OneDrive")
        
        return account
    except Exception as e:
        print(f"Error getting OneDrive account: {str(e)}")
        raise

def create_onedrive_folder(drive, folder_name):
    """Create a folder in OneDrive and return its ID."""
    try:
        # Get root folder
        root = drive.get_root_folder()
        
        # Create new folder
        new_folder = root.create_child_folder(folder_name)
        
        return new_folder
    except Exception as e:
        print(f"Error creating OneDrive folder: {str(e)}")
        raise

def upload_to_onedrive(file_path, folder):
    """Upload a file to OneDrive folder and return its sharing link."""
    try:
        # Upload file
        file_name = os.path.basename(file_path)
        uploaded_file = folder.upload_file(file_path)
        
        # Create sharing link
        permission = uploaded_file.share_with_link(share_type='view')
        
        return permission.share_link
    except Exception as e:
        print(f"Error uploading to OneDrive: {str(e)}")
        raise

def upload_to_dropbox(file_path, folder_path):
    """Upload a file to Dropbox and return its shared link."""
    try:
        if not DROPBOX_ACCESS_TOKEN:
            print("Error: Dropbox access token is missing")
            raise ValueError("Dropbox access token is not configured")
            
        print(f"Initializing Dropbox with token (first 10 chars): {DROPBOX_ACCESS_TOKEN[:10]}...")
        dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
        
        # Verify account access
        try:
            account = dbx.users_get_current_account()
            print(f"Connected to Dropbox account: {account.name.display_name}")
        except dropbox.exceptions.AuthError as e:
            print(f"Dropbox authentication failed: {str(e)}")
            raise
            
        # Read file
        if not os.path.exists(file_path):
            print(f"Error: File not found: {file_path}")
            raise FileNotFoundError(f"File not found: {file_path}")
            
        print(f"Reading file: {file_path}")
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Upload file
        dropbox_path = f"{folder_path}/{os.path.basename(file_path)}"
        print(f"Uploading to Dropbox path: {dropbox_path}")
        
        try:
            dbx.files_upload(file_data, dropbox_path, mode=WriteMode('overwrite'))
            print("File uploaded successfully")
        except dropbox.exceptions.ApiError as e:
            print(f"Dropbox upload failed: {str(e)}")
            if e.error.is_path():
                print("Path error - check if the folder exists and you have write permissions")
            raise
        
        # Create shared link
        try:
            shared_link = dbx.sharing_create_shared_link(dropbox_path)
            print(f"Created shared link: {shared_link.url}")
            return shared_link.url
        except dropbox.exceptions.ApiError as e:
            print(f"Failed to create shared link: {str(e)}")
            raise
            
    except Exception as e:
        print(f"Error uploading to Dropbox: {str(e)}")
        raise

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get-csrf-token')
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token})

@app.route('/search', methods=['POST'])
@csrf.exempt
def search():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        location = data.get('location')
        keyword = data.get('keyword')
        
        if not location or not keyword:
            return jsonify({'error': 'Location and keyword are required'}), 400
            
        print(f"\nProcessing search request for {keyword} in {location}")
        
        # Search for places
        places_result = search_places(location, keyword)
        if not places_result:
            return jsonify({'error': 'No results found'}), 404
        
        businesses = []
        
        # Process places without screenshots
        for place in places_result.get('places', []):
            try:
                website = clean_website_url(place.get('websiteUri', ''))
                emails = []
                if website:
                    print(f"\nScraping emails from website: {website}")
                    emails = extract_emails(website)
                    print(f"Found {len(emails)} emails from {website}")

                business = {
                    'name': place.get('displayName', {}).get('text', ''),
                    'website': website,
                    'address': place.get('formattedAddress', ''),
                    'phone': place.get('internationalPhoneNumber', '') or place.get('nationalPhoneNumber', ''),
                    'emails': emails,
                    'screenshot': None  # Screenshot functionality disabled
                }
                businesses.append(business)
                print(f"Added business: {business['name']} ({business['website']}) with {len(emails)} emails")
            except Exception as e:
                print(f"Error processing place: {str(e)}")
                continue
        
        """
        # SCREENSHOT PROCESSING - CURRENTLY DISABLED
        # To re-enable screenshots:
        # 1. Uncomment this section
        # 2. Make sure the capture_screenshot function is uncommented above
        
        # Process screenshots sequentially
        businesses_with_websites = [b for b in businesses if b['website']]
        completed_screenshots = 0
        
        print(f"\nProcessing screenshots for {len(businesses_with_websites)} businesses with websites")
        
        for business in businesses_with_websites:
            try:
                screenshot = capture_screenshot(business['website'])
                if screenshot:
                    business['screenshot'] = screenshot
                    completed_screenshots += 1
                    print(f"Screenshot captured successfully for {business['website']}")
                else:
                    print(f"Failed to capture screenshot for {business['website']}")
            except Exception as e:
                print(f"Error capturing screenshot for {business['website']}: {str(e)}")
        
        print(f"\nCompleted processing {completed_screenshots} screenshots out of {len(businesses_with_websites)} websites")
        """
        
        return jsonify({
            'success': True,
            'businesses': businesses,
            'screenshots_completed': 0,  # Screenshot functionality disabled
            'total_businesses': len(businesses)
        })
        
    except Exception as e:
        print(f"Search error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad Request'}), 400

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/download-csv')
def download_csv():
    data = request.args.get('data')
    if not data:
        return jsonify({'error': 'No data provided'}), 400
        
    businesses = json.loads(data)
    df = pd.DataFrame(businesses)
    
    # Convert DataFrame to CSV
    output = io.StringIO()
    df.to_csv(output, index=False)
    
    # Create the response
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'business_data_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.teardown_appcontext
def cleanup(exception=None):
    """Clean up resources when the application context ends."""
    if hasattr(thread_local, "driver"):
        try:
            # thread_local.driver.quit()
            print("WebDriver cleaned up successfully")
        except Exception as e:
            print(f"Error cleaning up WebDriver: {str(e)}")
        finally:
            thread_local.driver = None

@app.route('/upload-to-cloud', methods=['POST'])
def upload_results_to_cloud():
    try:
        # Verify Dropbox configuration
        if not DROPBOX_ACCESS_TOKEN:
            error_msg = "Dropbox access token not found. Please set up Dropbox API first."
            print(f"Error: {error_msg}")
            return jsonify({'error': error_msg}), 400
            
        print(f"Using Dropbox token (first 10 chars): {DROPBOX_ACCESS_TOKEN[:10]}...")
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided in request'}), 400
            
        if 'businesses' not in data:
            return jsonify({'error': 'No businesses data found in request'}), 400
        
        # Create folder path with timestamp
        folder_name = f"/Business_Data_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        print(f"Creating folder: {folder_name}")
        
        try:
            # Create and upload CSV
            businesses_for_csv = []
            for business in data['businesses']:
                business_copy = business.copy()
                if 'screenshot' in business_copy:
                    if isinstance(business_copy['screenshot'], dict):
                        business_copy['screenshot'] = business_copy['screenshot'].get('filename', '')
                    else:
                        business_copy['screenshot'] = ''
                businesses_for_csv.append(business_copy)
            
            # Create CSV file
            csv_path = f"temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            print(f"Creating CSV file: {csv_path}")
            df = pd.DataFrame(businesses_for_csv)
            df.to_csv(csv_path, index=False)
            
            if not os.path.exists(csv_path):
                return jsonify({'error': 'Failed to create CSV file'}), 500
            
            try:
                # Upload CSV
                print("Uploading CSV file...")
                csv_link = upload_to_dropbox(csv_path, folder_name)
                
                # Upload screenshots
                screenshot_links = []
                for business in data['businesses']:
                    if business.get('screenshot') and isinstance(business['screenshot'], dict):
                        screenshot_path = business['screenshot'].get('filename')
                        if screenshot_path and os.path.exists(screenshot_path):
                            print(f"Uploading screenshot: {screenshot_path}")
                            link = upload_to_dropbox(screenshot_path, folder_name)
                            if link:
                                screenshot_links.append({
                                    'business_name': business.get('name', 'Unknown'),
                                    'link': link
                                })
                
                print("All files uploaded successfully")
                return jsonify({
                    'success': True,
                    'folder_name': folder_name,
                    'csv_link': csv_link,
                    'screenshot_links': screenshot_links
                })
                
            except Exception as e:
                print(f"Upload error: {str(e)}")
                return jsonify({'error': f'Upload failed: {str(e)}'}), 500
                
            finally:
                # Clean up temporary CSV file
                if os.path.exists(csv_path):
                    os.remove(csv_path)
                    print(f"Cleaned up temporary file: {csv_path}")
                
        except Exception as e:
            print(f"Error processing upload: {str(e)}")
            if os.path.exists(csv_path):
                os.remove(csv_path)
            return jsonify({'error': str(e)}), 500
            
    except Exception as e:
        print(f"Error in upload_results_to_cloud: {str(e)}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

def search_places(location, keyword, page_token=None):
    """Search places using Places API v2."""
    try:
        # Check if API key is available
        api_key = os.getenv('GOOGLE_PLACES_API_KEY')
        if not api_key:
            print("Error: Google Places API key not found in environment variables")
            return None

        print(f"\n=== Starting search for '{keyword}' in '{location}' ===")
        print(f"Using API key (first 10 chars): {api_key[:10]}...")
        
        # First, get location coordinates using Geocoding API
        geocode_url = f"https://maps.googleapis.com/maps/api/geocode/json?address={quote(location)}&key={api_key}"
        print(f"Geocoding URL: {geocode_url}")
        
        try:
            geocode_response = requests.get(geocode_url)
            print(f"Geocoding Response Status: {geocode_response.status_code}")
            
            geocode_response.raise_for_status()
            geocode_data = geocode_response.json()
            
            if not geocode_data.get('results'):
                print(f"No geocoding results found for location: {location}")
                print(f"Full Geocoding API response: {json.dumps(geocode_data, indent=2)}")
                return None
                
            location_data = geocode_data['results'][0]['geometry']['location']
            center_lat, center_lng = location_data['lat'], location_data['lng']
            print(f"Found coordinates: {center_lat}, {center_lng}")
            
            # Define search points in an optimized grid pattern
            radius = 45000  # 45km radius (within 50km limit)
            # Calculate step size to create overlapping circles
            lat_step = 0.6  # Approximately 60km
            lng_step = 0.6
            grid_points = [
                (0, 0),      # Center
                (-1, 0),     # North
                (1, 0),      # South
                (0, -1),     # West
                (0, 1),      # East
                (-1, -1),    # Northwest
                (-1, 1),     # Northeast
                (1, -1),     # Southwest
                (1, 1),      # Southeast
                (-2, 0),     # Far North
                (2, 0),      # Far South
                (0, -2),     # Far West
                (0, 2),      # Far East
                (-2, -1),    # Far Northwest
                (-2, 1),     # Far Northeast
                (2, -1),     # Far Southwest
                (2, 1),      # Far Southeast
            ]
            
            search_points = [
                (center_lat + lat_step * y, center_lng + lng_step * x)
                for x, y in grid_points
            ]
            
            all_results = []
            seen_place_ids = set()
            max_total_results = 250  # Maximum total results to collect
            
            # Search places using Places API v2 for each point
            for lat, lng in search_points:
                if len(all_results) >= max_total_results:
                    print(f"Reached maximum desired results ({max_total_results})")
                    break
                    
                search_url = "https://places.googleapis.com/v1/places:searchText"
                headers = {
                    "Content-Type": "application/json",
                    "X-Goog-Api-Key": api_key,
                    "X-Goog-FieldMask": "places.id,places.displayName,places.formattedAddress,places.websiteUri,places.internationalPhoneNumber,places.nationalPhoneNumber,nextPageToken"
                }
                
                current_page_token = None
                max_pages_per_point = 3  # Number of pages to fetch per point
                
                for page in range(max_pages_per_point):
                    if len(all_results) >= max_total_results:
                        break
                        
                    data = {
                        "textQuery": f"{keyword} in {location}",
                        "locationBias": {
                            "circle": {
                                "center": {
                                    "latitude": lat,
                                    "longitude": lng
                                },
                                "radius": float(radius)
                            }
                        },
                        "maxResultCount": 20
                    }
                    
                    if current_page_token:
                        data["pageToken"] = current_page_token
                    
                    try:
                        print(f"\nMaking Places API request for coordinates: {lat}, {lng} (page {page + 1})")
                        
                        response = requests.post(search_url, headers=headers, json=data)
                        print(f"Response status code: {response.status_code}")
                        
                        if response.status_code != 200:
                            print(f"Places API Error for point ({lat}, {lng}): {response.status_code}")
                            print(f"Error response: {response.text}")
                            break
                        
                        result = response.json()
                        
                        # Add unique places to results
                        if 'places' in result:
                            new_places = 0
                            for place in result['places']:
                                if place.get('id') not in seen_place_ids:
                                    seen_place_ids.add(place.get('id'))
                                    all_results.append(place)
                                    new_places += 1
                                    if len(all_results) >= max_total_results:
                                        break
                            print(f"Found {new_places} new places at this point (Total: {len(all_results)})")
                            
                            # Check for next page token
                            current_page_token = result.get('nextPageToken')
                            if not current_page_token:
                                print("No more pages available for this point")
                                break
                        else:
                            print("No places found in the response")
                            break
                        
                        # Wait between requests to avoid rate limiting
                        time.sleep(2)
                        
                    except requests.exceptions.RequestException as e:
                        print(f"Request error at point ({lat}, {lng}): {str(e)}")
                        if hasattr(e, 'response') and e.response is not None:
                            print(f"Error response: {e.response.text}")
                        break
                    except Exception as e:
                        print(f"Unexpected error at point ({lat}, {lng}): {str(e)}")
                        break
            
            print(f"\nTotal unique results found: {len(all_results)}")
            return {"places": all_results}
            
        except requests.exceptions.RequestException as e:
            print(f"Geocoding API request error: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Error response: {e.response.text}")
            return None
            
    except Exception as e:
        print(f"Unexpected error in search_places: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return None

def extract_emails(url):
    """Extract email addresses from a website using multiple methods."""
    try:
        print(f"Extracting emails from: {url}")
        emails = set()
        
        # Get session for this thread
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        # Set headers to mimic a browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Try to get the webpage content
        response = session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Method 1: Extract from text content
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Get text content
        text = soup.get_text()
        
        # Find email addresses using regex
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        text_emails = set(re.findall(email_pattern, text))
        emails.update(text_emails)
        
        # Method 2: Extract from links
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('mailto:'):
                email = href.replace('mailto:', '').split('?')[0]
                emails.add(email)
        
        # Method 3: Check common contact page URLs
        contact_paths = ['/contact', '/contact-us', '/about', '/about-us']
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for path in contact_paths:
            try:
                contact_url = urljoin(base_url, path)
                if contact_url != url:  # Avoid re-scraping the same page
                    print(f"Checking contact page: {contact_url}")
                    contact_response = session.get(contact_url, headers=headers, timeout=30)
                    if contact_response.status_code == 200:
                        contact_soup = BeautifulSoup(contact_response.text, 'html.parser')
                        
                        # Extract from text
                        for script in contact_soup(["script", "style"]):
                            script.decompose()
                        contact_text = contact_soup.get_text()
                        contact_emails = set(re.findall(email_pattern, contact_text))
                        emails.update(contact_emails)
                        
                        # Extract from mailto links
                        for link in contact_soup.find_all('a', href=True):
                            href = link['href']
                            if href.startswith('mailto:'):
                                email = href.replace('mailto:', '').split('?')[0]
                                emails.add(email)
            except Exception as e:
                print(f"Error checking contact page {path}: {str(e)}")
                continue
        
        # Filter and validate emails
        filtered_emails = set()
        for email in emails:
            email = email.lower().strip()
            try:
                # Basic validation
                if (
                    len(email) <= 100 and  # Not too long
                    '.' in email.split('@')[1] and  # Has a proper domain
                    not any(x in email.lower() for x in ['example', 'test', 'sample', 'domain', 'email']) and  # Not example emails
                    all(c.isascii() for c in email) and  # Only ASCII characters
                    re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email)  # Strict email format
                ):
                    # Additional validation: Check domain has valid TLD
                    domain = email.split('@')[1]
                    if len(domain.split('.')) >= 2 and len(domain.split('.')[-1]) >= 2:
                        filtered_emails.add(email)
            except Exception:
                continue
        
        print(f"Found {len(filtered_emails)} valid emails")
        return list(filtered_emails)
        
    except Exception as e:
        print(f"Error extracting emails from {url}: {str(e)}")
        return []

def get_driver():
    """Initialize and return a Chrome WebDriver instance."""
    try:
        if not hasattr(thread_local, "driver"):
            print("Initializing Chrome WebDriver...")
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            
            try:
                service = Service(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=chrome_options)
                driver.set_page_load_timeout(30)
                thread_local.driver = driver
                print("Chrome WebDriver initialized successfully")
            except Exception as e:
                print(f"Failed to initialize Chrome WebDriver: {str(e)}")
                raise
        return thread_local.driver
    except Exception as e:
        print(f"Error in get_driver: {str(e)}")
        raise

def capture_screenshot(url):
    """Capture screenshot of a website."""
    if not url:
        return None
        
    print(f"\nAttempting to capture screenshot for: {url}")
    driver = None
    
    try:
        # Ensure screenshots directory exists
        os.makedirs('screenshots', exist_ok=True)
        
        # Get driver
        driver = get_driver()
        
        try:
            print(f"Navigating to URL: {url}")
            driver.get(url)
            time.sleep(2)  # Wait for page load
            
            print("Taking screenshot...")
            screenshot = driver.get_screenshot_as_png()
            
            if not screenshot:
                print("Screenshot capture returned None")
                return None
                
            print("Processing screenshot...")
            img = Image.open(io.BytesIO(screenshot))
            
            # Save screenshot
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"screenshots/{urlparse(url).netloc}_{timestamp}.png"
            img.save(filename, format='PNG', optimize=True, quality=95)
            print(f"Screenshot saved to: {filename}")
            
            # Create thumbnail
            thumb = img.copy()
            thumb.thumbnail((200, 200))
            
            # Convert to base64
            print("Converting to base64...")
            full_buffer = io.BytesIO()
            thumb_buffer = io.BytesIO()
            
            img.save(full_buffer, format='PNG', optimize=True, quality=95)
            thumb.save(thumb_buffer, format='PNG', optimize=True, quality=85)
            
            base64_screenshot = base64.b64encode(full_buffer.getvalue()).decode('utf-8')
            base64_thumbnail = base64.b64encode(thumb_buffer.getvalue()).decode('utf-8')
            
            print("Screenshot processing completed successfully")
            return {
                'full': base64_screenshot,
                'thumbnail': base64_thumbnail,
                'filename': filename
            }
            
        except Exception as e:
            print(f"Error capturing screenshot: {str(e)}")
            return None
            
    except Exception as e:
        print(f"Error in capture_screenshot: {str(e)}")
        return None

def clean_website_url(url):
    """Clean and validate website URL."""
    if not url:
        return None
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    except:
        return None

if __name__ == '__main__':
    try:
        app.run(debug=True)
    finally:
        
        cleanup()
