from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from PIL import Image
import io
import os
import time

def test_screenshot():
    print("Starting screenshot test...")
    
    # Create screenshots directory
    os.makedirs('screenshots', exist_ok=True)
    
    # Set up Chrome options
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    
    try:
        print("Initializing Chrome WebDriver...")
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(30)
        
        # Test URL
        test_url = "https://www.google.com"
        print(f"Navigating to {test_url}...")
        
        driver.get(test_url)
        time.sleep(2)  # Wait for page load
        
        print("Taking screenshot...")
        screenshot = driver.get_screenshot_as_png()
        
        if screenshot:
            print("Screenshot captured successfully")
            
            # Save the screenshot
            img = Image.open(io.BytesIO(screenshot))
            filename = "screenshots/test_screenshot.png"
            img.save(filename)
            print(f"Screenshot saved to: {filename}")
            
            return True
        else:
            print("Failed to capture screenshot")
            return False
            
    except Exception as e:
        print(f"Error during test: {str(e)}")
        return False
    finally:
        try:
            driver.quit()
            print("WebDriver cleaned up")
        except:
            pass

if __name__ == "__main__":
    success = test_screenshot()
    print(f"\nTest {'passed' if success else 'failed'}") 