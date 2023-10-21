import streamlit as st
import pickle
from urllib.parse import urlparse
from tld import get_tld
import re
import numpy as np

# Load the trained model from the pickle file
model_file_name = "malicious_model.pkl"
with open(model_file_name, "rb") as model_file:
    rf = pickle.load(model_file)

st.title("Malicious URL Detector")

# Create an input field for users to enter a URL
url = st.text_input("Enter a URL")
def main(url):
    status = []

    def having_ip_address(url):
        # Check if the URL has an IP address
        match = re.search(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5]))', url)
        if match:
            return 1
        else:
            return 0

    def abnormal_url(url):
        hostname = urlparse(url).hostname
        if hostname and hostname in url:
            return 1
        else:
            return 0



    def google_index(url):
        site = search(url, 5)
        return 1 if site else 0

    def count_dot(url):
        return url.count('.')

    def count_www(url):
        return url.count('www')

    def count_atrate(url):
        return url.count('@')

    def no_of_dir(url):
        urldir = urlparse(url).path
        return urldir.count('/')

    def no_of_embed(url):
        urldir = urlparse(url).path
        return urldir.count('//')

    def shortening_service(url):
        match = re.search(
            r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
            r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
            r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
            r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
            r'tr\.im|link\.zip\.net', url)
        if match:
            return 1
        else:
            return 0

    def count_https(url):
        return url.count('https')

    def count_http(url):
        return url.count('http')

    def count_per(url):
        return url.count('%')

    def count_ques(url):
        return url.count('?')

    def count_hyphen(url):
        return url.count('-')

    def count_equal(url):
        return url.count('=')

    def url_length(url):
        return len(url)

    def hostname_length(url):
        return len(urlparse(url).netloc)

    def suspicious_words(url):
        match = re.search(
            r'PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url)
        if match:
            return 1
        else:
            return 0

    def digit_count(url):
        digits = 0
        for i in url:
            if i.isnumeric():
                digits += 1
        return digits

    def letter_count(url):
        letters = 0
        for i in url:
            if i.isalpha():
                letters += 1
        return letters

    def fd_length(url):
        urlpath = urlparse(url).path
        try:
            return len(urlpath.split('/')[1])
        except:
            return 0

    def tld_length(tld):
        try:
            return len(tld)
        except:
            return -1

    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))
    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url, fail_silently=True)
    status.append(tld_length(tld))
    
    return status

    
    return status

def get_prediction_from_url(test_url):
    features_test = main(test_url)
    features_test = np.array(features_test).reshape((1, -1))

    pred = rf.predict(features_test)
    if int(pred[0]) == 0:
        res = "SAFE"
    elif int(pred[0]) == 1.0:
        res = "DEFACEMENT"
    elif int(pred[0]) == 2.0:
        res = "PHISHING"
    elif int(pred[0]) == 3.0:
        res = "MALWARE"
    
    return res

if st.button("Check"):
    if url:
        prediction = get_prediction_from_url(url)
        st.write(f"This URL is: {prediction}")

# Run the Streamlit app
if __name__ == '__main__':
    st.write("Enter a URL to check if it's malicious or safe.")
