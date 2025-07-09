import requests
import re
import sys
import time
from urllib.parse import quote


NVD_API_KEY = "1ad11ebc-b427-4013-b2c9-680753129a37"
HEADERS = {"apiKey": NVD_API_KEY}


TABLE_WIDTH = 100
CVE_ID_WIDTH = 20
SEVERITY_WIDTH = 8
DESC_WIDTH = 65
GITHUB_API_DELAY = 0.5  # Delay between GitHub API calls

#Calling NVP CPE API with the keyword in order find the list of matches to the input CPE
#Return list of matches
def search_cpe(keyword):
    url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={keyword}"
    resp = requests.get(url, headers = HEADERS)
    
    
    # Check if the request was successful
    if resp.status_code != 200:
        print(f"API Error - Status Code: {resp.status_code}")
        print(f"Response Text: {resp.text}")
        return []
    
    # Check if response is empty
    if not resp.text.strip():
        print("Empty response received")
        return []
    
    # Try to parse JSON
    try:
        data = resp.json()
    except ValueError as e:
        print(f"JSON parsing error: {e}")
        print(f"Response text: {resp.text}")
        return []
    
    
    print(f"Total results found: {data.get('totalResults', 0)}")
    
    # Get products data
    products = data.get("products", [])
    
    CPES = []
    for i, item in enumerate(products):
        cpe_data = item.get("cpe", {})
        
        # Extract title from titles array
        title = ""
        if "titles" in cpe_data and cpe_data["titles"]:
            title = cpe_data["titles"][0].get("title", "")
        
        # Extract CPE URI from cpeName
        cpe_uri = cpe_data.get("cpeName", "")
        
        CPES.append({
            "title": title,
            "cpe23Uri": cpe_uri
        })
    print(f"Found {len(CPES)} CPE entries")

    return CPES
    
    
    
    
#Presenting CPE's options for the user, in order to find the relevant CPE 
#Returns selected CPE 
def select_cpe(cpes):
    if not cpes:
        print("No CPEs found in your keyword.")
        return None
    
    print("\n" + "="*80)
    print("FOUND CPEs:")
    print("="*80)
    
    for i, cpe in enumerate(cpes, 1):
        print(f"{i}. {cpe['title']} ({cpe['cpe23Uri']})")
    print("="*80)
    
    while True:
        try:
            user_input = input("Select CPE by number: ")
            idx = int(user_input) - 1
            if 0 <= idx < len(cpes):
                selected_cpe = cpes[idx]
                print(f"Selected: {selected_cpe['title']} ({selected_cpe['cpe23Uri']})")
                return selected_cpe["cpe23Uri"], selected_cpe["title"]
            else:
                print("Invalid choice, Try Again")
        except ValueError:
            print("Please enter valid number")
            
            
    

#Calling NVD CVE API with cpe_uri in order to find the list of relevant CVE's to the selected CPE
#Return list of CVE's
def fetch_cves_for_cpe(cpe_uri):
    encoded_cpe = quote(cpe_uri, safe='')
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={encoded_cpe}"
    print(f"🌐 Original CPE URI: {cpe_uri}")
    print(f"🌐 Encoded CPE URI: {encoded_cpe}")
    print(f"🌐 Requesting URL: {url}")
    resp = requests.get(url, headers = HEADERS)
    
    
    
    # Check if the request was successful
    if resp.status_code != 200:
        print(f"API Error - Status Code: {resp.status_code}")
        print(f"Response Text: {resp.text}")
        if resp.status_code == 404:
            print("This might mean the CPE doesn't exist in NVD or the format is incorrect")
        return []
    
    # Check if response is empty
    if not resp.text.strip():
        print("Empty response received")
        return []
    
    # Try to parse JSON
    try:
        data = resp.json()
    except ValueError as e:
        print(f"JSON parsing error: {e}")
        print(f"Response text: {resp.text}")
        return []
    
    print(f"Total CVEs found: {data.get('totalResults', 0)}")
    
    
    cves = []
    for item in data.get("vulnerabilities", []):
        cve_data = item["cve"]
        description = cve_data["descriptions"][0]["value"]
        cvss_metrics = cve_data.get("metrics", {}).get("cvssMetricV31", [])
        cvss = cvss_metrics[0]["cvssData"]["baseScore"] if cvss_metrics else "N/A"
        refs = cve_data.get("references", [])
        
        #Checking for github exploits
        github_exploits = []
        for ref in refs:
            url = ref["url"]
            if "github.com" in url.lower():
                tags = ref.get("tags", [])
                tag_text = " ".join(tags).lower()
                url_lower = url.lower()
                
  
                if (any("exploit" in tag.lower() for tag in tags) or
                    any(keyword in url_lower for keyword in ["exploit", "poc", "cve", "vulnerability", "vuln"]) or
                    any(tag in ["Exploit", "Third Party Advisory", "Tool Signature"] for tag in tags)):
                    github_exploits.append(url)
            
            
        
        cves.append({
            "id": cve_data["id"],
            "cvss": cvss,
            "description": description,
            "github_exploits": github_exploits
        })
    return cves




#Calling GitHub API in order to get the popularity
def fetch_github_pop(github_url):
    time.sleep(GITHUB_API_DELAY)
    m = re.match(r"https://github.com/([^/]+)/([^/]+)/?", github_url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    resp = requests.get(api_url)
    if resp.status_code != 200:
        return None
    data = resp.json()
    return {
        "stars": data.get("stargazers_count", 0),
        "forks": data.get("forks_count", 0)
    }


# Converting star count into visual star rating
def get_star_rating(stars):
    if stars >= 1000:
        return "⭐⭐⭐⭐⭐"
    elif stars >= 500:
        return "⭐⭐⭐⭐"
    elif stars >= 100:
        return "⭐⭐⭐"
    elif stars >= 50:
        return "⭐⭐"
    elif stars >= 10:
        return "⭐"
    else:
        return "○"
    


#Remove duplicate URLs from the list
def remove_duplicate_urls(github_exploits):

    seen = set()
    unique_exploits = []
    for url in github_exploits:
        if url not in seen:
            seen.add(url)
            unique_exploits.append(url)
    return unique_exploits



# Filtering CVE's by their CVSS score
def filter_cves_by_cvss(cves, min_score):
    return [cve for cve in cves if cve["cvss"] != "N/A" and float(cve["cvss"]) >= min_score]   

 

# Display vulnerabilitis in the foramtted table
def display_vulnerabilities(cves, cpe_title):
    print(f"\n🔍 Vulnerabilities found for {cpe_title}:")
    print("="*TABLE_WIDTH)
    
    # Table header
    print(f"| {'CVE ID':<{CVE_ID_WIDTH}} | {'Severity':<{SEVERITY_WIDTH}} | {'Description':<{DESC_WIDTH}} |")
    print("="*TABLE_WIDTH)
    
    for cve in cves:
        cve_id = cve['id']
        severity = str(cve['cvss'])
        desc = cve['description']
        first_line = desc.split('\n')[0][:DESC_WIDTH]
        print(f"| {cve_id:<{CVE_ID_WIDTH}} | {severity:<{SEVERITY_WIDTH}} | {first_line:<{DESC_WIDTH}} |")
        # Print full description (indented) if it's longer
        if len(desc) > DESC_WIDTH or '\n' in desc:
            for line in desc[DESC_WIDTH:].split('\n'):
                print(f"| {'':<{CVE_ID_WIDTH}} | {'':<{SEVERITY_WIDTH}} | {line.strip():<{DESC_WIDTH}} |")

        
        # Handle GitHub exploits
        if cve["github_exploits"]:
            unique_exploits = remove_duplicate_urls(cve["github_exploits"])
            print(f"| {'':<{CVE_ID_WIDTH}} | {'':<{SEVERITY_WIDTH}} | {'GitHub Resources:':<{DESC_WIDTH}} |")
            
            # Gather all exploits with their popularity
            exploit_infos = []
            for url in unique_exploits:
                pop = fetch_github_pop(url)
                if pop:
                    stars = pop['stars']
                    forks = pop['forks']
                    repo_name = url.split('/')[-1] if '/' in url else url
                    exploit_infos.append((stars, forks, url, repo_name, pop))
                else:
                    repo_name = url.split('/')[-1] if '/' in url else url
                    exploit_infos.append((0, 0, url, repo_name, None))

            # Sort by stars in a descending order
            exploit_infos.sort(reverse=True, key=lambda x: x[0])

            # print the exploit links
            for stars, forks, url, repo_name, pop in exploit_infos:
                if pop:
                    star_rating = get_star_rating(stars)
                    resource_line = f"- {repo_name} ({star_rating} - {stars} stars, {forks} forks)"
                else:
                    resource_line = f"- {repo_name} (⚠️ - Unable to fetch stats)"
                print(f"| {'':<{CVE_ID_WIDTH}} | {'':<{SEVERITY_WIDTH}} | {resource_line:<{DESC_WIDTH}} |")
        
        print("-"*TABLE_WIDTH)
    
    print("="*TABLE_WIDTH)

def safe_input(prompt):
    user_input = input(prompt)
    if user_input.lower() == 'q':
        print("👋 Exiting the program.")
        sys.exit()
    return user_input

def main():
    while True:
        keyword = safe_input("Enter software/hardware name (e.g., 'log4j') or 'q' to quit: ")
        
        # Check if keyword is empty
        if not keyword or not keyword.strip():
            print("Keyword cannot be empty, Please enter a valid keyword")
            continue
        
        # Validate keyword length
        if len(keyword.strip()) > 100:
            print("Keyword too long (max 100 characters), Please enter a shorter keyword")
            continue
        
        keyword = keyword.strip()
        break
    
    
    print(f"\n🔎 Searching for CPEs matching '{keyword}'...")
    cpe_matches = search_cpe(keyword)
    
    if not cpe_matches:
        print("No CPEs found")
        return

    
    
    chosen_cpe_result = select_cpe(cpe_matches)
    if not chosen_cpe_result:
        print("No CPE selected")
        return
    cpe_uri, cpe_title = chosen_cpe_result
    
    cves = fetch_cves_for_cpe(cpe_uri)
    if not cves:
        print("No CVEs found for this CPE")
        return
    
    display_vulnerabilities(cves, cpe_title)
    
    #Asking the user if he ant to filter by severity
    while True:
        try:
            filter_choice = safe_input("Filter by CVSS score? (y/n) or 'q' to quit:").lower()
            if filter_choice == 'y':
                while True:
                    try:   
                        min_score = float(input("Enter minimum CVSS score (For Example: 9.0)"))
                        if 0 <= min_score <= 10.0:
                            filterd_cves = filter_cves_by_cvss(cves, min_score)
                            if not filterd_cves:
                                print("No CVE's above that score")
                                return
                            print(f"Filterd to {len(filterd_cves)} CVEs with CVSS >= {min_score}")
                            display_vulnerabilities(filterd_cves, cpe_title)
                            return
                        else:
                            print("Invalid number, try number between 0 to 10") 
                    except ValueError:
                        print("Invalid input. Please enter a valid number")
            elif filter_choice == 'n':
                display_vulnerabilities(cves, cpe_title)   
                return
            else:
                print("Please enter 'y', 'n' or 'q'")
        except ValueError:
            print("Please enter 'y' or 'n', or quit in order to exit")
                    
                 
        
    
        
    
    

        
    
if __name__ == "__main__":
    main()
        
    
    