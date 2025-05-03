import requests
import dns.resolver
import argparse
import concurrent.futures
from datetime import datetime
from tqdm import tqdm

VULNERABLE_SERVICES = {
    'aws': ['cloudfront.net', 's3.amazonaws.com', 'amazonaws.com'],
    'github': ['github.io', 'github.com', 'github.map.fastly.net'],
    'heroku': ['herokuapp.com', 'herokussl.com', 'herokudns.com'],
    'shopify': ['myshopify.com'],
    'fastly': ['fastly.net'],
    'azure': ['azurewebsites.net', 'cloudapp.net'],
    'google': ['googleusercontent.com', 'withgoogle.com'],
    'wordpress': ['wordpress.com', 'wpengine.com'],
    'tumblr': ['tumblr.com'],
    'zendesk': ['zendesk.com'],
    'unbounce': ['unbouncepages.com'],
    'helpjuice': ['helpjuice.com'],
    'help-scout': ['helpscoutdocs.com'],
    'cargocollective': ['cargocollective.com'],
    'surge': ['surge.sh'],
    'readme': ['readme.io'],
    'bitbucket': ['bitbucket.io'],
    'netlify': ['netlify.app', 'netlify.com'],
    'firebase': ['firebaseapp.com', 'web.app'],
    'ghost': ['ghost.io'],
    'pantheon': ['pantheonsite.io'],
    'intercom': ['intercom.help'],
    'webflow': ['webflow.io'],
    'teamwork': ['teamwork.com'],
    'tilda': ['tilda.ws', 'tilda.zone'],
    'wix': ['wix.com', 'wixsite.com'],
    'youtube': ['youtube.com'],
    'statuspage': ['statuspage.io'],
    'readthedocs': ['readthedocs.io'],
    'launchrock': ['launchrock.com'],
    'feedpress': ['feedpress.me'],
    'freshdesk': ['freshdesk.com'],
    'desk': ['desk.com'],
    'zoho': ['zohodesk.com'],
    'pingdom': ['stats.pingdom.com'],
    'uptimerobot': ['uptimerobot.com'],
    'logentries': ['logentries.com'],
    'cloudapp': ['cloudapp.azure.com'],
    'azureedge': ['azureedge.net'],
    'azure-api': ['azure-api.net'],
    'azurecontainer': ['azurecontainer.io'],
    'azurecr': ['azurecr.io'],
    'azuredatalake': ['azuredatalakestore.net'],
    'azurehdinsight': ['azurehdinsight.net'],
    'microsoftonline': ['microsoftonline.com'],
    'office': ['office.com'],
    'outlook': ['outlook.com'],
    'sharepoint': ['sharepoint.com'],
    'visualstudio': ['visualstudio.com'],
    'vsts': ['vsts.me'],
    'appveyor': ['appveyor.com'],
    'gitbook': ['gitbook.io'],
    'smartling': ['smartling.com'],
    'acquia': ['acquia-test.co', 'acquia-sites.com'],
    'prismic': ['prismic.io'],
    'vend': ['vendhq.com'],
    'bigcartel': ['bigcartel.com'],
    'activehosted': ['activehosted.com'],
    'agile': ['agilecrm.com'],
    'aha': ['aha.io'],
    'airtable': ['airtable.com'],
    'aos': ['aos-operations.com'],
    'apigee': ['apigee.net'],
    'asana': ['asana.com'],
    'assembla': ['assembla.com'],
    'atlassian': ['atlassian.net'],
    'basecamp': ['basecamp.com'],
    'bubble': ['bubbleapps.io'],
    'cage': ['cageapp.com'],
    'campaignmonitor': ['createsend.com'],
    'canny': ['canny.io'],
    'chartbeat': ['chartbeat.com'],
    'chartio': ['chartio.com'],
    'cloudant': ['cloudant.com'],
    'cloudflare': ['cloudflare.com'],
    'codepen': ['codepen.io'],
    'copper': ['copper.com'],
    'crisp': ['crisp.chat'],
    'customer': ['customer.io'],
    'datadog': ['datadoghq.com'],
    'digitalocean': ['digitalocean.com'],
    'discourse': ['discourse.org'],
    'dnsimple': ['dnsimple.com'],
    'docean': ['docean.com'],
    'docusign': ['docusign.net'],
    'drift': ['drift.com'],
    'dropbox': ['dropbox.com'],
    'dropsource': ['dropsource.com'],
    'elastic': ['elastic.co'],
    'envato': ['envato.com'],
    'front': ['frontapp.com'],
    'gengo': ['gengo.com'],
    'getresponse': ['getresponse.com'],
    'gitlab': ['gitlab.io'],
    'gocd': ['gocd.io'],
    'godsaddy': ['godsaddy.com'],
    'gosquared': ['gosquared.com'],
    'grove': ['grove.io'],
    'gsuite': ['gsuite.com'],
    'helpsite': ['helpsite.io'],
    'hubspot': ['hubspot.com'],
    'invision': ['invisionapp.com'],
    'jekyll': ['jekyllrb.com'],
    'jira': ['jira.com'],
    'kajabi': ['kajabi.com'],
    'kanban': ['kanbanize.com'],
    'kissmetrics': ['kissmetrics.com'],
    'klaviyo': ['klaviyo.com'],
    'launchdarkly': ['launchdarkly.com'],
    'livechat': ['livechatinc.com'],
    'loggly': ['loggly.com'],
    'looker': ['looker.com'],
    'mailchimp': ['mailchimp.com'],
    'mandrill': ['mandrillapp.com'],
    'mavenlink': ['mavenlink.com'],
    'medium': ['medium.com'],
    'mixpanel': ['mixpanel.com'],
    'mode': ['modeanalytics.com'],
    'monday': ['monday.com'],
    'myjetbrains': ['myjetbrains.com'],
    'newrelic': ['newrelic.com'],
    'ngrok': ['ngrok.io'],
    'npm': ['npmjs.com'],
    'olark': ['olark.com'],
    'optimizely': ['optimizely.com'],
    'pardot': ['pardot.com'],
    'pipedrive': ['pipedrive.com'],
    'postmark': ['postmarkapp.com'],
    'printful': ['printful.com'],
    'proofpoint': ['proofpoint.com'],
    'pusher': ['pusher.com'],
    'raygun': ['raygun.com'],
    'rollbar': ['rollbar.com'],
    'rubygems': ['rubygems.org'],
    'saucelabs': ['saucelabs.com'],
    'sendgrid': ['sendgrid.com'],
    'servicenow': ['servicenow.com'],
    'sift': ['sift.com'],
    'slack': ['slack.com'],
    'smugmug': ['smugmug.com'],
    'squarespace': ['squarespace.com'],
    'stripe': ['stripe.com'],
    'sumo': ['sumo.com'],
    'surveymonkey': ['surveymonkey.com'],
    'thinkific': ['thinkific.com'],
    'tictail': ['tictail.com'],
    'typeform': ['typeform.com'],
    'uberflip': ['uberflip.com'],
    'uservoice': ['uservoice.com'],
    'wistia': ['wistia.com'],
    'workable': ['workable.com'],
    'wpengine': ['wpengine.com'],
    'zoom': ['zoom.us'],
}

def check_cname(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).rstrip('.')
            for service, patterns in VULNERABLE_SERVICES.items():
                for pattern in patterns:
                    if pattern in cname:
                        return (subdomain, cname, service, True)
            return (subdomain, cname, None, False)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
        return (subdomain, None, None, False)
    except Exception as e:
        return (subdomain, None, None, False)

def check_http_response(subdomain):
    try:
        url = f"http://{subdomain}"
        response = requests.get(url, timeout=10, allow_redirects=True)
        return response.status_code
    except requests.exceptions.SSLError:
        try:
            url = f"https://{subdomain}"
            response = requests.get(url, timeout=10, allow_redirects=True)
            return response.status_code
        except:
            return None
    except:
        return None

def check_subdomain(subdomain):
    cname_info = check_cname(subdomain)
    http_status = check_http_response(subdomain)
    
    is_vulnerable = False
    if cname_info[3]:  # If CNAME points to a vulnerable service
        if http_status in [404, 403, 400, 503, 500, None]:
            is_vulnerable = True
    
    return {
        'subdomain': subdomain,
        'cname': cname_info[1],
        'service': cname_info[2],
        'http_status': http_status,
        'vulnerable': is_vulnerable
    }

def scan_subdomains(subdomains, threads=10):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in subdomains}
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(subdomains), desc="Scanning subdomains", unit="subdomain"):
            subdomain = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                tqdm.write(f"Error processing {subdomain}: {e}")
    return results

def generate_html_report(results, filename="report.html"):
    """Generate a complete HTML report with styling and interactive elements"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    vulnerable_count = sum(1 for r in results if r['vulnerable'])
    
    # CSS styling
    css = """
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2 {
            color: #2c3e50;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            position: sticky;
            top: 0;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .vulnerable-yes {
            color: #e74c3c;
            font-weight: bold;
        }
        .vulnerable-no {
            color: #27ae60;
        }
        .summary-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-stats {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
        }
        .stat-box {
            background: white;
            border-radius: 6px;
            padding: 15px;
            margin: 10px 0;
            flex: 1;
            min-width: 200px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            margin: 10px 0;
        }
        .vulnerable-list {
            background: #fff8f8;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #e74c3c;
        }
        .filter-controls {
            margin: 20px 0;
            padding: 15px;
            background: #f0f7ff;
            border-radius: 6px;
        }
        .search-box {
            padding: 8px;
            width: 100%;
            max-width: 400px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
    </style>
    """
    
    # JavaScript for interactivity
    js = """
    <script>
        function filterTable() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toLowerCase();
            const table = document.getElementById('resultsTable');
            const tr = table.getElementsByTagName('tr');
            
            for (let i = 1; i < tr.length; i++) {
                const td = tr[i].getElementsByTagName('td');
                let showRow = false;
                
                for (let j = 0; j < td.length; j++) {
                    if (td[j]) {
                        const txtValue = td[j].textContent || td[j].innerText;
                        if (txtValue.toLowerCase().indexOf(filter) > -1) {
                            showRow = true;
                            break;
                        }
                    }
                }
                
                tr[i].style.display = showRow ? '' : 'none';
            }
        }
        
        function filterByVulnerability() {
            const filter = document.getElementById('vulnFilter').value;
            const table = document.getElementById('resultsTable');
            const tr = table.getElementsByTagName('tr');
            
            for (let i = 1; i < tr.length; i++) {
                const vulnerableCell = tr[i].getElementsByClassName('vulnerable-cell')[0];
                if (!vulnerableCell) continue;
                
                const isVulnerable = vulnerableCell.textContent.trim() === 'YES';
                
                if (filter === 'all' || 
                    (filter === 'vulnerable' && isVulnerable) || 
                    (filter === 'safe' && !isVulnerable)) {
                    tr[i].style.display = '';
                } else {
                    tr[i].style.display = 'none';
                }
            }
        }
    </script>
    """
    
    # Vulnerable subdomains list
    vulnerable_list = ""
    vulnerable_subs = [r for r in results if r['vulnerable']]
    if vulnerable_subs:
        vulnerable_list = "<h3>⚠️ Vulnerable Subdomains</h3><ul>"
        for sub in vulnerable_subs:
            vulnerable_list += f"""
            <li>
                <strong>{sub['subdomain']}</strong> 
                (Service: {sub['service']}, CNAME: {sub['cname']}, Status: {sub['http_status']})
            </li>
            """
        vulnerable_list += "</ul>"
    else:
        vulnerable_list = "<p>No vulnerable subdomains found.</p>"
    
    # HTML structure
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Subdomain Takeover Scan Report</title>
        {css}
    </head>
    <body>
        <h1>Subdomain Takeover Scan Report</h1>
        <p>Generated on: {timestamp}</p>
        
        <div class="summary-card">
            <h2>Scan Summary</h2>
            <div class="summary-stats">
                <div class="stat-box">
                    <div>Total Subdomains</div>
                    <div class="stat-value">{len(results)}</div>
                </div>
                <div class="stat-box">
                    <div>Potentially Vulnerable</div>
                    <div class="stat-value" style="color: {'#e74c3c' if vulnerable_count > 0 else '#27ae60'}">
                        {vulnerable_count}
                    </div>
                </div>
                <div class="stat-box">
                    <div>Vulnerability Rate</div>
                    <div class="stat-value">
                        {(vulnerable_count/len(results)*100 if len(results) > 0 else 0):.2f}%
                    </div>
                </div>
            </div>
        </div>
        
        <div class="filter-controls">
            <h3>Filter Results</h3>
            <input type="text" id="searchInput" class="search-box" onkeyup="filterTable()" 
                   placeholder="Search for subdomains, services...">
            
            <select id="vulnFilter" onchange="filterByVulnerability()" style="margin-left: 10px; padding: 8px;">
                <option value="all">Show All</option>
                <option value="vulnerable">Only Vulnerable</option>
                <option value="safe">Only Safe</option>
            </select>
        </div>
        
        <h2>Detailed Results</h2>
        <table id="resultsTable">
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>CNAME</th>
                    <th>Service</th>
                    <th>HTTP Status</th>
                    <th>Vulnerable</th>
                </tr>
            </thead>
            <tbody>
    """
    
    # Add table rows
    for result in results:
        vulnerable_class = "vulnerable-yes" if result['vulnerable'] else "vulnerable-no"
        vulnerable_text = "YES" if result['vulnerable'] else "NO"
        http_status = str(result['http_status']) if result['http_status'] is not None else "N/A"
        
        html += f"""
                <tr>
                    <td>{result['subdomain']}</td>
                    <td>{result['cname'] or 'N/A'}</td>
                    <td>{result['service'] or 'N/A'}</td>
                    <td>{http_status}</td>
                    <td class="vulnerable-cell {vulnerable_class}">{vulnerable_text}</td>
                </tr>
        """
    
    # Close HTML
    html += f"""
            </tbody>
        </table>
        
        <div class="vulnerable-list">
            {vulnerable_list}
        </div>
        
        {js}
    </body>
    </html>
    """
    
    # Write to file
    with open(filename, 'w') as f:
        f.write(html)

def print_results(results, output_file=None, html_file=None):
    output = []
    output.append("\nScan Results:")
    output.append("-" * 80)
    output.append(f"{'Subdomain':<40} {'CNAME':<40} {'Service':<15} {'HTTP Status':<12} {'Vulnerable'}")
    output.append("-" * 80)
    
    for result in results:
        vulnerable = "YES" if result['vulnerable'] else "NO"
        http_status = str(result['http_status']) if result['http_status'] is not None else "N/A"
        output.append(f"{result['subdomain']:<40} {result['cname'] or 'N/A':<40} {result['service'] or 'N/A':<15} {http_status:<12} {vulnerable}")

    # Print to terminal
    print("\n".join(output))
    
    # Save to TXT file if specified
    if output_file:
        with open(output_file, 'w') as f:
            f.write("\n".join(output))
            f.write("\n\n=== Vulnerable Subdomains Summary ===\n")
            vulnerable_subs = [r for r in results if r['vulnerable']]
            if vulnerable_subs:
                for sub in vulnerable_subs:
                    f.write(f"{sub['subdomain']} (Service: {sub['service']}, CNAME: {sub['cname']}, Status: {sub['http_status']})\n")
            else:
                f.write("No vulnerable subdomains found.\n")
            
            f.write(f"\nScan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total subdomains scanned: {len(results)}\n")
            f.write(f"Potentially vulnerable: {len(vulnerable_subs)}\n")
    
    # Generate HTML report if specified
    if html_file:
        generate_html_report(results, html_file)
        print(f"\nHTML report generated: {html_file}")

def main():
    parser = argparse.ArgumentParser(description="Subdomain Takeover Scanner")
    parser.add_argument("-l", "--list", help="File containing list of subdomains", required=True)
    parser.add_argument("-t", "--threads", help="Number of threads to use (default: 10)", type=int, default=10)
    parser.add_argument("-o", "--output", help="Output TXT file (default: takeover_results.txt)", default="takeover_results.txt")
    parser.add_argument("--html", help="Output HTML file (default: takeover_report.html)", default="takeover_report.html")
    args = parser.parse_args()

    with open(args.list, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]

    print(f"\nStarting scan of {len(subdomains)} subdomains using {args.threads} threads...\n")
    results = scan_subdomains(subdomains, args.threads)
    print_results(results, args.output, args.html)
    
    vulnerable = sum(1 for r in results if r['vulnerable'])
    print(f"\nFound {vulnerable} potentially vulnerable subdomains out of {len(results)} scanned.")
    print(f"Text results saved to {args.output}")
    print(f"HTML report saved to {args.html}")

if __name__ == "__main__":
    main()