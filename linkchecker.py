import tkinter as tk  #GUI library for building the app window
import requests        #Makes HTTP requests to the VirusTotal API
import base64          #Used to encode the URL for the GET request

#API key for VirusTotal
API_KEY = "15dabe6d173f8c2879f8ed722fc9c9a8241c83c21854979ca50f089bacb13acf"  #Replace with your own API key

#Function to scan the URL using VirusTotal API
def scan_url():
    url = url_entry.get().strip()  #Gets URL input from user, removing extra spaces
    if not url:
        status_label.config(text="Please enter a URL.", fg="red")  #User feedback if input is empty
        return

    #Fixes links with "hxxp://" used to obscure real URLs in malware reports
    url = url.replace("hxxp://", "http://").replace("hxxps://", "https://")

    headers = {"x-apikey": API_KEY}  #Sets the API key in headers
    data = {"url": url}  #Data payload for the POST request
    status_label.config(text="Scanning...", fg="blue")  # Shows scanning status
    result_label.config(text="")  #Clears previous results

    try:
        #Step 1: Submits the URL to VirusTotal for scanning
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
        if response.status_code == 200:
            #Step 2: Encodes the URL to create a lookup ID
            encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            #Step 3: Retrieves the scan results for the submitted URL
            result = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)
            stats = result.json()["data"]["attributes"]["last_analysis_stats"]

            #Extracts analysis counts
            harmless = stats['harmless']
            malicious = stats['malicious']
            suspicious = stats['suspicious']
            undetected = stats['undetected']

            #Formats and displays the results in the UI
            result_text = f"""Scan Results:
• Harmless: {harmless} - This link is safe and poses no known threat.
• Malicious: {malicious} - WARNING: This link is dangerous and may infect your PC with malware.
• Suspicious: {suspicious} - Caution: This link is suspicious and may contain threats. Proceed with care.
• Undetected: {undetected} - This link hasn't been tested thoroughly, but could be harmful.
"""
            result_label.config(text=result_text, fg="black")  #Show results
            status_label.config(text="Scan complete.", fg="green")  #Success feedback
        else:
            #Handles HTTP errors (e.g., bad request, API limit)
            status_label.config(text=f"Failed to scan URL: {response.status_code}", fg="red")
    except Exception as e:
        #Catches network or runtime errors
        status_label.config(text=f"Error: {e}", fg="red")

#Function to Toggle Between Light and Dark Themes 
def toggle_theme():
    dark_bg = "#2e2e2e"          #Background color for dark mode
    light_bg = "SystemButtonFace"  #Default OS theme color
    current_bg = root["bg"]      #Get current background
    new_bg = dark_bg if current_bg == light_bg else light_bg
    fg = "white" if new_bg == dark_bg else "black"

    #Apply background and foreground color changes to all widgets
    root.configure(bg=new_bg)
    for widget in root.winfo_children():
        try:
            widget.configure(bg=new_bg, fg=fg)
        except:
            pass  #Some widgets may not accept fg/bg settings
    result_label.config(fg=fg)
    status_label.config(fg=fg)

#GUI app setup
root = tk.Tk()  #Creates the main window
root.title("Malicious Link Checker")  #Sets the window title
root.geometry("600x400")  #Sets the window size
root.resizable(False, False)  #Disable resizing

#Fonts
label_font = ("Segoe UI", 12, "bold")
entry_font = ("Segoe UI", 10)
button_font = ("Segoe UI", 10, "bold")
result_font = ("Courier New", 11, "bold")  #Fixed width font for formatting results

#GUI Widgets
#Instruction label
tk.Label(root, text="Enter a URL to scan:", font=label_font).pack(pady=(20, 5))

#Entry field for the user to type a URL
url_entry = tk.Entry(root, width=52, font=entry_font)
url_entry.pack(pady=5)

#"Scan URL" button to trigger scanning
tk.Button(root, text="Scan URL", command=scan_url, bg="#4CAF50", fg="white", padx=10, pady=6, font=button_font).pack(pady=10)

#"Toggle Dark Mode" button
tk.Button(root, text="Toggle Dark Mode", command=toggle_theme, bg="#444", fg="white", font=button_font).pack()

#Status label (e.g., "Scanning..." or errors)
status_label = tk.Label(root, text="", font=("Segoe UI", 10, "bold"))
status_label.pack(pady=(10, 0))

#Label to display scan results
result_label = tk.Label(root, text="", justify="left", font=result_font, wraplength=550)  # Wraps long text
result_label.pack(pady=10)

#Start the Tkinter event loop
root.mainloop()
