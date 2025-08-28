# SuperShell AI
<img width="1498" height="127" alt="image" src="https://github.com/user-attachments/assets/4114a628-ed4c-44b9-b7cb-d6904570efba" />

# Description
SuperShell AI is an advanced penetration testing tool that creates highly obfuscated PowerShell reverse shell payloads with integrated AI-powered evasion techniques. This tool leverages DeepSeek AI to generate polymorphic payloads that can bypass modern EDR (Endpoint Detection and Response) solutions and antivirus software.

# Features
🚀 AI-Powered Obfuscation: Utilizes DeepSeek AI to create advanced evasion techniques.

🔀 Multiple Payload Types: Support for standard PowerShell, Nishang-style, and CMD.exe reverse shells.

🛡️ EDR Evasion: Implements techniques like string splitting, encryption, and API unhooking.

🔄 Polymorphic Generation: Creates unique payload signatures with each generation.

💾 Export Options: Save payloads to files with customizable names.

📋 One-Liner Generation: Creates compact commands for easy execution.

# Installation
1. Clone the repository:
```bash
git clone https://github.com/badeeuzzaman/supershellai.git
cd supershellai
```
2. Install required dependencies:
```bash
pip install -r requirements.txt
```
3. Get a DeepSeek API key from https://platform.deepseek.com/

# Usage
Run the script:
```bash
python supershellai.py
```
Follow the interactive prompts to:
1. Enter your listener IP address and port
2. Provide your DeepSeek API key
3. Select generation mode (Basic, AI-powered, or Polymorphic)
4. Choose shell type (PowerShell, Nishang, or CMD)
5. Specify output filename

# Generation Modes
1. Basic Obfuscation: Local obfuscation without API calls
2. AI-Powered Obfuscation: Enhanced obfuscation using DeepSeek AI
3. Polymorphic Generation: Completely unique payload generation using AI

# Shell Types
1. Standard PowerShell: Classic PowerShell reverse shell
2. Nishang-style: Enhanced reverse shell with error handling
3. CMD.exe: Traditional command prompt reverse shell

# Ethical Use Disclaimer
This tool is designed for educational purposes and authorized penetration testing only. Users must ensure they have explicit permission before testing any systems. The developers are not responsible for misuse of this tool.

# Legal Notice
Unauthorized use of this tool against systems without explicit permission is illegal. Always ensure you have proper authorization before conducting any security testing.

# License
This project is licensed under the MIT License - see the LICENSE file for details.

# Support
If you encounter any issues or have questions:
1. Check the existing GitHub issues
2. Create a new issue with detailed information
3. Provide sample code and error messages if applicable

# Screenshot
<img width="1530" height="867" alt="image" src="https://github.com/user-attachments/assets/3dcd84e5-c1c4-4f3c-b507-21bc8bf59a53" />
