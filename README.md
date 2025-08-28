<p align="center">
  <img src="https://github.com/user-attachments/assets/14b2c4c2-4a11-4bea-85de-fa660dfe591e" alt="InzelSec Logo" width="150"/>
</p>


# Port Scanner

A Python implementation of a simple **TCP connect() port scanner**.  
(like Nmap)

---

## Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/InzelSec/port-scanner.git
cd port-scanner
chmod +x port_scanner.py
```

## Usage

Scan common ports on a host:
```
python3 port_scanner.py target.com
```
Scan specific ports:
```
python3 port_scanner.py target.com -p 22,80,443
```
Scan a port range:
```
python3 port_scanner.py target.com -p 20-25
```
Set aggressiveness level (like Nmap -T1..-T5, default is -T3):
```
python3 port_scanner.py target.com -p 1-100 -T4
```
Show ALL results (open + closed):
```
python3 port_scanner.py target.com --show-all
```

## Output example:

<img width="890" height="318" alt="Screenshot 2025-08-28 at 10 30 41" src="https://github.com/user-attachments/assets/76fa0c00-2d07-44c9-826f-7e3a51b85a47" />
