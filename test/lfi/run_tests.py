#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 The NASM Authors - All Rights Reserved

import os
import sys
import subprocess
import re

def parse_check_lines(filepath):
    """
    Parses CHECK, CHECK-NEXT, and CHECK-NOT assertions from the file.
    Assertions are comments starting with:
      ; CHECK: <pattern>
      ; CHECK-NEXT: <pattern>
      ; CHECK-NOT: <pattern>
    """
    assertions = []
    run_line = None
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line.startswith(';'):
                continue
            
            # Parse RUN line
            if 'RUN:' in line:
                match = re.search(r'RUN:\s*(.*)', line)
                if match:
                    run_line = match.group(1)
                continue
                
            # Parse CHECK assertions
            check_match = re.match(r'^;\s*(CHECK|CHECK-NEXT|CHECK-NOT):\s*(.*)', line)
            if check_match:
                assert_type = check_match.group(1)
                pattern = check_match.group(2).strip()
                
                # Normalize spaces in pattern
                pattern = re.sub(r'\s+', ' ', pattern)
                # Remove register/offset formatting differences if any
                # (e.g. replace commas with space-comma, etc.)
                
                assertions.append((assert_type, pattern))
                
    return run_line, assertions

def get_disassembly(obj_path):
    """
    Disassembles the .text section of the object file using objdump -d -M intel
    Returns a list of instruction strings, normalized.
    """
    try:
        result = subprocess.run(
            ['objdump', '-d', '-M', 'intel', obj_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error running objdump: {e.stderr}")
        return None

    instructions = []
    lines = result.stdout.split('\n')
    
    # Example objdump line:
    #    0:	41 5b                	pop    r11
    #   14:	4d 8d 3c 3e          	lea    r15,[r14+rdi]
    # We want to extract only the mnemonic and operands (e.g. "pop r11")
    for line in lines:
        line = line.strip()
        if not line or ':' not in line:
            continue
        
        parts = line.split('\t')
        if len(parts) < 3:
            continue
            
        # The instruction text is the last part (strip address and hex bytes)
        inst_text = parts[-1].strip()
        # Normalize spaces
        inst_text = re.sub(r'\s+', ' ', inst_text)
        # Normalize commas (remove spaces around commas for consistency)
        inst_text = inst_text.replace(' ,', ',').replace(', ', ',')
        
        # Strip comments from objdump (e.g. "jmp r11 <.text+0x9>" or "# 0xa")
        inst_text = re.sub(r'\s*<.*>', '', inst_text)
        inst_text = inst_text.split('#')[0].strip()
        
        instructions.append(inst_text)
        
    return instructions

def verify_assertions(instructions, assertions):
    """
    Verifies the disassembled instructions against the FileCheck-like assertions.
    """
    inst_idx = 0
    num_insts = len(instructions)
    
    for assert_idx, (assert_type, pattern) in enumerate(assertions):
        # Escape pattern for regex, but keep registers and constants matching
        # Convert pattern into a regex (flexible whitespace, case-insensitive)
        regex_pattern = re.escape(pattern)
        regex_pattern = regex_pattern.replace(r'\ ', r'\s*')
        regex_pattern = regex_pattern.replace(r'\,', r'\s*,\s*')
        # Allow matching immediate hex/decimal representations (e.g. -32 or 0xffffffe0)
        if '-32' in pattern:
            regex_pattern = regex_pattern.replace(r'\-32', r'(?:-32|0xffffffe0|0xffffffe0)')
        elif '$-32' in pattern or '$ -32' in pattern:
            regex_pattern = regex_pattern.replace(r'\$\-32', r'(?:\$-32|\$0xffffffe0|\$0xffffffe0)')
            
        regex = re.compile(f"^{regex_pattern}$", re.IGNORECASE)
        
        if assert_type == 'CHECK':
            # Search forward for the pattern
            found = False
            while inst_idx < num_insts:
                if regex.match(instructions[inst_idx]):
                    found = True
                    # Advance index to the matched instruction
                    inst_idx += 1
                    break
                inst_idx += 1
            
            if not found:
                return False, f"CHECK failed: Pattern '{pattern}' not found in remaining instructions starting from index {inst_idx}."
                
        elif assert_type == 'CHECK-NEXT':
            # The next instruction must match the pattern
            if inst_idx >= num_insts:
                return False, f"CHECK-NEXT failed: End of instructions reached. Expected '{pattern}'."
            
            if not regex.match(instructions[inst_idx]):
                return False, f"CHECK-NEXT failed:\n  Expected: '{pattern}'\n  Found:    '{instructions[inst_idx]}' at instruction index {inst_idx}."
            
            inst_idx += 1
            
        elif assert_type == 'CHECK-NOT':
            # The pattern must NOT appear before the next CHECK
            # Find the next CHECK or CHECK-NEXT index
            next_check_idx = len(assertions)
            for k in range(assert_idx + 1, len(assertions)):
                if assertions[k][0] in ('CHECK', 'CHECK-NEXT'):
                    next_check_idx = k
                    break
                    
            # Check if this NOT pattern appears in the range up to the next match
            # For simplicity, we check if it appears in any remaining instructions
            # until we find the next CHECK's pattern.
            temp_idx = inst_idx
            while temp_idx < num_insts:
                # If we hit the next CHECK's pattern, we stop checking NOT
                if next_check_idx < len(assertions):
                    next_pattern = assertions[next_check_idx][1]
                    next_regex_pattern = re.escape(next_pattern).replace(r'\ ', r'\s*').replace(r'\,', r'\s*,\s*')
                    if re.match(f"^{next_regex_pattern}$", instructions[temp_idx], re.IGNORECASE):
                        break
                
                if regex.match(instructions[temp_idx]):
                    return False, f"CHECK-NOT failed: Pattern '{pattern}' found at instruction index {temp_idx} when it should not be present."
                temp_idx += 1
                
    return True, "Passed"

def run_test(nasm_path, filepath):
    """
    Runs a single test case.
    """
    filename = os.path.basename(filepath)
    run_line, assertions = parse_check_lines(filepath)
    
    if not run_line:
        # If no RUN line, assume default LFI mode
        flags = ['-lfi']
    else:
        # Extract LFI flags from the RUN line
        # LLVM run line: llvm-mc -filetype asm -triple x86_64_lfi -mattr=+no-lfi-stores %s | FileCheck %s
        # NASM run line: nasm -lfi <flags> %s
        flags = ['-lfi']
        if '-mattr=' in run_line:
            attr_match = re.search(r'-mattr=([^\s]*)', run_line)
            if attr_match:
                attrs = attr_match.group(1).split(',')
                for attr in attrs:
                    if attr == '+no-lfi-segue':
                        flags.append('-lfi-no-segue')
                    elif attr == '+no-lfi-loads':
                        flags.append('-lfi-no-loads')
                    elif attr == '+no-lfi-stores':
                        flags.append('-lfi-no-stores')
        elif 'nasm' in run_line:
            # If we already updated the RUN line to NASM syntax, just extract the flags
            matches = re.findall(r'(-lfi[^\s]*)', run_line)
            if matches:
                flags = matches

    # Compile the file
    obj_path = filepath + '.o'
    compile_cmd = [nasm_path] + flags + ['-f', 'elf64', '-o', obj_path, filepath]
    
    try:
        subprocess.run(compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[{filename}] FAIL: Compilation failed.")
        print(f"  Command: {' '.join(compile_cmd)}")
        print(f"  Error:\n{e.stderr}")
        return False
        
    # Disassemble
    instructions = get_disassembly(obj_path)
    # Cleanup object file
    if os.path.exists(obj_path):
        os.remove(obj_path)
        
    if instructions is None:
        print(f"[{filename}] FAIL: Disassembly failed.")
        return False
        
    # Verify assertions
    passed, message = verify_assertions(instructions, assertions)
    
    if passed:
        print(f"[{filename}] PASS")
        return True
    else:
        print(f"[{filename}] FAIL")
        print(f"  {message}")
        print("  Disassembled instructions found:")
        for idx, inst in enumerate(instructions):
            print(f"    {idx:2d}: {inst}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: run_tests.py <path_to_nasm> [test_file.asm]")
        sys.exit(1)
        
    nasm_path = sys.argv[1]
    test_dir = os.path.dirname(os.path.abspath(__file__))
    
    test_files = []
    if len(sys.argv) >= 3:
        # Run specific test
        test_files.append(os.path.abspath(sys.argv[2]))
    else:
        # Run all test files (.asm or .s)
        # Note: We only run files that are .asm (which are the converted ones)
        # to avoid running on unconverted raw .s files yet.
        for entry in os.listdir(test_dir):
            if entry.endswith('.asm'):
                test_files.append(os.path.join(test_dir, entry))
                
    test_files.sort()
    
    total_tests = len(test_files)
    passed_tests = 0
    
    if total_tests == 0:
        print("No .asm test files found to run.")
        sys.exit(0)
        
    print(f"Running {total_tests} LFI sandboxing tests...")
    print("=" * 60)
    
    for filepath in test_files:
        if run_test(nasm_path, filepath):
            passed_tests += 1
            
    print("=" * 60)
    print(f"Result: {passed_tests}/{total_tests} passed.")
    
    if passed_tests < total_tests:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()
