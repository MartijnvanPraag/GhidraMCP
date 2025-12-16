import re

# Read the file  
with open('GhidraMCPHeadlessServer.java', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find patterns where we have consecutive addLinks calls with string parameters
# and replace them with a Map creation followed by one addLinks call

output_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    
    # Check if this is a line with addLinks(response, "key", "value")
    match = re.match(r'^(\s+)addLinks\(response, "([^"]+)", "([^"]+)"\);', line)
    
    if match:
        indent = match.group(1)
        # Collect all consecutive addLinks calls
        link_entries = []
        link_entries.append((match.group(2), match.group(3)))
        
        j = i + 1
        while j < len(lines):
            next_match = re.match(r'^(\s+)addLinks\(response, "([^"]+)", "([^"]+)"\);', lines[j])
            if next_match:
                link_entries.append((next_match.group(2), next_match.group(3)))
                j += 1
            else:
                break
        
        # Generate replacement code
        output_lines.append(f'{indent}\n')
        output_lines.append(f'{indent}Map<String, String> links = new HashMap<>();\n')
        for key, value in link_entries:
            output_lines.append(f'{indent}links.put("{key}", "{value}");\n')
        output_lines.append(f'{indent}addLinks(response, links);\n')
        
        # Skip the processed lines
        i = j
    else:
        output_lines.append(line)
        i += 1

# Write back
with open('GhidraMCPHeadlessServer.java', 'w', encoding='utf-8') as f:
    f.writelines(output_lines)

print(f'Consolidated {sum(1 for line in output_lines if "links.put" in line)} addLinks calls')
