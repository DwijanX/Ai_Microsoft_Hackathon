import json
import csv
from io import StringIO

# Load JSON data from file
with open('C:\\Users\\chris\\Documents\\Ai_Microsoft_Hackathon\\training.json', 'r') as json_file:
    data = json.load(json_file)

# Create a StringIO object to save the CSV content
csv_buffer = StringIO()

# Create a CSV writer object
csv_writer = csv.writer(csv_buffer)

# Write the header row
csv_writer.writerow(['instruction', 'input', 'output'])

# Process each JSON object and write the corresponding row to the CSV file
for item in data:
    instruction = item['instruction']
    
    input_data = item['input']
    input_str = json.dumps(input_data)  # Convert input dictionary to JSON string
    
    output_data = item['output']
    output_str = json.dumps(output_data)  # Convert output dictionary to JSON string
    
    csv_writer.writerow([instruction, input_str, output_str])

# Get the CSV content from the StringIO buffer
csv_content = csv_buffer.getvalue()

# Save CSV content to a file
with open('packets2.csv', 'w', newline='') as csv_file:
    csv_file.write(csv_content)

# Print CSV content for verification
print(csv_content)