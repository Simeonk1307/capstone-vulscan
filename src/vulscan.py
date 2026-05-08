# -*- coding: utf-8 -*-
"""
VulScan: A Deep Learning-based Vulnerability Scanning Tool for IoT OS source code files (C/C++).
"""

import numpy as np
import pandas as pd
import os
import sys
import torch
import re
from pathlib import Path
from transformers import DistilBertTokenizer, DistilBertModel, PretrainedConfig
from torch.utils.data import DataLoader, Dataset
from sklearn.preprocessing import LabelEncoder
from reportlab.pdfgen import canvas
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox, PhotoImage
import logging

os.environ["PYTHONWARNINGS"] = "ignore"
logging.getLogger("transformers").setLevel(logging.ERROR)

# Function to load the exact path of the resource stored in the executable
def resource_path(relative_path):
    """ Get the absolute path to the resource, works for both dev and PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores the path in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# Fetch the device type (CPU/GPU)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Pre-process the source code file to extract each line of code excluding certain fixed benign lines
def extract_lines(input_file, output_file):
    keywords_to_exclude = {'else', '#endif', '#else'}
    c_keywords = [
        'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do', 'double',
        'else', 'enum', 'extern', 'float', 'for', 'goto', 'if', 'inline', 'int', 'long',
        'register', 'restrict', 'return', 'short', 'signed', 'sizeof', 'static', 'struct',
        'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile', 'while', '_Alignas',
        '_Alignof', '_Atomic', '_Bool', '_Complex', '_Generic', '_Imaginary', '_Noreturn',
        '_Static_assert', '_Thread_local'
    ]

    try:
        with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
            for line in infile:
                # Remove all tab spaces and strip leading/trailing white spaces
                cleaned_line = line.replace('\t', '').strip()

                # Exclude blank lines
                if cleaned_line == '':
                    continue

                # Exclude lines with only opening or closing curly braces
                if cleaned_line in ('{', '}'):
                    continue

                # Exclude lines with keywords to be excluded
                if any(keyword in cleaned_line.split() for keyword in keywords_to_exclude):
                    continue

                # Exclude lines with #include statements
                if cleaned_line.startswith('#include'):
                    continue

                # Exclude lines where any C/C++ keyword is immediately followed by a semicolon
                if any(re.match(rf'\b{keyword}\s*;', cleaned_line) for keyword in c_keywords):
                    continue

                # Write the cleaned line to the output file
                outfile.write(cleaned_line + '\n')
    except FileNotFoundError:
        print(f'Error: The file {input_file} does not exist.')
    except Exception as e:
        print(f'An error occurred: {e}')

# Remove comments from a particular file
def remove_comments(file_path):
    #Remove C/C++ style comments from a file and handle different encodings.
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except UnicodeDecodeError:
        # Try reading with a different encoding if UTF-8 fails
        with open(file_path, 'r', encoding='iso-8859-1') as file:
            content = file.read()

    # Remove all multiline comments
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)

    # Remove all single line comments
    content = re.sub(r'//.*', '', content)

    # Write the processed content back to the file
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)

# Remove comments from all files in a directory that end with .c, .cpp or .h
def remove_comments_from_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.c', '.cpp', '.h', '.nc')):  # Checking for multiple file extensions
                file_path = os.path.join(root, file)
                remove_comments_from_file(file_path)

# Remove duplicate entries (if any) in a file
def remove_duplicates(input_file, output_file):
    # Load the data from the input CSV file
    data = pd.read_csv(input_file)

    # Remove duplicate rows
    data_cleaned = data.drop_duplicates()

    # Save the cleaned data to the output CSV file
    data_cleaned.to_csv(output_file, index=False)

# Specify the input source code file to be processed for vulnerabilities (GLOBAL)
input_filename = ""

# Specify the input directory containing the source code files to be processed for vulnerabilities (GLOBAL)
dir_name = ""

# Flag to indicate whether the input is a single file or a directory (GLOBAL)
dir_flag = 0

def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        global input_filename
        global dir_name

        input_filename = ""
        dir_name = ""

        root.destroy()

def open_file_dialog():
    file_path = filedialog.askopenfilename(title="Select a File", filetypes=[("C/C++ files", "*.c *.cpp *.h")])
    if file_path:
        selected_file_label.config(text=f"Selected File: \n{file_path}")
        process_file(file_path)

def open_directory_dialog():
    dir_path = filedialog.askdirectory(title="Select a Directory")
    if dir_path:
        selected_file_label.config(text=f"Selected Directory: \n{dir_path}")
        process_directory(dir_path)

def process_file(file_path):
    global input_filename
    try:
        input_filename = file_path
        ok_button.config(state=tk.NORMAL)

        with open(file_path, 'r') as file:
            file_contents = file.read()
            file_text.delete('1.0', tk.END)
            file_text.insert(tk.END, file_contents)

    except Exception as e:
        selected_file_label.config(text=f"Error: {str(e)}")

def process_directory(dir_path):
    global dir_name, dir_flag
    try:
        dir_name = dir_path + '/'
        dir_flag = 1
        ok_button.config(state=tk.NORMAL)

    except Exception as e:
        selected_file_label.config(text=f"Error: {str(e)}")

root = tk.Tk()
root.title("VulScan Tool Input Interface")

icon = PhotoImage(file=resource_path("iitpkd_logo.png"))
resized_icon = icon.subsample(1, 1)

image_label = tk.Label(root, image=resized_icon)
image_label.pack(padx=10, pady=10)

open_file_button = tk.Button(root, text="Open File", command=open_file_dialog)
open_file_button.pack(padx=20, pady=10)

open_dir_button = tk.Button(root, text="Open Directory", command=open_directory_dialog)
open_dir_button.pack(padx=20, pady=10)

selected_file_label = tk.Label(root, text="Selected File or Directory:")
selected_file_label.pack()

file_text = tk.Text(root, wrap=tk.WORD, height=10, width=40)
file_text.pack(padx=20, pady=20)

ok_button = tk.Button(root, text="Confirm", command=root.destroy, state=tk.DISABLED)
ok_button.pack(padx=20, pady=10)

root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()

if dir_flag == 1:
    if dir_name == "":
        print("No directory specified, exiting tool...")
    else:
        dir_script_path = resource_path('vulscan_dir.py')

        if hasattr(sys, '_MEIPASS'):
            os.system(f"python3 -W ignore {dir_script_path} {dir_name} {sys._MEIPASS}")
        else:
            os.system(f"python3 -W ignore {dir_script_path} {dir_name}")

    sys.exit()

if input_filename == "":
    print("No file specified, exiting tool...")
    sys.exit()

# Specify the output file containing the source code file formatted as each line of code
output_filename = os.path.splitext(input_filename)[0] + '.txt'

# Call the function to remove comments from the file
remove_comments(input_filename)

# Call the function to pre-process the file and extract each line of code as a text file
extract_lines(input_filename, output_filename)

# Call the function to remove duplicates
#remove_duplicates(output_filename, out_without_dups)

print("Scanning for vulnerabilities...")

df = pd.read_table(output_filename, names=['code'])
df_nospc = df

for i in range(0, len(df)):
  df_nospc["code"][i] = df_nospc["code"][i].replace(' ', '')
  df_nospc["code"][i] = df_nospc["code"][i].lower()

tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")

class VulnerabilityDataset(Dataset):
    def __init__(self, texts):
        self.texts = texts

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        encoding = tokenizer.encode_plus(
            text,
            add_special_tokens=True, #adds the [CLS] and [SEP] tokens
            return_token_type_ids=False, #DistilBERT does not use token type embeddings (as BERT does for sentence pairs)
            padding="max_length",
            truncation=True,
            max_length=256,
            return_tensors="pt",
        )
        return {
            "input_ids": encoding["input_ids"].flatten(),
            "attention_mask": encoding["attention_mask"].flatten(),
        }

# Creating the dataset and dataloader for the model
test_dataset = df.reset_index(drop=True)
testing_set = VulnerabilityDataset(test_dataset["code"])

batch_size = 32

test_loader = DataLoader(testing_set, batch_size=batch_size, shuffle=True)

class DistilBertConfig(PretrainedConfig):
      model_type = "distilbert"
      attribute_map = {
          "hidden_size": "dim",
          "num_attention_heads": "n_heads",
          "num_hidden_layers": "n_layers",
      }

      def __init__(
        self,
        vocab_size=30522,
        max_position_embeddings=512,
        sinusoidal_pos_embds=False,
        n_layers=1,
        n_heads=12,
        dim=768,
        hidden_dim=4 * 768,
        dropout=0.3,
        attention_dropout=0.1,
        activation="gelu",
        initializer_range=0.02,
        qa_dropout=0.1,
        seq_classif_dropout=0.2,
        pad_token_id=0,
        **kwargs,
    ):
        self.vocab_size = vocab_size
        self.max_position_embeddings = max_position_embeddings
        self.sinusoidal_pos_embds = sinusoidal_pos_embds
        self.n_layers = n_layers
        self.n_heads = n_heads
        self.dim = dim
        self.hidden_dim = hidden_dim
        self.dropout = dropout
        self.attention_dropout = attention_dropout
        self.activation = activation
        self.initializer_range = initializer_range
        self.qa_dropout = qa_dropout
        self.seq_classif_dropout = seq_classif_dropout
        super().__init__(**kwargs, pad_token_id=pad_token_id)

# Creating a customized model, by reducing the number of encoders layer to 1
configuration = DistilBertConfig()
model = DistilBertModel(configuration)

optimizer = torch.optim.AdamW(model.parameters(), lr=5e-5)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)

# Load the 36 Vulnerabilty classes used by the model
classes_path = resource_path('classes.npy')
le = LabelEncoder()
le.classes_ = np.load(classes_path, allow_pickle=True)

class DistillBERTClass(torch.nn.Module):
    def __init__(self):
        super(DistillBERTClass, self).__init__()
        self.l1 = model
        self.pre_classifier = torch.nn.Linear(768, 768)
        self.dropout = torch.nn.Dropout(0.3)
        self.classifier = torch.nn.Linear(768, le.classes_.size)

    def forward(self, input_ids, attention_mask):
        output_1 = self.l1(input_ids=input_ids, attention_mask=attention_mask)
        hidden_state = output_1[0]
        pooler = hidden_state[:, 0]
        pooler = self.pre_classifier(pooler)
        pooler = torch.nn.ReLU()(pooler)
        pooler = self.dropout(pooler)
        output = self.classifier(pooler)
        return output

model1 = DistillBERTClass()
model1.to(device)

# model_file
#output_model_file = 'CWE_Model_1lyr_12hd.pt'
output_model_file = resource_path('CWE_Model_1lyr_12hd_GPU2CPU.pt')

# Reloading the model
loaded_model = DistillBERTClass()
loaded_model.to(device)

if torch.cuda.is_available():
  # Loading on GPU
  loaded_model.load_state_dict(torch.load(output_model_file))
else:
  # Loading on CPU
  loaded_model.load_state_dict(torch.load(output_model_file, map_location=device))

loaded_model.eval()

def valid(model, testing_loader):
    tr_loss = 0
    nb_tr_steps = 0
    nb_tr_examples = 0

    model.eval()
    n_correct = 0; n_wrong = 0; total = 0

    pred_out = []
    act_targets = []

    vuls = {}

    with torch.no_grad():
        for _, data in enumerate(testing_loader, 0):
            ids = data['input_ids'].to(device, dtype = torch.long)
            mask = data['attention_mask'].to(device, dtype = torch.long)

            outputs = model(ids, mask)
            big_val, big_idx = torch.max(outputs.data, dim=1)

            pred_out = []

            for item in big_idx.detach().cpu().numpy():
              pred_out.append(item)

            decoded_labels = le.inverse_transform(pred_out)

            ids_list = ids.tolist()
            text = [tokenizer.decode(seq, skip_special_tokens = True, clean_up_tokenization_spaces = True) for seq in ids_list]

            for index in range(0, len(pred_out)):
              if decoded_labels[index] != '0':

                idx = df_nospc[df_nospc['code'] == text[index].replace(' ', '')].index
                line = "Line " + str(idx[0] + 1) + ": " + text[index]

                vul = {decoded_labels[index]: line}
                vuls.update(vul)

    return vuls

vuls = valid(loaded_model, test_loader)

def generate_vuln_report(vuls, inp_file, dir_name):
    url = "https://cwe.mitre.org/data/definitions/"
    fileName = dir_name + '/vulscan_report_' + inp_file + '.pdf'
    documentTitle = 'vulscan_report'
    title = 'VulScan Vulnerability Results'
    subTitle = 'File Name: ' + input_filename

    status = 0

    # Function to wrap text
    def wrap_text(text, font_name, font_size, max_width, color):
        words = text.split(' ')
        lines = []
        current_line = ''
        pdf.setFont(font_name, font_size)
        pdf.setFillColor(color)
        for word in words:
            test_line = current_line + (word + ' ')
            if pdf.stringWidth(test_line, font_name, font_size) > max_width:
                lines.append(current_line.strip())
                current_line = word + ' '
            else:
                current_line = test_line
        if current_line:
            lines.append(current_line.strip())
        return lines

    # Create a Canvas object with A4 page size
    pdf = canvas.Canvas(fileName, pagesize=A4)
    width, height = A4  # A4 dimensions in points (595.27 x 841.89)

    # Set Title
    pdf.setTitle(documentTitle)
    font_path = resource_path('SakBunderan.ttf')
    pdfmetrics.registerFont(TTFont('abc', font_path))
    pdf.setFont('abc', 34)
    title_width = pdf.stringWidth(title, 'abc', 34)
    pdf.drawString((width - title_width) / 2, height - 80, title)

    # Set Sub-title
    pdf.setFillColorRGB(0, 0, 255)
    pdf.setFont("Courier", 14)
    subTitle_width = pdf.stringWidth(subTitle, "Courier-Bold", 15)
    subt = wrap_text(subTitle, "Courier", 14, subTitle_width, colors.blue)
    for l in subt:
        pdf.drawString((width - subTitle_width) / 2, height - 120, l)
        height -= 20
    #pdf.drawString((width - subTitle_width) / 2, height - 120, subTitle)
    height += 20

    # Draw Horizontal Line
    pdf.setStrokeColor(colors.black)
    pdf.setLineWidth(1)
    pdf.line(40, height - 130, width - 40, height - 130)

    # Add Introductory Text for Page 1
    pdf.setFillColor(colors.black)
    pdf.setFont("Courier", 12)
    intro_text_p1 = "Please find below the vulnerable lines identified along with their corresponding vulnerability id/description. Line numbers mentioned in RED can be referred in the formatted line-by-line input file attached with this report."

    # Position for the text
    text_y = height - 150
    max_width = width - 80  # Set max width (leaving margins)

    if not vuls:
        text_y -= 30
        pdf.drawString(40, text_y, "No vulnerabilities detected.")
    else:
        # Wrap and draw the introductory text for page 1
        intro_lines = wrap_text(intro_text_p1, "Courier", 12, max_width, colors.black)
        for line in intro_lines:
            pdf.drawString(40, text_y, line)
            text_y -= 15

        text_y -= 20  # Add some space between the text and the list

        # Add Vulnerabilities Content
        for idx, (cwe, line) in enumerate(vuls.items(), start=1):
            # Wrap and draw the CWE text
            cwe_lines = wrap_text(f"{idx}. {cwe}", "Courier-Bold", 12, max_width, colors.black)
            for l in cwe_lines:
                pdf.drawString(40, text_y, l)
                text_y -= 15

            # Wrap and draw the code line
            code_lines = wrap_text(line, "Courier", 12, max_width, colors.red)
            for l in code_lines:
                pdf.drawString(40, text_y, l)
                text_y -= 15

            # Add URL for more info about the CWE
            pattern = r'CWE-(\d+):'
            match = re.search(pattern, cwe)
            if match:
                cwe_id = match.group(1)
                msg = "For more info regarding the vulnerability, please visit: " + url + cwe_id + ".html"
                url_lines = wrap_text(msg, "Courier", 12, max_width, colors.black)
                for l in url_lines:
                    pdf.drawString(40, text_y, l)
                    # Make the URL clickable by defining the clickable area
                    if url in l:
                        pdf.linkURL(url + cwe_id + ".html", (40, text_y - 5, 500, text_y + 10), relative=1)
                    text_y -= 15

            # Add some space between each vulnerability block
            text_y -= 10

        # Start a new page
        pdf.showPage()

        # Set Sub-title
        pdf.setFillColorRGB(0, 0, 255)
        pdf.setFont("Courier", 14)
        subTitle_width = pdf.stringWidth(subTitle, "Courier-Bold", 15)
        subt = wrap_text(subTitle, "Courier", 14, subTitle_width, colors.blue)
        for l in subt:
            pdf.drawString((width - subTitle_width) / 2, height - 40, l)
            height -= 20
        height += 20

        # Draw the horizontal line
        pdf.setStrokeColor(colors.black)
        pdf.setLineWidth(1)
        pdf.line(40, height - 50, width - 40, height - 50)

        # Set the font and position for the text file content
        pdf.setFont("Courier", 12)
        text_y = height - 80  # Start from the top with some margin

        # Add Introductory Text for Page 2
        pdf.setFillColor(colors.black)
        intro_text_p2 = "Input file formatted line-by-line for developer reference below."

        # Wrap and draw the introductory text for page 1
        intro_lines = wrap_text(intro_text_p2, "Courier", 12, max_width, colors.black)
        for line in intro_lines:
            pdf.drawString(40, text_y, line)
            text_y -= 15

        text_y -= 15  # Add some space between the text and the list

        # Read the text file and write its content to the PDF with serial numbers
        with open(output_filename, 'r') as file:
            text_content = file.readlines()

        # Initialize a serial number counter
        serial_number = 1

        # Wrap and draw the text file content
        for line in text_content:
            wrapped_lines = wrap_text(line.strip(), "Courier", 12, max_width, colors.black)
            for wl in wrapped_lines:
                if text_y <= 40:  # If near the bottom of the page, start a new page
                    pdf.showPage()
                    pdf.setFont("Courier", 12)
                    text_y = height - 40
                # Print each line with its corresponding serial number
                pdf.drawString(40, text_y, f"{serial_number}. {wl}")
                text_y -= 15

            serial_number += 1  # Increment the serial number after printing each line

    pdf.save()
    status = 1

    return status

# Call the function to generate PDF report
status = generate_vuln_report(vuls, Path(input_filename).stem, os.path.dirname(input_filename))

if status:
    print("Vulnerability report (PDF) generated at location:", os.path.dirname(input_filename))
