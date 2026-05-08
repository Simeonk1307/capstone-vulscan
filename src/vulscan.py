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
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Function to load the exact path of the resource stored in the executable
def resource_path(relative_path):
    """ Get the absolute path to the resource, works for both dev and PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores the path in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        # Get the directory where vulscan.py is located
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)

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
                cleaned_line = line.replace('\t', '').strip()
                if cleaned_line == '':
                    continue
                if cleaned_line in ('{', '}'):
                    continue
                if any(keyword in cleaned_line.split() for keyword in keywords_to_exclude):
                    continue
                if cleaned_line.startswith('#include'):
                    continue
                if any(re.match(rf'\b{keyword}\s*;', cleaned_line) for keyword in c_keywords):
                    continue
                outfile.write(cleaned_line + '\n')
    except FileNotFoundError:
        print(f'Error: The file {input_file} does not exist.')
    except Exception as e:
        print(f'An error occurred: {e}')

def remove_comments_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding='iso-8859-1') as file:
            content = file.read()

    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    content = re.sub(r'//.*', '', content)

    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)

def remove_comments_from_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.c', '.cpp', '.h', '.nc')):
                file_path = os.path.join(root, file)
                remove_comments_from_file(file_path)

def remove_duplicates(input_file, output_file):
    data = pd.read_csv(input_file)
    data_cleaned = data.drop_duplicates()
    data_cleaned.to_csv(output_file, index=False)

input_filename = ""
dir_name = ""
dir_flag = 0

def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        global input_filename, dir_name
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

output_filename = os.path.splitext(input_filename)[0] + '.txt'
remove_comments_from_file(input_filename)
extract_lines(input_filename, output_filename)

print("Scanning for vulnerabilities...")

df = pd.read_table(output_filename, names=['code'])

# FIX: Efficient vectorized replacement to avoid ChainedAssignmentError
df["code"] = df["code"].astype(str).str.replace(' ', '', regex=False).str.lower()
df_nospc = df

tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")

class VulnerabilityDataset(Dataset):
    def __init__(self, texts):
        self.texts = texts

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        # FIX: Calling tokenizer directly instead of .encode_plus
        encoding = tokenizer(
            text,
            add_special_tokens=True,
            return_token_type_ids=False,
            padding="max_length",
            truncation=True,
            max_length=256,
            return_tensors="pt",
        )
        return {
            "input_ids": encoding["input_ids"].flatten(),
            "attention_mask": encoding["attention_mask"].flatten(),
        }

test_dataset = df.reset_index(drop=True)
testing_set = VulnerabilityDataset(test_dataset["code"])
test_loader = DataLoader(testing_set, batch_size=32, shuffle=False) # Changed shuffle to False for report mapping

class DistilBertConfig(PretrainedConfig):
      model_type = "distilbert"
      attribute_map = {
          "hidden_size": "dim",
          "num_attention_heads": "n_heads",
          "num_hidden_layers": "n_layers",
      }

      def __init__(self, vocab_size=30522, max_position_embeddings=512, sinusoidal_pos_embds=False,
                   n_layers=1, n_heads=12, dim=768, hidden_dim=4 * 768, dropout=0.3,
                   attention_dropout=0.1, activation="gelu", initializer_range=0.02,
                   qa_dropout=0.1, seq_classif_dropout=0.2, pad_token_id=0, **kwargs):
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

configuration = DistilBertConfig()
model = DistilBertModel(configuration)

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

output_model_file = resource_path('CWE_Model_1lyr_12hd_GPU2CPU.pt')
loaded_model = DistillBERTClass()
loaded_model.to(device)

if torch.cuda.is_available():
    loaded_model.load_state_dict(torch.load(output_model_file))
else:
    loaded_model.load_state_dict(torch.load(output_model_file, map_location=device))

loaded_model.eval()

def valid(model, testing_loader):
    model.eval()
    vuls = {}
    with torch.no_grad():
        for _, data in enumerate(testing_loader, 0):
            ids = data['input_ids'].to(device, dtype=torch.long)
            mask = data['attention_mask'].to(device, dtype=torch.long)
            outputs = model(ids, mask)
            _, big_idx = torch.max(outputs.data, dim=1)
            
            pred_out = big_idx.detach().cpu().numpy()
            decoded_labels = le.inverse_transform(pred_out)
            ids_list = ids.tolist()
            texts = [tokenizer.decode(seq, skip_special_tokens=True, clean_up_tokenization_spaces=True) for seq in ids_list]

            for index in range(len(pred_out)):
                if decoded_labels[index] != '0':
                    clean_text = texts[index].replace(' ', '')
                    idx_matches = df_nospc[df_nospc['code'] == clean_text].index
                    line_num = str(idx_matches[0] + 1) if not idx_matches.empty else "Unknown"
                    line_desc = f"Line {line_num}: {texts[index]}"
                    vuls[decoded_labels[index]] = line_desc
    return vuls

vuls = valid(loaded_model, test_loader)

def generate_vuln_report(vuls, inp_file, dir_name):
    url = "https://cwe.mitre.org/data/definitions/"
    fileName = os.path.join(dir_name, 'vulscan_report_' + inp_file + '.pdf')
    documentTitle = 'vulscan_report'
    title = 'VulScan Vulnerability Results'
    subTitle = 'File Name: ' + input_filename

    def wrap_text(text, font_name, font_size, max_width, color):
        words = str(text).split(' ')
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

    pdf = canvas.Canvas(fileName, pagesize=A4)
    width, height = A4
    pdf.setTitle(documentTitle)
    
    try:
        font_path = resource_path('SakBunderan.ttf')
        pdfmetrics.registerFont(TTFont('abc', font_path))
        pdf.setFont('abc', 34)
    except:
        pdf.setFont("Helvetica-Bold", 34)

    title_width = pdf.stringWidth(title, 'abc' if 'abc' in pdfmetrics.getRegisteredFontNames() else "Helvetica-Bold", 34)
    pdf.drawString((width - title_width) / 2, height - 80, title)

    pdf.setFillColor(colors.blue)
    pdf.setFont("Courier", 14)
    subt = wrap_text(subTitle, "Courier", 14, width - 100, colors.blue)
    y_pos = height - 120
    for l in subt:
        pdf.drawString(50, y_pos, l)
        y_pos -= 20

    pdf.setStrokeColor(colors.black)
    pdf.line(40, y_pos - 10, width - 40, y_pos - 10)
    y_pos -= 40

    pdf.setFillColor(colors.black)
    pdf.setFont("Courier", 12)
    
    if not vuls:
        pdf.drawString(40, y_pos, "No vulnerabilities detected.")
    else:
        intro = "Vulnerable lines identified. Line numbers in RED refer to the formatted input below."
        for l in wrap_text(intro, "Courier", 12, width - 80, colors.black):
            pdf.drawString(40, y_pos, l)
            y_pos -= 15
        
        y_pos -= 20
        for cwe, line in vuls.items():
            if y_pos < 100:
                pdf.showPage()
                y_pos = height - 50
            
            for l in wrap_text(f"Vulnerability: {cwe}", "Courier-Bold", 12, width - 80, colors.black):
                pdf.drawString(40, y_pos, l)
                y_pos -= 15
            for l in wrap_text(line, "Courier", 12, width - 80, colors.red):
                pdf.drawString(40, y_pos, l)
                y_pos -= 15
            
            match = re.search(r'CWE-(\d+)', cwe)
            if match:
                cwe_url = url + match.group(1) + ".html"
                pdf.setFillColor(colors.black)
                pdf.drawString(40, y_pos, "More info: ")
                pdf.setFillColor(colors.blue)
                pdf.drawString(120, y_pos, cwe_url)
                pdf.linkURL(cwe_url, (120, y_pos-2, 500, y_pos+10))
                y_pos -= 25

    pdf.showPage()
    # Code formatting page
    pdf.setFont("Courier", 12)
    pdf.setFillColor(colors.black)
    pdf.drawString(40, height - 40, "Formatted Source Code Reference:")
    y_pos = height - 70
    
    with open(output_filename, 'r') as f:
        for i, line in enumerate(f, 1):
            if y_pos < 50:
                pdf.showPage()
                y_pos = height - 50
            pdf.drawString(40, y_pos, f"{i}. {line.strip()[:80]}")
            y_pos -= 15

    pdf.save()
    return 1

status = generate_vuln_report(vuls, Path(input_filename).stem, os.path.dirname(input_filename))
if status:
    print("Vulnerability report (PDF) generated at:", os.path.dirname(input_filename))