# Required Libraries
from tkinter import *
from tkinter import filedialog, messagebox
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectKBest, chi2
from sklearn import svm
from sklearn.metrics import accuracy_score
from keras.models import Sequential
from keras.layers import Dense, Input
from keras.utils import to_categorical
import matplotlib.pyplot as plt

# Globals
filename = ""
data = None
X = Y = X_train = X_test = y_train = y_test = None
svm_acc = ann_acc = 0
classifier = None

# GUI Initialization
main = Tk()
main.title("Network Intrusion Detection")
main.geometry("1300x800")
main.config(bg='PeachPuff2')

text = Text(main, height=30, width=80, font=('times', 12, 'bold'))
text.place(x=10, y=100)

pathlabel = Label(main, font=('times', 14, 'bold'))
pathlabel.place(x=700, y=150)

def isfloat(value):
    try:
        float(value)
        return True
    except ValueError:
        return False

def upload():
    global filename
    filename = filedialog.askopenfilename(initialdir="NSL-KDD-Dataset")
    pathlabel.config(text=filename)
    text.insert(END, f"Dataset loaded: {filename}\n\n")

def preprocess():
    global data
    if not filename:
        text.insert(END, "Upload dataset first!\n")
        return

    columns = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", 
        "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", 
        "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", 
        "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", 
        "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", 
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", 
        "dst_host_srv_rerror_rate", "label"]

    label_map = {
        "normal": 0, "neptune": 1, "warezclient": 2, "ipsweep": 3, "portsweep": 4, "teardrop": 5, "nmap": 6,
        "satan": 7, "smurf": 8, "pod": 9, "back": 10, "guess_passwd": 11, "ftp_write": 12, "multihop": 13,
        "rootkit": 14, "buffer_overflow": 15, "imap": 16, "warezmaster": 17, "phf": 18, "land": 19,
        "loadmodule": 20, "spy": 21, "perl": 22, "saint": 23, "mscan": 24, "apache2": 25, "snmpgetattack": 26,
        "processtable": 27, "httptunnel": 28, "ps": 29, "snmpguess": 30, "mailbomb": 31, "named": 32,
        "sendmail": 33, "xterm": 34, "worm": 35, "xlock": 36, "xsnoop": 37, "sqlattack": 38, "udpstorm": 39
    }

    try:
        raw_data = pd.read_csv(filename)
    except:
        text.insert(END, "Error reading dataset.\n")
        return

    clean_data = []
    for _, row in raw_data.iterrows():
        cleaned = [float(row.iloc[i]) if isfloat(row.iloc[i]) else 0.0 for i in range(41)]
        label = label_map.get(row.iloc[41], 1)
        cleaned.append(label)
        clean_data.append(cleaned)

    data = pd.DataFrame(clean_data, columns=columns)
    data.to_csv("clean.txt", index=False)
    text.insert(END, "Preprocessing complete. Clean data saved to clean.txt\n")

def generateModel():
    global data, X, Y, X_train, X_test, y_train, y_test
    try:
        data = pd.read_csv("clean.txt")
    except:
        text.insert(END, "Run preprocessing first.\n")
        return

    X = data.iloc[:, :-1].values
    Y = data.iloc[:, -1].values
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2)
    text.insert(END, f"Model generated with {len(X_train)} train and {len(X_test)} test samples.\n")

def prediction(X_test, cls):
    return cls.predict(X_test)

def cal_accuracy(y_test, y_pred, label):
    acc = accuracy_score(y_test, y_pred) * 100
    text.insert(END, f"{label} Accuracy: {acc:.2f}%\n\n")
    return acc

def runSVM():
    global svm_acc, classifier
    if X_train is None:
        text.insert(END, "Generate model first.\n")
        return

    selector = SelectKBest(score_func=chi2, k=15)
    X_train_sel = selector.fit_transform(X_train, y_train)
    X_test_sel = selector.transform(X_test)

    cls = svm.SVC(kernel='rbf', class_weight='balanced')
    cls.fit(X_train_sel, y_train)
    y_pred = prediction(X_test_sel, cls)
    svm_acc = cal_accuracy(y_test, y_pred, "SVM")
    classifier = cls

def runANN():
    global ann_acc
    if X_train is None:
        text.insert(END, "Generate model first.\n")
        return

    selector = SelectKBest(score_func=chi2, k=25)
    X_train_sel = selector.fit_transform(X_train, y_train)
    X_test_sel = selector.transform(X_test)

    y_train_cat = to_categorical(y_train)

    model = Sequential([
        Input(shape=(25,)),
        Dense(64, activation='relu'),
        Dense(64, activation='relu'),
        Dense(y_train_cat.shape[1], activation='softmax')
    ])

    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.fit(X_train_sel, y_train_cat, epochs=50, batch_size=32, verbose=0)
    _, acc = model.evaluate(X_train_sel, y_train_cat, verbose=0)
    ann_acc = acc * 100
    text.insert(END, f"ANN Accuracy: {ann_acc:.2f}%\n\n")

def graph():
    bars = ['SVM', 'ANN']
    values = [svm_acc, ann_acc]
    plt.bar(bars, values, color=['blue', 'green'])
    plt.title("Accuracy Comparison")
    plt.ylabel("Accuracy (%)")
    plt.show()

# GUI Buttons
font1 = ('times', 14, 'bold')
Button(main, text="Upload Dataset", command=upload, font=font1).place(x=700, y=100)
Button(main, text="Preprocess Dataset", command=preprocess, font=font1).place(x=700, y=200)
Button(main, text="Generate Model", command=generateModel, font=font1).place(x=700, y=250)
Button(main, text="Run SVM", command=runSVM, font=font1).place(x=700, y=300)
Button(main, text="Run ANN", command=runANN, font=font1).place(x=700, y=350)
Button(main, text="Accuracy Graph", command=graph, font=font1).place(x=700, y=400)

# GUI Title
title = Label(main, text='Network Intrusion Detection using Supervised Machine Learning',
              bg='PaleGreen2', fg='Khaki4', font=('times', 16, 'bold'), height=3, width=120)
title.place(x=0, y=5)

main.mainloop()
