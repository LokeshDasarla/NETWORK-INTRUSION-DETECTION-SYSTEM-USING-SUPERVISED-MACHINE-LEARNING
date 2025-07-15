 NETWORK-INTRUSION-DETECTION-SYSTEM-USING-SUPERVISED-MACHINE-LEARNING

A machine learning-based intrusion detection system using SVM and ANN classifiers, implemented with Python and Tkinter GUI.

 Features

- 🖥️ **Tkinter GUI** for user-friendly interaction
- 📊 **Data preprocessing** for NSL-KDD dataset
- 🤖 **Two classifier models**:
  - Support Vector Machine (SVM)
  - Artificial Neural Network (ANN)
- 📈 **Accuracy comparison** visualization
- 🔍 **Feature selection** using Chi-squared test

Requirements

- Python 3.6+
  Required packages:
- pip install numpy pandas scikit-learn tensorflow matplotlib
  
How to Run
1. Clone the repository
2. Install dependencies:
 ```bash
 pip install -r requirements.txt
3.Download the NSL-KDD dataset and place it in an NSL-KDD-Dataset folder
4.Run the application
  python intrusion_detection.py

File Structure:
network-intrusion-detection/
├── intrusion_detection.py    # Main application code
├── clean.txt                # Preprocessed data output
├── NSL-KDD-Dataset/         # Dataset directory
│   └── KDDTrain+.txt        # Sample dataset file
├── README.md
└── requirements.txt

Sample Outputs:

1. Application Interface
Network Intrusion Detection using Supervised Machine Learning
[Text display area]
[Upload Dataset] [Preprocess Dataset] [Generate Model]
[Run SVM] [Run ANN] [Accuracy Graph]

2. Preprocessing Output
Dataset loaded: NSL-KDD-Dataset/KDDTrain+.txt
Preprocessing complete. Clean data saved to clean.txt

3. Model Generation
Model generated with 67343 train and 16836 test samples.

4. SVM Results
SVM Accuracy: 92.45%

5. ANN Results
ANN Accuracy: 95.67%

6. Accuracy Graph

Workflow:
Upload Dataset: Load the NSL-KDD dataset
Preprocess: Clean and prepare the data
Generate Model: Split data into train/test sets
Run Classifiers:
SVM with RBF kernel
ANN with 2 hidden layers
View Results: Compare classifier accuracies

Dataset Information:
The system uses the NSL-KDD dataset which contains:
41 network traffic features
38 attack types + normal traffic
Predefined label mapping for classification

