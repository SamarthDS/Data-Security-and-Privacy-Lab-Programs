import streamlit as st
import re
import json

# --- PII Detection Functions ---
# Regex patterns for common PII
# Note: These are simplified patterns for demonstration and may not catch all variations.
# Real-world PII detection often uses more complex regex, libraries, or machine learning.
PII_PATTERNS = {
    'NAME': r'Patient Name:\s*([A-Z][a-z]+ [A-Z][a-z]+)',
    'EMAIL': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+[a-zA-Z0-9-]',
    'PHONE_NUMBER_US': r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
    'SSN_US': r'\b\d{3}-\d{2}-\d{4}\b',
    'CREDIT_CARD_VISA': r'\b4[0-9]{12}(?:[0-9]{3})?\b', # Simple Visa pattern
}

def find_pii(text_data):
    """
    Finds potential PII elements in a given string using regex patterns.
    
    Args:
        text_data (str): The text content to scan.

    Returns:
        dict: A dictionary where keys are PII types and values are lists of found matches.
    """
    found_pii = {pii_type: [] for pii_type in PII_PATTERNS}
    
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, text_data)
        if matches:
            found_pii[pii_type] = matches
            
    return found_pii

# --- Data Classification (Conceptual Explanation) ---

def classify_data_concept(data_example, source_name):
    """
    This function demonstrates the *thinking* process for classifying data.
    These classifications are highly contextual.
    """
    
    st.header(f"--- Classification for: {source_name} ---")
    
    # 1. Structured vs. Unstructured
    classification = {
        'type': '',
        'state': '',
        'pii_analysis': {}
    }
    
    # We can try to infer based on the data format.
    try:
        # Is it valid JSON? That's structured.
        json_data = json.loads(data_example)
        classification['type'] = 'Structured (JSON)'
        st.write("**Data Type:** Structured (JSON)")
        st.json(json_data)
    except json.JSONDecodeError:
        # Is it CSV-like (comma-separated lines)?
        if '\n' in data_example and ',' in data_example.split('\n')[0]:
            classification['type'] = 'Structured (Likely CSV)'
        else:
            # Otherwise, assume it's free text.
            classification['type'] = 'Unstructured (Free Text)'
            
        st.write(f"**Data Type:** {classification['type']}")

    # 2. Data State (Contextual)
    # This cannot be determined by the script alone. It depends on *how*
    # the script gets the data.
    # - At-Rest: The data is stored on a disk (e.g., in a file or database).
    # - In-Use: The data is actively being processed in memory (RAM), like
    #            it is right now by this script.
    # - In-Transit: The data is being sent over a network (e.g., via HTTPS
    #                or FTP).
    
    # For this script, the data is 'in-use'.
    classification['state'] = 'In-Use (being processed by this script)'
    st.write(f"**Data State:** {classification['state']}")

    # 3. Highlight PII Elements
    st.subheader("PII Analysis:")
    pii_results = find_pii(data_example)
    found_any = False
    for pii_type, matches in pii_results.items():
        if matches:
            found_any = True
            st.success(f"  - Found {pii_type}: {matches}")
            
    if not found_any:
        st.write("  - No common PII patterns found.")
        
    st.write("-" * 30)


# --- Main Demonstration ---
def main():
    st.title("PII Detector & Data Classifier")

    st.write("""
    This application helps you identify Personally Identifiable Information (PII) in your text data 
    and provides a conceptual classification of the data's structure and state.
    """)

    # Example buttons
    st.subheader("Load an Example")
    col1, col2 = st.columns(2)

    unstructured_note_example = """
Patient Name: John Doe
Patient visited on 10/20/2024. Reports feeling fine.
Callback number is (123) 456-7890. 
SSN for insurance: 987-65-4321.
Email: john.doe@example.com. 
Patient ID: 1005
"""

    structured_json_example = """
{
  "employee_id": "E1024",
  "name": "Jane Smith",
  "position": "Developer",
  "contact": {
    "email": "j.smith@company-email.com",
    "phone": "321-555-0199"
  },
  "emergency_contact_ssn": "111-22-3333"
}
"""
    
    if 'text_input' not in st.session_state:
        st.session_state.text_input = ""

    with col1:
        if st.button("Load Doctor's Note Example"):
            st.session_state.text_input = unstructured_note_example
    with col2:
        if st.button("Load JSON Record Example"):
            st.session_state.text_input = structured_json_example

    # Text area for user input
    text_data = st.text_area("Enter text to analyze:", value=st.session_state.text_input, height=250, key="text_input_area")

    if st.button("Analyze Text"):
        if text_data:
            classify_data_concept(text_data, "User Input")
        else:
            st.warning("Please enter some text to analyze.")

if __name__ == "__main__":
    main() 