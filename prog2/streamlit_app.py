import streamlit as st
import itertools
import string
import time
import re
import threading
from datetime import datetime

# Configure page
st.set_page_config(
    page_title="Password Security Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .strength-weak { color: #ff4444; font-weight: bold; }
    .strength-moderate { color: #ffaa00; font-weight: bold; }
    .strength-strong { color: #00aa00; font-weight: bold; }
    .metric-card {
        background: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .attack-status {
        background: #e8f4fd;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
</style>
""", unsafe_allow_html=True)

CHARSET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:'\",.<>?/|`~"

def analyze_password_strength(password):
    """Analyze password strength and return detailed metrics"""
    length = len(password)
    has_lower = re.search(r'[a-z]', password) is not None
    has_upper = re.search(r'[A-Z]', password) is not None
    has_digit = re.search(r'\d', password) is not None
    has_special = re.search(r'[^a-zA-Z0-9]', password) is not None
    
    score = sum([has_lower, has_upper, has_digit, has_special])
    
    if length < 6 or score < 2:
        strength = "Weak"
        color_class = "strength-weak"
    elif length >= 6 and score == 3:
        strength = "Moderate"
        color_class = "strength-moderate"
    elif length >= 8 and score == 4:
        strength = "Strong"
        color_class = "strength-strong"
    else:
        strength = "Moderate"
        color_class = "strength-moderate"
    
    return {
        'length': length,
        'has_lower': has_lower,
        'has_upper': has_upper,
        'has_digit': has_digit,
        'has_special': has_special,
        'score': score,
        'strength': strength,
        'color_class': color_class
    }

def estimate_crack_time(password_length, charset_size):
    """Estimate time to crack password"""
    combinations = charset_size ** password_length
    # Assuming 1 million attempts per second
    seconds = combinations / 1000000
    
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} days"
    else:
        return f"{seconds/31536000:.2f} years"

def brute_force_attack_generator(password, max_attempts=10000):
    """Generator for brute force attack with limited attempts for demo"""
    attempts = 0
    start_time = time.time()
    
    for length in range(1, len(password) + 1):
        for guess_tuple in itertools.product(CHARSET, repeat=length):
            if attempts >= max_attempts:
                return None, attempts, time.time() - start_time, "Max attempts reached"
            
            guess = ''.join(guess_tuple)
            attempts += 1
            
            if guess == password:
                return guess, attempts, time.time() - start_time, "Found"
            
            # Yield progress every 100 attempts
            if attempts % 100 == 0:
                yield guess, attempts, time.time() - start_time, "Searching"
    
    return None, attempts, time.time() - start_time, "Not found"

# Main app
st.markdown('<h1 class="main-header">🔐 Password Security Analyzer</h1>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.header("⚙️ Settings")
    max_attempts = st.slider("Max Brute Force Attempts", 1000, 50000, 10000, step=1000)
    show_real_time = st.checkbox("Show Real-time Attack Progress", value=True)
    
    st.header("📊 About")
    st.info("""
    This tool analyzes password strength and demonstrates brute-force attacks.
    
    **Features:**
    - Password strength analysis
    - Real-time brute-force simulation
    - Security recommendations
    """)

# Main content
col1, col2 = st.columns([1, 1])

with col1:
    st.header("🔍 Password Analysis")
    
    password_input = st.text_input(
        "Enter password to analyze:",
        type="password",
        help="Your password will be analyzed for strength"
    )
    
    if password_input:
        analysis = analyze_password_strength(password_input)
        
        # Strength indicator
        if analysis['strength'] == 'Weak':
            st.error(f"Password Strength: {analysis['strength']}")
        elif analysis['strength'] == 'Moderate':
            st.warning(f"Password Strength: {analysis['strength']}")
        else:
            st.success(f"Password Strength: {analysis['strength']}")
        
        # Metrics
        col_a, col_b, col_c, col_d = st.columns(4)
        
        with col_a:
            st.metric("Length", analysis['length'])
        with col_b:
            st.metric("Character Types", f"{analysis['score']}/4")
        with col_c:
            estimated_time = estimate_crack_time(analysis['length'], len(CHARSET))
            st.metric("Est. Crack Time", estimated_time)
        with col_d:
            complexity = len(CHARSET) ** analysis['length']
            st.metric("Combinations", f"{complexity:,.0f}")
        
        # Detailed analysis
        st.subheader("📋 Detailed Analysis")
        
        checks = [
            ("Lowercase letters", analysis['has_lower']),
            ("Uppercase letters", analysis['has_upper']),
            ("Numbers", analysis['has_digit']),
            ("Special characters", analysis['has_special'])
        ]
        
        for check, passed in checks:
            icon = "✅" if passed else "❌"
            st.write(f"{icon} {check}")

with col2:
    st.header("⚡ Brute Force Simulation")
    
    if password_input:
        if st.button("🚀 Start Brute Force Attack", type="primary"):
            st.warning("⚠️ Starting brute force simulation...")
            
            # Progress containers
            progress_bar = st.progress(0)
            status_container = st.empty()
            attempts_container = st.empty()
            current_guess_container = st.empty()
            
            # Attack simulation
            attack_gen = brute_force_attack_generator(password_input, max_attempts)
            
            try:
                for result in attack_gen:
                    if result is None:
                        break
                    
                    guess, attempts, elapsed, status = result
                    
                    # Update progress
                    progress = min(attempts / max_attempts, 1.0)
                    progress_bar.progress(progress)
                    
                    # Update status
                    if show_real_time:
                        status_container.write(f"**Status:** {status}")
                        status_container.write(f"**Current Guess:** {guess}")
                        status_container.write(f"**Elapsed:** {elapsed:.2f}s")
                    
                    attempts_container.metric("Attempts Made", f"{attempts:,}")
                    
                    time.sleep(0.01)  # Small delay for visualization
                
                # Final result
                final_result = next(attack_gen, (None, max_attempts, 0, "Completed"))
                found_password, total_attempts, total_time, final_status = final_result
                
                if found_password:
                    st.success(f"🎯 Password cracked: `{found_password}`")
                    st.balloons()
                else:
                    st.error(f"❌ Password not found within {max_attempts:,} attempts")
                
                # Final stats
                col_x, col_y = st.columns(2)
                with col_x:
                    st.metric("Total Attempts", f"{total_attempts:,}")
                with col_y:
                    st.metric("Total Time", f"{total_time:.2f}s")
                    
            except Exception as e:
                st.error(f"Error during attack simulation: {str(e)}")
    
    else:
        st.info("👆 Enter a password above to start the simulation")

# Security recommendations
st.header("🛡️ Security Recommendations")

recommendations = [
    "Use at least 12 characters",
    "Include uppercase and lowercase letters",
    "Add numbers and special characters",
    "Avoid common words and patterns",
    "Use unique passwords for each account",
    "Consider using a password manager"
]

cols = st.columns(2)
for i, rec in enumerate(recommendations):
    with cols[i % 2]:
        st.write(f"• {rec}")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666;'>"
    "⚠️ This tool is for educational purposes only. Always use strong, unique passwords!"
    "</div>",
    unsafe_allow_html=True
)