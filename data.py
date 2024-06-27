import streamlit as st
from pathlib import Path
import os
import hashlib
import base64

# File to store user credentials
USERS_FILE = "users.txt"

# Hash a password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to load user data from file
def load_user_data():
    users = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            for line in f:
                username, password = line.strip().split(":")
                users[username] = password
    return users

# Function to save user data to file
def save_user_data(users):
    with open(USERS_FILE, "w") as f:
        for username, password in users.items():
            f.write(f"{username}:{password}\n")

# Function to handle user registration
def register_user(username, password):
    users = load_user_data()
    if username in users:
        st.error("Username already exists. Please choose a different username.")
    else:
        hashed_password = hash_password(password)
        users[username] = hashed_password
        save_user_data(users)
        st.success(f"User '{username}' registered successfully!")

# Function to handle user login
def login_user(username, password):
    users = load_user_data()
    hashed_password = hash_password(password)
    if username in users and users[username] == hashed_password:
        st.session_state['logged_in'] = True
        st.session_state['username'] = username
        return True
    else:
        return False

# Function to handle user logout
def logout_user():
    st.session_state['logged_in'] = False
    st.session_state['username'] = ""
    st.session_state['selected_file'] = None
    st.session_state['search_query'] = ""
    st.info("Logged out successfully.")

# Function to handle file uploads
def save_uploaded_file(uploaded_file, username, category):
    try:
        # Save the file to a specific directory
        upload_dir = Path("uploads") / username / category
        upload_dir.mkdir(parents=True, exist_ok=True)
        file_path = upload_dir / uploaded_file.name
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return file_path
    except Exception as e:
        st.error(f"Error saving file: {e}")
        return None

# Function to list uploaded files
def list_uploaded_files(username, category):
    upload_dir = Path("uploads") / username / category
    if upload_dir.exists():
        return [file for file in upload_dir.iterdir()]
    else:
        return []

# Function to display uploaded files
def display_uploaded_file(file_path):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()

        file_extension = file_path.suffix.lower()
        if file_extension in ['.jpg', '.jpeg', '.png', '.gif']:
            st.image(file_data)
        elif file_extension in ['.mp4', '.mov', '.avi']:
            st.video(file_data)
        elif file_extension in ['.mp3', '.wav', '.ogg']:
            st.audio(file_data)
        elif file_extension in ['.pdf']:
            base64_pdf = base64.b64encode(file_data).decode('utf-8')
            pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="700" height="1000" type="application/pdf"></iframe>'
            st.markdown(pdf_display, unsafe_allow_html=True)
        else:
            st.text_area(f"File: {file_path.name}", file_data.decode())
    except Exception as e:
        st.error(f"Error displaying file: {e}")

# Function to delete a file
def delete_file(file_path):
    try:
        file_path.unlink()
        st.success("File deleted successfully.")
    except Exception as e:
        st.error(f"Error deleting file: {e}")

# Function to share a file
def share_file(file_path):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()

        # Creating a download link for sharing
        b64 = base64.b64encode(file_data).decode('utf-8')
        mime_type = "application/octet-stream"  # Default MIME type
        file_extension = file_path.suffix.lower()
        
        # Set the correct MIME type based on file extension
        if file_extension in ['.jpg', '.jpeg', '.png', '.gif']:
            mime_type = f"image/{file_extension[1:]}"
        elif file_extension in ['.mp4', '.mov', '.avi']:
            mime_type = f"video/{file_extension[1:]}"
        elif file_extension in ['.mp3', '.wav', '.ogg']:
            mime_type = f"audio/{file_extension[1:]}"
        elif file_extension == '.pdf':
            mime_type = "application/pdf"
        else:
            mime_type = "application/octet-stream"

        href = f'<a href="data:{mime_type};base64,{b64}" download="{file_path.name}">Download {file_path.name}</a>'
        st.markdown(href, unsafe_allow_html=True)
    except Exception as e:
        st.error(f"Error sharing file: {e}")

# Function to clear selected file
def clear_selected_file():
    st.session_state['selected_file'] = None

# Function to set custom CSS styles
def set_custom_style():
    st.markdown(
        """
        <style>
        body {
            color: #333;
            background-color: #f0f0f0;
            font-family: 'Arial', sans-serif;
        }
        .stButton>button {
            background-color: #007bff;
            color: #fff;
            border-radius: 5px;
            padding: 10px;
            transition: all 0.3s ease;
        }
        .stButton>button:hover {
            background-color: #0056b3;
            transform: scale(1.05);
        }
        .stTextInput>div>input {
            border: 1px solid #007bff;
            border-radius: 5px;
            padding: 10px;
        }
        .stSidebar {
            background-color: #343a40;
            color: #fff;
        }
        .stSidebar .stButton>button {
            background-color: #6c757d;
            color: #fff;
        }
        .stSidebar .stButton>button:hover {
            background-color: #5a6268;
        }
        .stSidebar .stTextInput>div>input {
            border: 1px solid #6c757d;
            border-radius: 5px;
            padding: 10px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

# Main Streamlit app
def main():
    # Initialize session state for user data
    if 'users' not in st.session_state:
        st.session_state['users'] = load_user_data()
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
    if 'username' not in st.session_state:
        st.session_state['username'] = ""
    if 'selected_file' not in st.session_state:
        st.session_state['selected_file'] = None
    if 'search_query' not in st.session_state:
        st.session_state['search_query'] = ""

    # Apply custom styles
    set_custom_style()

    st.title("Media Storage App")

    if not st.session_state['logged_in']:
        # User choice: Register or Login
        user_choice = st.selectbox("Choose an option", ["Register", "Login"])

        # Centered layout for forms
        col1, col2, col3 = st.columns([1, 2, 1])

        with col2:
            if user_choice == "Register":
                st.header("Register")
                new_username = st.text_input("New Username", key="new_username")
                new_password = st.text_input("New Password", type="password", key="new_password")
                if st.button("Register"):
                    register_user(new_username, new_password)

            elif user_choice == "Login":
                st.header("Login")
                username_input = st.text_input("Username", key="username_input")
                password_input = st.text_input("Password", type="password", key="password_input")
                if st.button("Login"):
                    if login_user(username_input, password_input):
                        st.success(f"Logged in as {username_input}")
                    else:
                        st.error("Invalid username or password")
    else:
        st.success(f"Welcome {st.session_state['username']}")

        st.write("---")

        # Sidebar for file management
        st.sidebar.title("File Manager")

        # File management options
        st.sidebar.subheader("Manage Files")
        categories = ["Images", "Videos", "Documents", "Audio", "Other"]
        selected_category = st.sidebar.selectbox("Select Category", categories)

        uploaded_files = list_uploaded_files(st.session_state['username'], selected_category)
        file_names = [file.name for file in uploaded_files]
        selected_file = st.sidebar.selectbox("Select File", file_names, key='file_selector')

        if selected_file:
            file_path = Path("uploads") / st.session_state['username'] / selected_category / selected_file
            if st.sidebar.button("View", key="view"):
                display_uploaded_file(file_path)
            if st.sidebar.button("Share", key="share"):
                share_file(file_path)
            if st.sidebar.button("Delete", key="delete"):
                delete_file(file_path)
                st.sidebar.success(f"File '{selected_file}' deleted successfully.")
                uploaded_files = list_uploaded_files(st.session_state['username'], selected_category)

        # Logout button
        if st.button("Logout", key="logout"):
            logout_user()

        st.write("---")

        # File upload section
        st.subheader(f"Upload {selected_category}")
        uploaded_file = st.file_uploader(f"Choose {selected_category} file", type=get_allowed_file_types(selected_category))

        if uploaded_file is not None:
            # Save the uploaded file
            file_path = save_uploaded_file(uploaded_file, st.session_state['username'], selected_category)
            if file_path:
                st.success(f"File uploaded successfully: {file_path}")
            else:
                st.error("Failed to upload file. Please try again.")

        st.write("---")

        # Search bar
        st.subheader("Search Files")
        search_query = st.text_input("Search for a file", key="search_query")
        if st.button("Search", key="search"):
            st.session_state['search_query'] = search_query

        # List and display uploaded files
        st.header(f"Your {selected_category}")
        uploaded_files = list_uploaded_files(st.session_state['username'], selected_category)
        
        if st.session_state['search_query']:
            uploaded_files = [file for file in uploaded_files if st.session_state['search_query'].lower() in file.name.lower()]

        if uploaded_files:
            for i, file in enumerate(uploaded_files):
                if st.button(file.name, key=f"file_{i}"):
                    st.session_state['selected_file'] = file
        else:
            st.write(f"No {selected_category} files uploaded yet.")

        # Display the selected file with Back and Delete options
        if st.session_state['selected_file']:
            st.write("---")
            col1, col2, col3 = st.columns([1, 1, 1])
            with col1:
                st.button("< Back", on_click=clear_selected_file, key="back")  # Back button
            with col3:
                if st.button("Delete", key="delete_selected"):
                    delete_file(st.session_state['selected_file'])
                    clear_selected_file()  # Clear selected file after deletion

            if st.session_state['selected_file'] is not None:
                st.header(f"Viewing {st.session_state['selected_file'].name}")
                display_uploaded_file(st.session_state['selected_file'])

# Function to get allowed file types for each category
def get_allowed_file_types(category):
    # Allow all common file types
    file_types = {
        "Images": ["jpg", "jpeg", "png", "gif", "bmp", "tiff", "svg"],
        "Videos": ["mp4", "mov", "avi", "mkv", "flv", "wmv", "webm"],
        "Documents": ["pdf", "doc", "docx", "txt", "rtf", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "html", "css", "js", "json", "xml", "md", "csv"],
        "Audio": ["mp3", "wav", "ogg", "flac", "aac", "m4a"],
        "Other": ["zip", "rar", "7z", "tar", "gz", "bz2", "py", "ipynb", "c", "cpp", "java", "class", "jar", "cs", "rb", "go", "pl", "sh", "bat", "ps1"]
    }
    return file_types.get(category, ["*"])

if __name__ == "__main__":
    main()
