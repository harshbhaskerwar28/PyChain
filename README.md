# PyChain
A BlockChain Storage Solution
This is a simple Flask web application that allows users to upload files to a blockchain-based storage system. The application also provides a simple authentication system for users and administrators.

## Features

- User authentication with username and password
- File upload to a secure blockchain-based storage system
- File download with encryption
- User-specific file storage and retrieval
- Blockchain explorer for administrators

### Prerequisites

Make sure you have a Decent PC or Server with following installed:

- Python Installation
- Flask
- os
- hashlib
- datetime

### Installation 

1. Clone the Repository.

```pyton
git clone https://github.com/bharathajjarapu/PyChain.git
```

2. Change Directory.
   
```pyton
cd PyChain
```

3. Install the Requirements

```python
pip install flask os hashlib datetime
```

4. Then run the python file in terminal
```python
python app.py
```

## Usage

1. Open your web browser and go to ```http://127.0.0.1:5000/```.
2. Enter the login details.
3. Click on the "Login" button.
4. You are sent to index page to upload the files in the blockchain environment

## Project Structure

- app.py: The main Flask application file containing the routes and image processing logic.
- templates/: Folder containing HTML templates for the web interface.
- templates/index.html: Main page for image upload.
- templates/login.html: Page displaying Login form.

Happy hacking!
