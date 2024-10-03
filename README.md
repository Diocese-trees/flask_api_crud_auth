**Flask RESTful API with Authentication and CRUD Operations**
===========================================================

**Table of Contents**
-----------------

* [Dependencies](#dependencies)
* [How to Run the Application](#how-to-run-the-application)
* [Explanation of the Code](#explanation-of-the-code)
* [Routes](#routes)
* [Conclusion](#conclusion)

**Dependencies**
---------------

This project requires the following Python libraries and frameworks:

* **Flask**: A lightweight web framework used to create web applications.
```bash
pip install Flask
```
* **Flask-RESTful**: An extension for Flask that adds support for quickly building REST APIs.
```bash
pip install Flask-RESTful
```
* **Flask-JWT-Extended**: A library for adding JSON Web Token (JWT) support to Flask, allowing for user authentication and access control.
```bash
pip install Flask-JWT-Extended
```
* **Flask-SQLAlchemy**: An SQL toolkit that provides Object Relational Mapping (ORM) for handling databases easily.
```bash
pip install Flask-SQLAlchemy
```
* **Werkzeug**: A utility library for password hashing and checking.
```bash
# Comes with Python; no installation needed
```
* **Marshmallow**: A library used for input validation, serialization, and deserialization.
```bash
pip install marshmallow
```
* **Flask-Limiter**: A Flask extension that provides rate limiting to prevent abuse or brute-force attacks.
```bash
pip install Flask-Limiter
```
* **Redis**: A library for interacting with the Redis database.
```bash
pip install redis
```
* **Logging**: Built-in Python library to log user activity.
```bash
# Comes with Python; no installation needed
```

**How to Run the Application**
-----------------------------

1. Clone the repository:
```bash
git clone https://github.com/Diocese-trees/flask_api_crud_auth.git
```
2. Navigate to the project directory:
```bash
cd flask_api_crud_auth
```
3. Create a virtual environment (optional but recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
4. Install the required dependencies:
```bash
pip install -r requirements.txt
```
5. Start the Redis server (if not already running):
```bash
# Make sure you have Redis installed and running. You can download it from the Redis website.
```
6. Run the Flask app:
```bash
python api_Restful-Flask_crud_authenticate.py
```
This will start the app in debug mode on `http://127.0.0.1:5000/`.

**Explanation of the Code**
-------------------------

This project is a RESTful API built using Flask that supports user authentication (JWT-based) and CRUD operations on a set of items. Here's a breakdown of how the code is organized:

### Configuration (Config class)

The configuration for the app is stored in the `Config` class, where important settings like `SECRET_KEY` (used for JWT encryption) and `SQLALCHEMY_DATABASE_URI` (path to the SQLite database) are set. These are used to configure the Flask app when it starts.

### Database Models (User and Item)

* **User Model**: Stores users' data in the database, including username and a hashed version of their password. Methods include:
	+ `set_password()`: Hashes a raw password.
	+ `check_password()`: Verifies if the entered password matches the hashed version.
* **Item Model**: Stores information about items (like name and description) in the database. This is used to perform CRUD operations on items.

### Input Validation with Marshmallow

The project uses Marshmallow for input validation, which ensures the data passed by the user follows the expected structure:

* **UserSchema**: Validates the username and password fields for user-related operations.
* **ItemSchema**: Validates the name and description fields for item-related operations.

### Password Complexity Validation

A custom function `validate_password()` ensures that passwords meet complexity requirements. It checks for the following:

* Minimum of 8 characters
* At least one uppercase letter, one lowercase letter, one number, and one special character.

### Username Censorship

To prevent inappropriate or offensive usernames, the `censor_username()` function checks against a list of offensive words. If the username contains any of these words, registration is blocked.

### Rate Limiting with Flask-Limiter and Redis

The project includes rate limiting using Flask-Limiter integrated with Redis to prevent brute-force attacks and abuse. For example:

* User registration and login routes are limited to 5 requests per minute.

### JWT Authentication

The API uses JWT (JSON Web Tokens) for secure user authentication:

* **UserRegistration**: Allows new users to register by creating an account with a username and password.
* **UserLogin**: Validates the credentials (username and password), and if valid, generates a JWT token for the user. This token is used to authenticate future requests.

### Error Handling

Custom error handlers have been added for common HTTP status codes:

* **404**: If a resource (e.g., item or user) is not found, a user-friendly "Resource not found" message is returned.
* **500**: For internal server errors, a general "Internal server error" message is returned.

### CRUD Operations on Items

Users who are authenticated (i.e., provide a valid JWT token) can perform Create, Read, Update, and Delete (CRUD) operations on items:

* **Create**: Add a new item to the database.
* **Read**: Fetch details of a specific item or list all items.
* **Update**: Modify the details of an existing item.
* **Delete**: Remove an item from the database.

### Logging User Activity

User activities like login attempts and registrations are logged using Python's logging module, which helps monitor and track important events for security purposes.

**Routes**
---------

### User Routes

* **POST /register**: Register a new user. Example payload:
```json
{
    "username": "john",
    "password": "John@1234"
}
```
* **POST /login**: Login with username and password. Returns a JWT token if credentials are correct.

### Item Routes

* **GET /items**: Retrieve a list of all items. Requires a valid JWT token.
* **POST /items**: Add a new item. Example payload:
```json
{
    "name": "Laptop",
    "description": "A powerful laptop"
}
```
* **GET /items/<int:item_id>**: Retrieve details of a specific item.
* **PUT /items/<int:item_id>**: Update an item. Example payload:
```json
{
    "name": "Smartphone",
    "description": "Updated description"
}
```
* **DELETE /items/<int:item_id>**: Delete a specific item.

**Conclusion**
----------

This project demonstrates how to build a secure and scalable REST API using Flask, SQLAlchemy, and JWT authentication, enhanced by Redis for efficient rate limiting. The incorporation of Redis significantly improves performance and scalability, making the application robust enough to handle heavy traffic.