# 🌌 Silk Developer Portal
The Silk Developer Portal WebUI source code for building SilkOS. Self-hostable, simple and secure.

## ⚠️ WARNING: THIS IS IN AN EARLY DEVELOPMENT PHASE ⚠️
Expect errors from the scripts.

## ⚡ Features
- Simple account system (based on Silk-Forum)
- Building SilkOS
- Straightforward WebUI
- Viewable container build status

## ⚙️ Usage

### Requirements
- `python3` (through package manager)
- `flask`, `flask_cors` (pip)
- `docker` (pip and through package manager)

### Running the app
To run the app, type in the following command:
```
flask run
```

## 🗺️ API Routes
### Accounts
- `/api/validate/`: Validate a requested token
- `/api/accounts/`: Returns every account
- `/api/accounts/len/`: Returns total amount of users
- `/api/login/`: Login a user and return a token
- `/api/register/`: Adds a user to the authentication list
- `/api/register/add/`: Registers a new user

### Containers
- `/api/containers`: Returns every containers' info
- `/api/containers/create`: Creates a new container
- `/api/containers/<container_id>`: Used to delete a container
- `/api/containers/delete_all`: Clean up everything by deleting every container
- `/api/containers/<container_id>/build`: Build SilkOS with a specified container
- `/api/containers/<container_id>/logs`: Returns logs of a specified container
