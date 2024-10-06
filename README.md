# Notix

Notix is a comprehensive note-taking application designed to help users efficiently create, manage, and track their notes. The application features a robust and scalable backend architecture with Spring Boot, reliable data storage with MySQL, and a smooth, responsive user interface powered by React.js.

## Features

- **User Authentication**: Secure login with email and password, Google, or GitHub OAuth integrations.
- **JWT Authentication**: JSON Web Token (JWT) authentication for session management.
- **Role-based Access Control**: Permissions are assigned based on user roles, ensuring secure data access.
- **Two-factor Authentication (2FA)**: Adds an extra layer of security for user accounts.
- **Responsive User Interface**: A fast and smooth frontend built with React.js for optimal user experience.

## Tech Stack

- **Backend**: Java Spring Boot
- **Frontend**: React.js, Axios
- **Database**: MySQL
- **Authentication**: JWT, Google OAuth, GitHub OAuth, Two-factor Authentication

## Authentication

All endpoints require authentication. The system uses Spring Security for authentication and authorization. Users must be logged in to access protected resources.

## Endpoints

### User Management

#### Get All Users
- **URL:** `/admin/getusers`
- **Method:** `GET`
- **Authorization:** `ROLE_ADMIN`
- **Description:** Retrieve a list of all users.

#### Update User Role
- **URL:** `/admin/update-role`
- **Method:** `PUT`
- **Authorization:** `ROLE_ADMIN`
- **Parameters:**
  - `userId` (Long) - ID of the user
  - `roleName` (String) - New role name to assign
- **Description:** Update the role of a specific user.

#### Get User by ID
- **URL:** `/admin/user/{id}`
- **Method:** `GET`
- **Authorization:** `ROLE_ADMIN`
- **Description:** Retrieve user details by user ID.

#### Update Account Lock Status
- **URL:** `/admin/update-lock-status`
- **Method:** `PUT`
- **Authorization:** `ROLE_ADMIN`
- **Parameters:**
  - `userId` (Long) - ID of the user
  - `lock` (boolean) - Lock status
- **Description:** Update the lock status of a user account.

#### Get All Roles
- **URL:** `/admin/roles`
- **Method:** `GET`
- **Authorization:** `ROLE_ADMIN`
- **Description:** Retrieve all available user roles.

#### Update Account Expiry Status
- **URL:** `/admin/update-expiry-status`
- **Method:** `PUT`
- **Authorization:** `ROLE_ADMIN`
- **Parameters:**
  - `userId` (Long) - ID of the user
  - `expire` (boolean) - Expiry status
- **Description:** Update the expiry status of a user account.

#### Update Account Enabled Status
- **URL:** `/admin/update-enabled-status`
- **Method:** `PUT`
- **Authorization:** `ROLE_ADMIN`
- **Parameters:**
  - `userId` (Long) - ID of the user
  - `enabled` (boolean) - Enabled status
- **Description:** Update whether a user account is enabled.

#### Update Credentials Expiry Status
- **URL:** `/admin/update-credentials-expiry-status`
- **Method:** `PUT`
- **Authorization:** `ROLE_ADMIN`
- **Parameters:**
  - `userId` (Long) - ID of the user
  - `expire` (boolean) - Expiry status
- **Description:** Update the credentials expiry status for a user.

#### Update Password
- **URL:** `/admin/update-password`
- **Method:** `PUT`
- **Authorization:** `ROLE_ADMIN`
- **Parameters:**
  - `userId` (Long) - ID of the user
  - `password` (String) - New password
- **Description:** Update the password for a user.

### Audit Log Management

#### Get All Audit Logs
- **URL:** `/audit`
- **Method:** `GET`
- **Authorization:** `ROLE_ADMIN`
- **Description:** Retrieve all audit logs.

#### Get Audit Logs for Note
- **URL:** `/audit/note/{id}`
- **Method:** `GET`
- **Authorization:** `ROLE_ADMIN`
- **Description:** Retrieve audit logs related to a specific note by its ID.

### CSRF Protection

#### Get CSRF Token
- **URL:** `/csrf-token`
- **Method:** `GET`
- **Description:** Retrieve the CSRF token for the session.

### Notes Management

#### Create Note
- **URL:** `/notes`
- **Method:** `POST`
- **Body:** 
  ```json
  {
    "content": "Your note content here"
  }
