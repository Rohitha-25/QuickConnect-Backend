## 👨‍🔧 QuickConnect – Home Services Application – Backend

### Overview
QuickConnect is a full-stack service-booking platform. This repository contains the Spring Boot backend responsible for authentication, users and service providers, services, bookings, payments, reviews and role-based access control.

The backend follows a layered architecture with controllers, services and repositories and uses JWT-based security for protected APIs.

### Key Features
- JWT-based authentication and authorization
- User and service-provider management
- Service discovery and management
- Booking creation and management
- Payment module
- Review and rating module
- Role-based access control
- Bean/annotation-based request validation
- Global exception handling
- DTO-oriented API responses
- JPA/Hibernate persistence

### Architecture
```
   Client/React Frontend
            ↓
   Spring Boot REST API
            │
   ┌────────┼─────────┐
   │        │         │
Controller Service Repository
                      ↓
                     MySQL
```

### Security Model
The application uses JWT-based authentication with role-oriented access control.

#### Typical flow:
```
Register / Login
      ↓
JWT issued
      ↓
Bearer token on protected requests
      ↓
Spring Security validates token
      ↓
Role-based endpoint authorization (User / Provider)
```

### API Overview
The project includes endpoints covering authentication, services, users, providers, bookings, payments and reviews.

<table>
  <tr>
    <th>Method</th>
    <th>Endpoint</th>
    <th>Purpose</th>
  </tr>

  <tr>
    <td>POST</td>
    <td>/api/auth/register</td>
    <td>Register a user/provider account.</td>
  </tr>

  <tr>
    <td>POST</td>
    <td>/api/auth/login</td>
    <td>Authenticate and obtain JWT.</td>
  </tr>

  <tr>
    <td>GET</td>
    <td>/api/services</td>
    <td>Browse available services.</td>
  </tr>

  <tr>
    <td>POST</td>
    <td>/api/bookings</td>
    <td>Create a booking.</td>
  </tr>

  <tr>
    <td>GET</td>
    <td>/api/bookings</td>
    <td>View bookings.</td>
  </tr>

  <tr>
    <td>POST</td>
    <td>/api/payments</td>
    <td>Create payment-related record.</td>
  </tr>

  <tr>
    <td>POST</td>
    <td>/api/reviews</td>
    <td>Submit a review.</td>
  </tr>
</table>



### Tech Stack
- Java
- Spring Boot
- Spring Security (JWT)
- Spring Data JPA
- MySQL
- Hibernate

### Project Structure
```
src/main/java/
└── com/ust/qcb/
    ├── controller/      # REST endpoints
    ├── service/         # Business logic
    ├── repository/      # Spring Data repositories
    ├── entity/          # JPA domain entities
    ├── dto/             # Data transfer objects
    ├── security/        # JWT / Spring Security configuration
    └── exception/       # Global exception handling
```

### Local Setup

#### Prerequisites
- Java 17
- MySQL 8.x
- Maven (or the included Maven Wrapper)

#### 1. Clone
```
git clone https://github.com/Rohitha-25/QuickConnect-Backend.git
cd QuickConnect-Backend
```

#### 2. Create the database
```
CREATE DATABASE quickconnect-db;
```

#### 3. Configure database credentials
Configure your local MySQL username and password through environment variables or an ignored local configuration file.
```
Example values:
DB_URL=jdbc:mysql://localhost:3306/quickconnect-db
DB_USERNAME=<your-username>
DB_PASSWORD=<your-password>
```

#### 4. Run the application
```
Windows:
mvnw.cmd spring-boot:run

macOS / Linux:
./mvnw spring-boot:run
```

#### Related Repository
https://github.com/Rohitha-25/QuickConnect-Frontend
