# 👨‍🔧 QuickConnect – Backend

## Overview
QuickConnect is a full-stack backend system designed for a service booking platform where users can discover services, make bookings, manage payments, and leave reviews.

## Tech Stack
- Java
- Spring Boot
- Spring Security (JWT)
- Spring Data JPA
- MySQL
- Hibernate

## Features
- JWT-based Authentication & Authorization
- User & Service Provider Management
- Booking System
- Review & Rating System
- Payment Module
- Role-based Access Control

## Architecture
- Layered Architecture (Controller → Service → Repository)
- DTO-based data transfer
- Global Exception Handling
- Validation using annotations

## API Endpoints (Sample)

| Method | Endpoint | Description |
|--------|--------|------------|
| POST | /auth/register | Register user |
| POST | /auth/login | Login |
| GET | /services | Get services |
| POST | /booking | Create booking |
