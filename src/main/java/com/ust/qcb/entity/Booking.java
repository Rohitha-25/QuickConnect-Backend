package com.ust.qcb.entity;

import java.time.LocalDate;
import java.time.LocalTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;

@Entity
public class Booking {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDate bookingDate;
    private String status;
    private double amount;

    // ✅ NEW: Date the user wants the provider to come
    private LocalDate slotDate;

    // ✅ NEW: Time slot picked (e.g. 09:00, 11:00, 14:00)
    private LocalTime slotTime;

    // ✅ NEW: OTP reserved for provider verification in the production version
    private String serviceOtp;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private Users users;

    @ManyToOne
    @JoinColumn(name = "service_id")
    private Service service;

    @ManyToOne
    @JoinColumn(name = "serviceProvider_id")
    private ServiceProvider serviceProvider;

    public Booking() {}

    public Booking(Long id, LocalDate bookingDate, String status, double amount,
                   Users users, Service service, ServiceProvider serviceProvider) {
        this.id = id;
        this.bookingDate = bookingDate;
        this.status = status;
        this.amount = amount;
        this.users = users;
        this.service = service;
        this.serviceProvider = serviceProvider;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public LocalDate getBookingDate() { return bookingDate; }
    public void setBookingDate(LocalDate bookingDate) { this.bookingDate = bookingDate; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public double getAmount() { return amount; }
    public void setAmount(double amount) { this.amount = amount; }
    public LocalDate getSlotDate() { return slotDate; }
    public void setSlotDate(LocalDate slotDate) { this.slotDate = slotDate; }
    public LocalTime getSlotTime() { return slotTime; }
    public void setSlotTime(LocalTime slotTime) { this.slotTime = slotTime; }
    public String getServiceOtp() { return serviceOtp; }
    public void setServiceOtp(String serviceOtp) { this.serviceOtp = serviceOtp; }
    public Users getUsers() { return users; }
    public void setUsers(Users users) { this.users = users; }
    public Service getService() { return service; }
    public void setService(Service service) { this.service = service; }
    public ServiceProvider getServiceProvider() { return serviceProvider; }
    public void setServiceProvider(ServiceProvider serviceProvider) { this.serviceProvider = serviceProvider; }
}
