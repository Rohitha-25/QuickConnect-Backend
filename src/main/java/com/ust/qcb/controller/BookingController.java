package com.ust.qcb.controller;

import com.ust.qcb.entity.Booking;
import com.ust.qcb.service.BookingService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/bookings")
public class BookingController {

    @Autowired
    private BookingService bookingService;

    @PostMapping("/book/{userId}/{serviceId}")
    public Booking createBooking(@PathVariable Long userId, @PathVariable Long serviceId) {
        return bookingService.createBooking(userId, serviceId);
    }

    // ✅ NEW: Confirms the slot date and time chosen by the user
    // Body: { "slotDate": "2026-07-01", "slotTime": "09:00" }
    @PostMapping("/confirm-slot/{bookingId}")
    public ResponseEntity<?> confirmSlot(@PathVariable Long bookingId, @RequestBody Map<String, String> body) {
        try {
            LocalDate slotDate = LocalDate.parse(body.get("slotDate"));
            LocalTime slotTime = LocalTime.parse(body.get("slotTime"));
            Booking booking = bookingService.confirmSlot(bookingId, slotDate, slotTime);
            return ResponseEntity.ok(booking);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", e.getMessage()));
        }
    }

    @GetMapping("/get/{id}")
    public Booking getBookingById(@PathVariable Long id) {
        return bookingService.getBookingById(id);
    }

    @GetMapping("/user/{userId}")
    public List<Booking> getBookingsByUser(@PathVariable Long userId) {
        return bookingService.getBookingsByUser(userId);
    }

    @GetMapping("/provider/{providerId}")
    public List<Booking> getBookingsByProvider(@PathVariable Long providerId) {
        return bookingService.getBookingsByProvider(providerId);
    }

    @GetMapping("/date/{date}")
    public List<Booking> getBookingsByDate(@PathVariable String date) {
        return bookingService.getBookingsByDate(LocalDate.parse(date));
    }

    @DeleteMapping("/delete/{id}")
    public String deleteBooking(@PathVariable Long id) {
        bookingService.deleteBooking(id);
        return "Booking deleted successfully";
    }
}
