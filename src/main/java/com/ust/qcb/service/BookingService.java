package com.ust.qcb.service;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ust.qcb.entity.Booking;
import com.ust.qcb.entity.ServiceProvider;
import com.ust.qcb.entity.Users;
import com.ust.qcb.repository.BookingRepository;
import com.ust.qcb.repository.ServiceRepository;
import com.ust.qcb.repository.UserRepository;

@Service
public class BookingService {

    @Autowired
    private BookingRepository bookingRepo;

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private ServiceRepository serviceRepo;

    public Booking createBooking(Long userId, Long serviceId) {
        Optional<Users> user = userRepo.findById(userId);
        Optional<com.ust.qcb.entity.Service> service = serviceRepo.findById(serviceId);

        if (user.isEmpty() || service.isEmpty())
            throw new RuntimeException("User or Service not found");

        ServiceProvider provider = service.get().getServiceProvider();

        Booking booking = new Booking();
        booking.setUsers(user.get());
        booking.setService(service.get());
        booking.setServiceProvider(provider);
        booking.setStatus("PENDING");
        booking.setBookingDate(LocalDate.now());
        booking.setAmount(service.get().getPrice());

        return bookingRepo.save(booking);
    }

    // ✅ NEW: Saves the chosen slot date + time, generates a backend OTP
    // (reserved for production provider verification), sets status to SLOT_CONFIRMED
    public Booking confirmSlot(Long bookingId, LocalDate slotDate, LocalTime slotTime) {
        Booking booking = bookingRepo.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));

        booking.setSlotDate(slotDate);
        booking.setSlotTime(slotTime);
        booking.setStatus("SLOT_CONFIRMED");

        // Generate OTP now — stored silently for provider verification
        // in the production version of this app
        booking.setServiceOtp(String.valueOf(100000 + new Random().nextInt(900000)));

        return bookingRepo.save(booking);
    }

    public Booking getBookingById(Long id) {
        return bookingRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("Booking not found"));
    }

    public List<Booking> getBookingsByUser(Long userId) {
        return bookingRepo.findByUsersId(userId);
    }

    public List<Booking> getBookingsByProvider(Long providerId) {
        return bookingRepo.findByServiceProviderId(providerId);
    }

    public List<Booking> getBookingsByDate(LocalDate date) {
        return bookingRepo.findByBookingDate(date);
    }

    public void deleteBooking(Long id) {
        bookingRepo.deleteById(id);
    }
}
