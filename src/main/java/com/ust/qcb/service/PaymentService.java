package com.ust.qcb.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ust.qcb.entity.Booking;
import com.ust.qcb.entity.Payment;
import com.ust.qcb.repository.BookingRepository;
import com.ust.qcb.repository.PaymentRepository;

@Service
public class PaymentService {
	@Autowired
    private PaymentRepository paymentRepo;

    @Autowired
    private BookingRepository bookingRepo;

    public Payment makePayment(Long bookingId, Payment payment) {
        Booking booking = bookingRepo.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));

        payment.setBooking(booking);
        payment.setPaymentDateTime(LocalDateTime.now());
        payment.setStatus("SUCCESS");
        payment.setAmount(booking.getAmount());

        // ✅ NEW: Once payment succeeds, generate a 6-digit verification OTP
        // and attach it to the booking. The user will share this with their
        // service provider on-site to confirm their identity.
        String otp = generateOtp();
        booking.setServiceOtp(otp);
        booking.setStatus("PAID");
        bookingRepo.save(booking);

        return paymentRepo.save(payment);
    }

    private String generateOtp() {
        int otp = 100000 + new Random().nextInt(900000);
        return String.valueOf(otp);
    }

    public Payment getPaymentByBooking(Long bookingId) {
        return paymentRepo.findByBookingId(bookingId);
    }

    public List<Payment> getAllPayments() {
        return paymentRepo.findAll();
    }
}
