package com.ust.qcb.repository;

import java.time.LocalDate;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ust.qcb.entity.Booking;

@Repository
public interface BookingRepository extends JpaRepository<Booking, Long>{
	List<Booking> findByUsersId(Long userId);
    List<Booking> findByServiceProviderId(Long providerId);
    List<Booking> findByBookingDate(LocalDate bookingDate);
}