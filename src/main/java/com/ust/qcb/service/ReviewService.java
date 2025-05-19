package com.ust.qcb.service;

import java.time.LocalDate;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ust.qcb.entity.Review;
import com.ust.qcb.entity.Users;
import com.ust.qcb.repository.ReviewRepository;
import com.ust.qcb.repository.ServiceRepository;
import com.ust.qcb.repository.UserRepository;

@Service
public class ReviewService {

    @Autowired
    private ReviewRepository reviewRepo;

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private ServiceRepository serviceRepo;

    public Review addReview(Long userId, Long serviceId, Review review) {
        Users user = userRepo.findById(userId).orElseThrow();
        com.ust.qcb.entity.Service service = serviceRepo.findById(serviceId).orElseThrow();
        review.setUser(user);
        review.setService(service);
        review.setDate(LocalDate.now());
        return reviewRepo.save(review);
    }

    public List<Review> getReviewsForService(Long serviceId) {
        return reviewRepo.findByServiceId(serviceId);
    }
}