package com.ust.qcb.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import com.ust.qcb.entity.Review;
import com.ust.qcb.service.ReviewService;

@RestController
@RequestMapping("/api/reviews")
public class ReviewController {

    @Autowired
    private ReviewService reviewService;

    @PostMapping("/add/{userId}/{serviceId}")
    public Review addReview(@PathVariable Long userId, @PathVariable Long serviceId, @RequestBody Review review) {
        return reviewService.addReview(userId, serviceId, review);
    }

    @GetMapping("/service/{serviceId}")
    public List<Review> getReviewsByService(@PathVariable Long serviceId) {
        return reviewService.getReviewsForService(serviceId);
    }

    @GetMapping("/exists/{userId}/{serviceId}")
    public boolean hasReviewedService(@PathVariable Long userId, @PathVariable Long serviceId) {
        return reviewService.hasReviewedService(userId, serviceId);
    }
}