package com.ust.qcb.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ust.qcb.entity.Users;

@Repository
public interface UserRepository extends JpaRepository<Users, Long> {
	Users findByEmail(String email);
}