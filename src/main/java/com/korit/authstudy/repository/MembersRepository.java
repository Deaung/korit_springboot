package com.korit.authstudy.repository;

import com.korit.authstudy.domain.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MembersRepository extends JpaRepository<Member, Integer> {
}
