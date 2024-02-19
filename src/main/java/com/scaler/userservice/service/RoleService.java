package com.scaler.userservice.service;

import com.scaler.userservice.model.Role;
import com.scaler.userservice.repository.RoleRepository;
import org.springframework.stereotype.Service;

@Service
public class RoleService {

    private final RoleRepository roleRepository;

    public RoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public Role createRole(String name) {

        Role role = new Role();
        role.setRole(name);

        return roleRepository.save(role);
    }
}
