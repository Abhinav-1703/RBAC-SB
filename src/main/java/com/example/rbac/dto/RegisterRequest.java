package com.example.rbac.dto;

import com.example.rbac.entity.Role;
import lombok.Data;

import java.util.Set;

@Data
public class RegisterRequest {
    
    private String email;
    private String password;
    private Set<Role> roles;
}
