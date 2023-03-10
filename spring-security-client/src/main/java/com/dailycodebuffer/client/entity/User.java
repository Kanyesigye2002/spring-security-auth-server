package com.dailycodebuffer.client.entity;

import lombok.Data;

import javax.persistence.*;

@Entity(name = "system_user")
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String firstName;
    private String lastName;
    private String email;

    @Column(length = 60)
    private String password;

    private String role;
    private boolean enabled = false;

    private String imageUrl;
    private String name;
    private AuthProvider provider;
    private String providerId;
}
